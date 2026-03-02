use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum FecError {
    #[error("invalid shard configuration")]
    InvalidShardConfig,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("frame too short")]
    FrameTooShort,
    #[error("frame malformed")]
    FrameMalformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecMode {
    Mode0,
    Mode1,
}

impl FecMode {
    fn to_wire(self) -> u8 {
        match self {
            Self::Mode0 => 0,
            Self::Mode1 => 1,
        }
    }

    fn from_wire(v: u8) -> Result<Self, FecError> {
        match v {
            0 => Ok(Self::Mode0),
            1 => Ok(Self::Mode1),
            _ => Err(FecError::FrameMalformed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FecConfig {
    pub mode: FecMode,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub max_payload_size: usize,
    pub encode_fast_send: bool,
    pub decode_fast_send: bool,
    pub replay_window_blocks: usize,
}

impl FecConfig {
    pub fn validate(&self) -> Result<(), FecError> {
        if self.data_shards == 0 {
            return Err(FecError::InvalidShardConfig);
        }
        if self.max_payload_size == 0 || self.max_payload_size > u16::MAX as usize {
            return Err(FecError::PayloadTooLarge);
        }
        if self.replay_window_blocks == 0 {
            return Err(FecError::InvalidShardConfig);
        }
        Ok(())
    }
}

struct PendingData {
    bytes: Vec<u8>,
}

pub struct FecEncoder {
    cfg: FecConfig,
    block_id: u32,
    pending: Vec<PendingData>,
    first_pending_at: Option<Instant>,
}

impl FecEncoder {
    pub fn new(cfg: FecConfig) -> Result<Self, FecError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            block_id: 1,
            pending: Vec::with_capacity(cfg.data_shards as usize),
            first_pending_at: None,
        })
    }

    pub fn push(&mut self, payload: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        if payload.len() > self.cfg.max_payload_size || payload.len() > u16::MAX as usize {
            return Err(FecError::PayloadTooLarge);
        }

        let inner_index = self.pending.len() as u8;

        self.pending.push(PendingData {
            bytes: payload.to_vec(),
        });
        if self.first_pending_at.is_none() {
            self.first_pending_at = Some(Instant::now());
        }

        let mut out = Vec::new();
        if self.cfg.mode == FecMode::Mode1 && self.cfg.encode_fast_send {
            let fast_payload = encode_data_payload(payload);
            out.push(encode_fec_frame(
                self.cfg.mode,
                self.block_id,
                inner_index,
                0,
                0,
                &fast_payload,
            ));
        }

        if self.pending.len() < self.cfg.data_shards as usize {
            return Ok(out);
        }

        out.extend(self.flush_block()?);
        Ok(out)
    }

    pub fn flush_if_timed_out(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, FecError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(started) = self.first_pending_at {
            if started.elapsed() >= timeout {
                return self.flush_block();
            }
        }
        Ok(Vec::new())
    }

    fn flush_block(&mut self) -> Result<Vec<Vec<u8>>, FecError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }

        let data_shards = self.pending.len();
        let parity_shards = self.cfg.parity_shards as usize;
        let total_shards = data_shards + parity_shards;

        let shard_len = self
            .pending
            .iter()
            .map(|item| item.bytes.len() + 2)
            .max()
            .unwrap_or(0);

        let mut shards = vec![vec![0u8; shard_len]; total_shards];
        for (idx, item) in self.pending.iter().enumerate() {
            let len = item.bytes.len() as u16;
            shards[idx][0..2].copy_from_slice(&len.to_be_bytes());
            shards[idx][2..2 + item.bytes.len()].copy_from_slice(&item.bytes);
        }

        if parity_shards > 0 {
            let rs = ReedSolomon::new(data_shards, parity_shards).map_err(|_| FecError::InvalidShardConfig)?;
            rs.encode(&mut shards).map_err(|_| FecError::InvalidShardConfig)?;
        }

        let block_id = self.block_id;
        self.block_id = self.block_id.wrapping_add(1);

        let mut out = Vec::with_capacity(total_shards);
        for (idx, shard) in shards.into_iter().enumerate() {
            out.push(encode_fec_frame(
                self.cfg.mode,
                block_id,
                idx as u8,
                data_shards as u8,
                self.cfg.parity_shards,
                &shard,
            ));
        }

        self.pending.clear();
        self.first_pending_at = None;
        Ok(out)
    }
}

struct BlockState {
    mode: FecMode,
    data_shards: usize,
    parity_shards: usize,
    shard_len: usize,
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
    created_at: Instant,
}

pub struct FecDecoder {
    decode_fast_send: bool,
    replay_window_blocks: usize,
    blocks: HashMap<u32, BlockState>,
    mode1_fast_seen: HashMap<u32, (Instant, HashSet<usize>)>,
    completed_blocks: HashSet<u32>,
    completed_order: VecDeque<u32>,
    ttl: Duration,
}

impl FecDecoder {
    pub fn new(decode_fast_send: bool, replay_window_blocks: usize) -> Self {
        Self {
            decode_fast_send,
            replay_window_blocks,
            blocks: HashMap::new(),
            mode1_fast_seen: HashMap::new(),
            completed_blocks: HashSet::new(),
            completed_order: VecDeque::new(),
            ttl: Duration::from_secs(10),
        }
    }

    pub fn ingest(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        self.gc();

        let parsed = decode_fec_frame(frame)?;

        if self.completed_blocks.contains(&parsed.block_id) {
            return Ok(Vec::new());
        }

        if parsed.mode == FecMode::Mode1 && parsed.data_shards == 0 && parsed.parity_shards == 0 {
            if self.decode_fast_send {
                let payload = extract_payload(parsed.shard_data).ok_or(FecError::FrameMalformed)?;
                let shard_idx = parsed.shard_index as usize;

                if let Some(state) = self.blocks.get(&parsed.block_id) {
                    if shard_idx < state.delivered.len() && state.delivered[shard_idx] {
                        return Ok(Vec::new());
                    }
                }

                let entry = self
                    .mode1_fast_seen
                    .entry(parsed.block_id)
                    .or_insert_with(|| (Instant::now(), HashSet::new()));
                entry.0 = Instant::now();
                if !entry.1.insert(shard_idx) {
                    return Ok(Vec::new());
                }
                return Ok(vec![payload]);
            }
            return Ok(Vec::new());
        }

        let data_shards = parsed.data_shards as usize;
        let parity_shards = parsed.parity_shards as usize;
        let total_shards = data_shards + parity_shards;

        if data_shards == 0 || parsed.shard_index as usize >= total_shards {
            return Err(FecError::FrameMalformed);
        }

        let state = self.blocks.entry(parsed.block_id).or_insert_with(|| BlockState {
            mode: parsed.mode,
            data_shards,
            parity_shards,
            shard_len: parsed.shard_data.len(),
            shards: vec![None; total_shards],
            delivered: vec![false; data_shards],
            created_at: Instant::now(),
        });

        if state.mode != parsed.mode
            || state.data_shards != data_shards
            || state.parity_shards != parity_shards
            || state.shard_len != parsed.shard_data.len()
        {
            return Err(FecError::FrameMalformed);
        }

        if parsed.mode == FecMode::Mode1 && self.decode_fast_send {
            if let Some((_, seen)) = self.mode1_fast_seen.get(&parsed.block_id) {
                for idx in seen {
                    if *idx < state.delivered.len() {
                        state.delivered[*idx] = true;
                    }
                }
            }
        }

        let idx = parsed.shard_index as usize;
        if state.shards[idx].is_none() {
            state.shards[idx] = Some(parsed.shard_data.to_vec());
        }

        let mut out = Vec::new();

        if idx < state.data_shards && !state.delivered[idx] {
            if let Some(ref shard) = state.shards[idx] {
                if let Some(data) = extract_payload(shard) {
                    out.push(data);
                    state.delivered[idx] = true;
                }
            }
        }

        let present = state.shards.iter().filter(|s| s.is_some()).count();
        if present >= state.data_shards && state.delivered.iter().any(|d| !*d) {
            let mut work = state.shards.clone();
            let rs = ReedSolomon::new(state.data_shards, state.parity_shards).map_err(|_| FecError::InvalidShardConfig)?;
            if rs.reconstruct(&mut work).is_ok() {
                state.shards = work;
                for data_idx in 0..state.data_shards {
                    if state.delivered[data_idx] {
                        continue;
                    }
                    if let Some(ref shard) = state.shards[data_idx] {
                        if let Some(data) = extract_payload(shard) {
                            out.push(data);
                            state.delivered[data_idx] = true;
                        }
                    }
                }
            }
        }

        if state.delivered.iter().all(|d| *d) {
            self.blocks.remove(&parsed.block_id);
            self.mode1_fast_seen.remove(&parsed.block_id);
            self.mark_completed(parsed.block_id);
        }

        Ok(out)
    }

    fn gc(&mut self) {
        let ttl = self.ttl;
        self.blocks.retain(|_, block| block.created_at.elapsed() <= ttl);
        self.mode1_fast_seen
            .retain(|_, (created_at, _)| created_at.elapsed() <= ttl);
    }

    fn mark_completed(&mut self, block_id: u32) {
        if self.completed_blocks.insert(block_id) {
            self.completed_order.push_back(block_id);
            while self.completed_order.len() > self.replay_window_blocks {
                if let Some(evicted) = self.completed_order.pop_front() {
                    self.completed_blocks.remove(&evicted);
                }
            }
        }
    }
}

struct ParsedFrame<'a> {
    mode: FecMode,
    block_id: u32,
    shard_index: u8,
    data_shards: u8,
    parity_shards: u8,
    shard_data: &'a [u8],
}

pub fn encode_fec_frame(
    mode: FecMode,
    block_id: u32,
    shard_index: u8,
    data_shards: u8,
    parity_shards: u8,
    shard_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + shard_data.len());
    out.push(mode.to_wire());
    out.extend_from_slice(&block_id.to_be_bytes());
    out.push(shard_index);
    out.push(data_shards);
    out.push(parity_shards);
    out.extend_from_slice(&(shard_data.len() as u16).to_be_bytes());
    out.extend_from_slice(shard_data);
    out
}

fn decode_fec_frame(buf: &[u8]) -> Result<ParsedFrame<'_>, FecError> {
    if buf.len() < 10 {
        return Err(FecError::FrameTooShort);
    }

    let mode = FecMode::from_wire(buf[0])?;
    let block_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let shard_index = buf[5];
    let data_shards = buf[6];
    let parity_shards = buf[7];
    let shard_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;

    if buf.len() != 10 + shard_len {
        return Err(FecError::FrameMalformed);
    }

    Ok(ParsedFrame {
        mode,
        block_id,
        shard_index,
        data_shards,
        parity_shards,
        shard_data: &buf[10..],
    })
}

fn encode_data_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn extract_payload(shard: &[u8]) -> Option<Vec<u8>> {
    if shard.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([shard[0], shard[1]]) as usize;
    if len > shard.len().saturating_sub(2) {
        return None;
    }
    Some(shard[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_one_missing_data_shard() {
        let cfg = FecConfig {
            mode: FecMode::Mode0,
            data_shards: 2,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: false,
            decode_fast_send: false,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        assert!(enc.push(b"alpha").expect("push 1").is_empty());
        let shards = enc.push(b"beta").expect("push 2");
        assert_eq!(shards.len(), 3);

        let mut recovered = Vec::new();
        for frame in [shards[1].clone(), shards[2].clone()] {
            let packets = dec.ingest(&frame).expect("ingest");
            recovered.extend(packets);
        }

        assert!(recovered.iter().any(|p| p == b"alpha"));
        assert!(recovered.iter().any(|p| p == b"beta"));
    }

    #[test]
    fn mode1_fast_packet_decodes_immediately() {
        let cfg = FecConfig {
            mode: FecMode::Mode1,
            data_shards: 3,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: true,
            decode_fast_send: true,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        let frames = enc.push(b"quick").expect("push");
        assert_eq!(frames.len(), 1);
        let out = dec.ingest(&frames[0]).expect("ingest");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], b"quick");
    }

    #[test]
    fn mode1_emits_fast_and_coded_when_block_completes() {
        let cfg = FecConfig {
            mode: FecMode::Mode1,
            data_shards: 2,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: true,
            decode_fast_send: true,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");

        let first = enc.push(b"a").expect("push first");
        assert_eq!(first.len(), 1);

        let second = enc.push(b"b").expect("push second");
        assert_eq!(second.len(), 4);
    }

    #[test]
    fn mode0_flush_timeout_emits_partial_block() {
        let cfg = FecConfig {
            mode: FecMode::Mode0,
            data_shards: 4,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: false,
            decode_fast_send: false,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");

        let first = enc.push(b"only-one").expect("push");
        assert!(first.is_empty());

        let flushed = enc
            .flush_if_timed_out(Duration::ZERO)
            .expect("flush on timeout");
        assert_eq!(flushed.len(), 2);
    }

    #[test]
    fn mode1_without_encode_fast_send_delays_until_block_complete() {
        let cfg = FecConfig {
            mode: FecMode::Mode1,
            data_shards: 2,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: false,
            decode_fast_send: true,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");

        assert!(enc.push(b"x").expect("push x").is_empty());
        let second = enc.push(b"y").expect("push y");
        assert_eq!(second.len(), 3);
    }

    #[test]
    fn mode1_without_decode_fast_send_ignores_fast_frame() {
        let cfg = FecConfig {
            mode: FecMode::Mode1,
            data_shards: 2,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: true,
            decode_fast_send: false,
            replay_window_blocks: 1024,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        let first = enc.push(b"left").expect("push left");
        assert_eq!(first.len(), 1);
        let out_fast = dec.ingest(&first[0]).expect("ingest fast");
        assert!(out_fast.is_empty());

        let second = enc.push(b"right").expect("push right");
        let mut recovered = Vec::new();
        for frame in second {
            recovered.extend(dec.ingest(&frame).expect("ingest coded"));
        }
        assert!(recovered.iter().any(|p| p == b"left"));
        assert!(recovered.iter().any(|p| p == b"right"));
    }

    #[test]
    fn replay_of_completed_block_is_ignored() {
        let cfg = FecConfig {
            mode: FecMode::Mode0,
            data_shards: 1,
            parity_shards: 0,
            max_payload_size: 1500,
            encode_fast_send: false,
            decode_fast_send: false,
            replay_window_blocks: 128,
        };
        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        let frames = enc.push(b"once").expect("push once");
        assert_eq!(frames.len(), 1);

        let first = dec.ingest(&frames[0]).expect("first ingest");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0], b"once");

        let replay = dec.ingest(&frames[0]).expect("replay ingest");
        assert!(replay.is_empty());
    }

    #[test]
    fn mode1_decode_fast_send_avoids_duplicate_delivery() {
        let cfg = FecConfig {
            mode: FecMode::Mode1,
            data_shards: 2,
            parity_shards: 1,
            max_payload_size: 1500,
            encode_fast_send: true,
            decode_fast_send: true,
            replay_window_blocks: 128,
        };

        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        let first_frames = enc.push(b"p1").expect("push p1");
        assert_eq!(first_frames.len(), 1);
        let out_first = dec.ingest(&first_frames[0]).expect("ingest fast p1");
        assert_eq!(out_first, vec![b"p1".to_vec()]);

        let second_frames = enc.push(b"p2").expect("push p2");
        assert_eq!(second_frames.len(), 4);

        let mut delivered = Vec::new();
        for frame in second_frames {
            delivered.extend(dec.ingest(&frame).expect("ingest frame"));
        }

        let p1_count = delivered.iter().filter(|p| p.as_slice() == b"p1").count();
        let p2_count = delivered.iter().filter(|p| p.as_slice() == b"p2").count();

        assert_eq!(p1_count, 0);
        assert_eq!(p2_count, 1);
    }

    #[test]
    fn replay_window_eviction_allows_old_block_again() {
        let cfg = FecConfig {
            mode: FecMode::Mode0,
            data_shards: 1,
            parity_shards: 0,
            max_payload_size: 1500,
            encode_fast_send: false,
            decode_fast_send: false,
            replay_window_blocks: 1,
        };

        let mut enc = FecEncoder::new(cfg).expect("encoder");
        let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

        let frame_block1 = enc.push(b"block1").expect("push block1");
        assert_eq!(frame_block1.len(), 1);
        let out1 = dec.ingest(&frame_block1[0]).expect("ingest block1");
        assert_eq!(out1, vec![b"block1".to_vec()]);

        let frame_block2 = enc.push(b"block2").expect("push block2");
        assert_eq!(frame_block2.len(), 1);
        let out2 = dec.ingest(&frame_block2[0]).expect("ingest block2");
        assert_eq!(out2, vec![b"block2".to_vec()]);

        let replay_block1 = dec.ingest(&frame_block1[0]).expect("replay old block1");
        assert_eq!(replay_block1, vec![b"block1".to_vec()]);
    }
}
