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
