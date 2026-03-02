use std::collections::HashSet;

use cat4igp_libfec::{FecConfig, FecDecoder, FecEncoder, FecMode};

#[derive(Clone, Copy)]
struct SimParams {
    drop_mod: u32,
    dup_mod: u32,
    reorder_chunk: usize,
}

fn payload_for(i: u16) -> Vec<u8> {
    i.to_be_bytes().to_vec()
}

fn apply_network_sim(frames: Vec<Vec<u8>>, mut seed: u32, sim: SimParams) -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    for frame in frames {
        seed = lcg(seed);
        if sim.drop_mod > 0 && seed % sim.drop_mod == 0 {
            continue;
        }

        out.push(frame.clone());

        seed = lcg(seed);
        if sim.dup_mod > 0 && seed % sim.dup_mod == 0 {
            out.push(frame);
        }
    }

    if sim.reorder_chunk > 1 {
        for chunk in out.chunks_mut(sim.reorder_chunk) {
            chunk.reverse();
        }
    }

    out
}

fn lcg(seed: u32) -> u32 {
    seed.wrapping_mul(1664525).wrapping_add(1013904223)
}

fn run_case(cfg: FecConfig, packet_count: u16, sim: SimParams) -> (usize, usize) {
    let mut enc = FecEncoder::new(cfg).expect("encoder");
    let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

    let mut expected = HashSet::new();
    let mut delivered = HashSet::new();

    let mut block_seed = 1u32;

    for i in 0..packet_count {
        let payload = payload_for(i);
        expected.insert(payload.clone());

        let frames = enc.push(&payload).expect("encode push");
        if frames.is_empty() {
            continue;
        }

        let networked = apply_network_sim(frames, block_seed, sim);
        block_seed = lcg(block_seed);

        for frame in networked {
            let out = dec.ingest(&frame).expect("decoder ingest");
            for packet in out {
                delivered.insert(packet);
            }
        }
    }

    (delivered.len(), expected.len())
}

#[test]
fn matrix_mode0_and_mode1_stress() {
    let sim = SimParams {
        drop_mod: 7,
        dup_mod: 5,
        reorder_chunk: 3,
    };

    let cases = [
        FecConfig {
            mode: FecMode::Mode0,
            data_shards: 4,
            parity_shards: 2,
            max_payload_size: 1400,
            encode_fast_send: false,
            decode_fast_send: false,
            replay_window_blocks: 1024,
        },
        FecConfig {
            mode: FecMode::Mode1,
            data_shards: 4,
            parity_shards: 2,
            max_payload_size: 1400,
            encode_fast_send: true,
            decode_fast_send: true,
            replay_window_blocks: 1024,
        },
        FecConfig {
            mode: FecMode::Mode1,
            data_shards: 4,
            parity_shards: 2,
            max_payload_size: 1400,
            encode_fast_send: true,
            decode_fast_send: false,
            replay_window_blocks: 1024,
        },
    ];

    for cfg in cases {
        let (delivered, expected) = run_case(cfg, 120, sim);

        let ratio = delivered as f64 / expected as f64;
        assert!(
            ratio >= 0.92,
            "recovery ratio too low: mode={:?}, delivered={}, expected={}, ratio={:.3}",
            cfg.mode,
            delivered,
            expected,
            ratio
        );
    }
}
