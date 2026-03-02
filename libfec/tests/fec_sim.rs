use std::collections::HashSet;
use cat4igp_libfec::{FecConfig, FecDecoder, FecEncoder, FecMode};

fn payload_for(i: u16) -> Vec<u8> {
    i.to_be_bytes().to_vec()
}

#[test]
fn mode0_recovers_with_two_data_losses_per_block() {
    let cfg = FecConfig {
        mode: FecMode::Mode0,
        data_shards: 4,
        parity_shards: 2,
        max_payload_size: 1400,
        encode_fast_send: false,
        decode_fast_send: false,
        replay_window_blocks: 1024,
    };

    let mut enc = FecEncoder::new(cfg).expect("encoder");
    let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

    let mut expected = HashSet::new();
    let mut delivered = HashSet::new();

    for i in 0..40u16 {
        let payload = payload_for(i);
        expected.insert(payload.clone());

        let frames = enc.push(&payload).expect("encode push");
        if frames.is_empty() {
            continue;
        }

        assert_eq!(frames.len(), 6);
        for (idx, frame) in frames.into_iter().enumerate() {
            if idx == 1 || idx == 3 {
                continue;
            }
            let out = dec.ingest(&frame).expect("decoder ingest");
            for packet in out {
                delivered.insert(packet);
            }
        }
    }

    assert_eq!(expected.len(), 40);
    assert_eq!(delivered, expected);
}

#[test]
fn mode1_coded_recovery_works_when_fast_decode_disabled() {
    let cfg = FecConfig {
        mode: FecMode::Mode1,
        data_shards: 4,
        parity_shards: 2,
        max_payload_size: 1400,
        encode_fast_send: true,
        decode_fast_send: false,
        replay_window_blocks: 1024,
    };

    let mut enc = FecEncoder::new(cfg).expect("encoder");
    let mut dec = FecDecoder::new(cfg.decode_fast_send, cfg.replay_window_blocks);

    let mut expected = HashSet::new();
    let mut delivered = HashSet::new();

    for i in 0..40u16 {
        let payload = payload_for(i);
        expected.insert(payload.clone());

        let frames = enc.push(&payload).expect("encode push");
        if frames.is_empty() {
            continue;
        }

        if frames.len() == 1 {
            let out = dec.ingest(&frames[0]).expect("ingest fast frame");
            assert!(out.is_empty());
            continue;
        }

        assert_eq!(frames.len(), 7);
        for (idx, frame) in frames.into_iter().enumerate() {
            if idx == 2 || idx == 4 {
                continue;
            }
            let out = dec.ingest(&frame).expect("decoder ingest");
            for packet in out {
                delivered.insert(packet);
            }
        }
    }

    assert_eq!(expected.len(), 40);
    assert_eq!(delivered, expected);
}
