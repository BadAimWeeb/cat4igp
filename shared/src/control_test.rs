use super::*;

#[test]
fn rejects_expired_or_malformed_messages() {
    let meta = MessageMeta {
        message_id: "a".repeat(32),
        network_id: "network".into(),
        recipient_node_id: 1,
        issued_at_ms: 10,
        expires_at_ms: 20,
        topology_revision: 0,
    };
    assert!(meta.validate(20).is_ok());
    assert_eq!(meta.validate(21), Err("expired message"));

    let mut malformed = meta.clone();
    malformed.message_id = "not-an-id".into();
    assert_eq!(malformed.validate(10), Err("invalid message id"));
    let long_lived = MessageMeta {
        expires_at_ms: 60_011,
        ..meta.clone()
    };
    assert_eq!(long_lived.validate(10), Err("expired message"));
    let uppercase = MessageMeta {
        message_id: "A".repeat(32),
        ..meta
    };
    assert_eq!(uppercase.validate(10), Err("invalid message id"));
}

#[test]
fn only_new_revisions_are_applied() {
    assert_eq!(accept_revision(3, 4), Ok(true));
    assert_eq!(accept_revision(3, 3), Ok(false));
    assert_eq!(accept_revision(3, 2), Ok(false));
    assert_eq!(accept_revision(3, -1), Err("invalid topology revision"));
}

#[test]
fn topology_topics_are_versioned_and_recipient_specific() {
    assert_eq!(
        topology_topic("private", 7),
        "/cat4igp/topology/v1/private/7"
    );
}

#[test]
fn encrypted_snapshot_rejects_tampering() {
    let signing = identity::Keypair::generate_ed25519();
    let private = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&private);
    let snapshot = TopologySnapshot {
        node_id: 7,
        revision: 1,
        tunnels: Vec::new(),
    };
    let envelope = seal_topology_snapshot(
        &signing,
        &hex_encode(public.as_bytes()),
        MessageMeta {
            message_id: "a".repeat(32),
            network_id: "private".into(),
            recipient_node_id: 7,
            issued_at_ms: 10,
            expires_at_ms: 20,
            topology_revision: 1,
        },
        &snapshot,
    )
    .unwrap();
    let signing_key = hex_encode(&signing.public().encode_protobuf());
    let payload = serde_json::to_vec(&envelope).unwrap();
    assert!(verify_topology_relay(&signing.public(), "private", 20, &payload).is_ok());
    assert!(verify_topology_relay(&signing.public(), "other", 20, &payload).is_err());
    assert!(verify_topology_relay(&signing.public(), "private", 21, &payload).is_err());
    assert!(
        verify_topology_relay(
            &identity::Keypair::generate_ed25519().public(),
            "private",
            20,
            &payload
        )
        .is_err()
    );
    assert!(verify_topology_relay(&signing.public(), "private", 20, &vec![0; 65537]).is_err());
    let mut forged = envelope.clone();
    forged.meta.topology_revision += 1;
    assert!(
        verify_topology_relay(
            &signing.public(),
            "private",
            20,
            &serde_json::to_vec(&forged).unwrap()
        )
        .is_err()
    );
    forged.meta.issued_at_ms = i64::MIN;
    forged.meta.expires_at_ms = i64::MAX;
    assert!(
        verify_topology_relay(
            &signing.public(),
            "private",
            20,
            &serde_json::to_vec(&forged).unwrap()
        )
        .is_err()
    );
    assert_eq!(
        open_topology_snapshot(
            &signing_key,
            &hex_encode(&private.to_bytes()),
            "private",
            7,
            20,
            &envelope,
        )
        .unwrap()
        .revision,
        1
    );
    let mut tampered = envelope;
    tampered.meta.topology_revision = 2;
    assert!(
        open_topology_snapshot(
            &signing_key,
            &hex_encode(&private.to_bytes()),
            "private",
            7,
            20,
            &tampered,
        )
        .is_err()
    );

    let mismatched = seal_topology_snapshot(
        &signing,
        &hex_encode(public.as_bytes()),
        MessageMeta {
            message_id: "b".repeat(32),
            network_id: "private".into(),
            recipient_node_id: 7,
            issued_at_ms: 10,
            expires_at_ms: 20,
            topology_revision: 2,
        },
        &snapshot,
    )
    .unwrap();
    assert!(matches!(
        open_topology_snapshot(
            &signing_key,
            &hex_encode(&private.to_bytes()),
            "private",
            7,
            20,
            &mismatched,
        ),
        Err("snapshot metadata mismatch")
    ));
}

#[test]
fn encrypted_tunnel_answer_rejects_tampering() {
    let signing = identity::Keypair::generate_ed25519();
    let private = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
    let answer = TunnelAnswer {
        tunnel_id: 7,
        decline_type: None,
        endpoint: Some("127.0.0.1:51820".into()),
    };
    let envelope = seal_tunnel_answer(
        &signing,
        &hex_encode(x25519_dalek::PublicKey::from(&private).as_bytes()),
        MessageMeta {
            message_id: "c".repeat(32),
            network_id: "private".into(),
            recipient_node_id: 1,
            issued_at_ms: 10,
            expires_at_ms: 20,
            topology_revision: 0,
        },
        &answer,
    )
    .unwrap();
    let signing_key = hex_encode(&signing.public().encode_protobuf());
    assert_eq!(
        open_tunnel_answer(
            &signing_key,
            &hex_encode(&private.to_bytes()),
            "private",
            1,
            20,
            &envelope,
        )
        .unwrap()
        .tunnel_id,
        7
    );
    let mut tampered = envelope;
    tampered.ciphertext.replace_range(
        0..1,
        if tampered.ciphertext.starts_with('0') {
            "1"
        } else {
            "0"
        },
    );
    assert!(
        open_tunnel_answer(
            &signing_key,
            &hex_encode(&private.to_bytes()),
            "private",
            1,
            20,
            &tampered,
        )
        .is_err()
    );
}
