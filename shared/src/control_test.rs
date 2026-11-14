use super::*;

#[test]
fn feature_support_defaults_missing_fields_to_unsupported() {
    let features: FeatureSupport = serde_json::from_str(r#"{"wireguard":true,"future":true}"#).unwrap();
    assert!(features.wireguard);
    assert!(!features.fec && !features.faketcp && !features.l2tp_v2 && !features.l2tp_v3);
    assert!(FeatureSupport::server().supports(features));
    assert!(!features.supports(FeatureSupport { fec: true, ..Default::default() }));
    let message = ControlRequest::Features(features);
    assert!(matches!(serde_json::from_str::<ControlRequest>(&serde_json::to_string(&message).unwrap()).unwrap(), ControlRequest::Features(value) if value == features));
}

#[test]
fn l2tp_capability_report_binds_identity_network_and_nonce() {
    let key = identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let mut report = L2tpCapabilityReport { version: 1, network_id: "network".into(), node_id: 7,
        peer_id: peer.to_string(), nonce: "ab".repeat(32), supported: vec![] };
    let signature = report.sign(&key).unwrap();
    assert!(report.verify(&key.public(), "network", 7, &peer, &"ab".repeat(32), &signature));
    assert!(!report.verify(&key.public(), "other", 7, &peer, &"ab".repeat(32), &signature));
    assert!(!report.verify(&key.public(), "network", 8, &peer, &"ab".repeat(32), &signature));
    assert!(!report.verify(&key.public(), "network", 7, &peer, &"cd".repeat(32), &signature));
    report.supported.push("unimplemented".into());
    assert!(report.sign(&key).is_err());
    assert!(!report.verify(&key.public(), "network", 7, &peer, &"ab".repeat(32), &signature));
    assert!(serde_json::from_str::<L2tpCapabilityReport>(r#"{"version":1,"network_id":"network","node_id":7,"peer_id":"x","nonce":"x","supported":[],"extra":true}"#).is_err());
}

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
fn l2tp_status_is_fail_closed_for_legacy_snapshots() {
    let legacy = r#"{"node_id":1,"revision":1,"tunnels":[]}"#;
    let snapshot: TopologySnapshot = serde_json::from_str(legacy).unwrap();
    assert!(snapshot.l2tp_availability.is_none());
    assert!(snapshot.l2tp_v2_tunnels.is_empty());
    assert_eq!(serde_json::to_string(&snapshot).unwrap(), legacy);
    let current = r#"{"node_id":1,"revision":1,"tunnels":[],"l2tp_availability":{"v2":false,"v3":false}}"#;
    let snapshot: TopologySnapshot = serde_json::from_str(current).unwrap();
    let availability = snapshot.l2tp_availability.unwrap();
    assert!(!availability.v2 && !availability.v3);
    assert!(serde_json::from_str::<TopologySnapshot>(r#"{"node_id":1,"revision":1,"tunnels":[],"l2tp_availability":{"v2":false}}"#).is_err());
    let info = L2tpV2TunnelInfo { tunnel_id: 1, peer_node_id: 2, wireguard_tunnel_id: None, local_endpoint: "192.0.2.1".into(), remote_endpoint: "192.0.2.2".into(), local_port: 1701, remote_port: 1702, local_address: "10.0.0.1".into(), remote_address: "10.0.0.2".into(), secret: "private".into(), mtu: 1400, initiator: true };
    assert!(!format!("{info:?}").contains("private"));
    let snapshot: TopologySnapshot = serde_json::from_value(serde_json::json!({"node_id":1,"revision":1,"tunnels":[],"l2tp_v2_tunnels":[info]})).unwrap();
    assert_eq!(snapshot.l2tp_v2_tunnels[0].secret, "private");
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
        l2tp_tunnels: Vec::new(),
        l2tp_v2_tunnels: Vec::new(),
        l2tp_availability: None,
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
        refresh: None,
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

#[test]
fn low_order_x25519_keys_are_rejected_at_all_control_boundaries() {
    let signing = identity::Keypair::generate_ed25519();
    let private = x25519_dalek::StaticSecret::from([7; 32]);
    let public = hex_encode(x25519_dalek::PublicKey::from(&private).as_bytes());
    let signing_public = hex_encode(&signing.public().encode_protobuf());
    let meta = MessageMeta {
        message_id: "a".repeat(32), network_id: "private".into(), recipient_node_id: 7,
        issued_at_ms: 10, expires_at_ms: 20, topology_revision: 1,
    };
    let snapshot = TopologySnapshot {
        node_id: 7, revision: 1, tunnels: vec![], l2tp_tunnels: vec![],
        l2tp_v2_tunnels: vec![], l2tp_availability: None,
    };
    let answer = TunnelAnswer { tunnel_id: 7, decline_type: None, endpoint: None, refresh: None };
    assert!(validate_encryption_public_key(&public).is_ok());
    assert!(validate_encryption_public_key("not a key").is_err());
    for low_order in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        let low_order = hex_encode(&low_order);
        assert_eq!(validate_encryption_public_key(&low_order), Err("invalid X25519 public key"));
        assert!(matches!(seal_topology_snapshot(&signing, &low_order, meta.clone(), &snapshot), Err("invalid X25519 public key")));
        assert!(matches!(seal_tunnel_answer(&signing, &low_order, meta.clone(), &answer), Err("invalid X25519 public key")));
        let mut topology = seal_topology_snapshot(&signing, &public, meta.clone(), &snapshot).unwrap();
        topology.ephemeral_public_key = low_order.clone();
        topology.signature = hex_encode(&signing.sign(&envelope_bytes(&topology).unwrap()).unwrap());
        assert!(matches!(open_topology_snapshot(&signing_public, &hex_encode(&private.to_bytes()), "private", 7, 20, &topology), Err("invalid X25519 public key")));
        let mut tunnel = seal_tunnel_answer(&signing, &public, meta.clone(), &answer).unwrap();
        tunnel.ephemeral_public_key = low_order;
        tunnel.signature = hex_encode(&signing.sign(&envelope_bytes(&tunnel).unwrap()).unwrap());
        assert!(matches!(open_tunnel_answer(&signing_public, &hex_encode(&private.to_bytes()), "private", 7, 20, &tunnel), Err("invalid X25519 public key")));
    }
}
