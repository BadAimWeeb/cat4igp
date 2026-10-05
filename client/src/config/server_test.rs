use super::*;
use tempfile::TempDir;

#[test]
#[cfg(unix)]
fn publication_faults_preserve_pending_identity_and_clean_secrets() {
    use std::os::unix::fs::PermissionsExt;
    let directory = TempDir::new().unwrap();
    let root = directory.path();
    let path = root.join("server.json");
    let mut pending = ServerConfig::new("trusted-seed".into(), "pending-invite".into());
    pending.ensure_control_keypair().unwrap();
    pending.ensure_control_encryption_key().unwrap();
    pending.ensure_wireguard_keypair().unwrap();
    pending.enrollment_node_name = Some("original-name".into());
    pending.save(root).unwrap();
    let old = fs::read(&path).unwrap();
    let mut completed = pending.clone();
    completed.control_node_id = Some(42);
    completed.invite_code.clear();
    let check = |expected: &ServerConfig| {
        assert_eq!(
            serde_json::to_value(ServerConfig::load(root).unwrap()).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(root).unwrap().count(),
            1,
            "temporary secret leaked"
        );
    };
    // ponytail: deterministic I/O seams on a live filesystem, not power loss;
    // add a crash/power-cut harness to test kernel/filesystem persistence guarantees.
    for seam in ["partial_write", "publish"] {
        let mut reached = false;
        let error = completed
            .save_inner(root, |stage| {
                if stage != seam {
                    return Ok(());
                }
                reached = true;
                let temporary = fs::read_dir(root)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|entry| entry != &path)
                    .unwrap();
                assert_eq!(
                    fs::metadata(&temporary).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                if stage == "partial_write" {
                    assert!(
                        serde_json::from_slice::<ServerConfig>(&fs::read(temporary).unwrap())
                            .is_err()
                    );
                }
                Err(io::Error::other("injected publication failure"))
            })
            .unwrap_err();
        assert!(reached);
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(fs::read(&path).unwrap(), old);
        check(&pending);
    }
    // Rename has happened: a failed directory barrier must return Err, retain
    // the valid new identity, and never attempt destructive rollback.
    assert!(
        completed
            .save_inner(root, |stage| {
                if stage == "parent_sync" {
                    Err(io::Error::other("injected directory sync failure"))
                } else {
                    Ok(())
                }
            })
            .is_err()
    );
    check(&completed);
    let mut stages = Vec::new();
    completed
        .save_inner(root, |stage| {
            stages.push(stage.to_owned());
            Ok(())
        })
        .unwrap();
    assert_eq!(
        stages,
        ["partial_write", "publish", "parent_sync", "durable"]
    );
    check(&completed);
}

#[test]
fn public_seeds_are_capped_deduplicated_and_withdrawn_without_changing_pins() {
    use cat4igp_shared::discovery::*;
    let authority = libp2p::identity::Keypair::generate_ed25519();
    let mut config = ServerConfig::new(String::new(), "invite".into());
    config.controller_signing_key = Some(hex_encode(&authority.public().encode_protobuf()));
    config.controller_peer_id = Some(authority.public().to_peer_id().to_string());
    let requester = config
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    let before = config.clone();
    let endpoints: Vec<_> = (0..5)
        .map(|i| {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            ControllerEndpoint {
                peer_id: peer,
                addresses: (0..4)
                    .map(|j| {
                        format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer}", 9000 + i * 4 + j)
                            .parse()
                            .unwrap()
                    })
                    .collect(),
            }
        })
        .collect();
    let make = |revision, discovery_endpoints| {
        ControllerAvailable {
            version: VERSION,
            cluster_id: "default".into(),
            role: Role::Client,
            recipient: requester,
            nonce: [1; 16],
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            endpoint: endpoints[0].clone(),
            roster: ControllerRoster {
                version: VERSION,
                cluster_id: "default".into(),
                revision,
                issued_at_ms: 1000,
                expires_at_ms: 60_000,
                controllers: endpoints.clone(),
                discovery_endpoints,
            }
            .sign(&authority)
            .unwrap(),
        }
        .sign(&authority)
        .unwrap()
    };
    config.discovery_bootstrap_addresses = vec![endpoints[0].addresses[0].to_string(); 16];
    config
        .accept_discovery_proof(make(7, endpoints.clone()), 1000)
        .unwrap();
    assert_eq!(config.discovery_bootstrap_addresses.len(), 16);
    let unique: std::collections::HashSet<_> =
        config.discovery_bootstrap_addresses.iter().collect();
    assert_eq!(unique.len(), 16);
    let directory = TempDir::new().unwrap();
    config.save(directory.path()).unwrap();
    let mut config = ServerConfig::load(directory.path()).unwrap();
    assert_eq!(config.discovery_bootstrap_addresses.len(), 16);
    assert!(
        config
            .accept_discovery_proof(make(6, vec![]), 1000)
            .is_err()
    );
    config
        .accept_discovery_proof(make(8, vec![endpoints[4].clone()]), 1000)
        .unwrap();
    assert_eq!(
        config.discovery_bootstrap_addresses,
        endpoints[4]
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    let mut expected = serde_json::to_value(before).unwrap();
    let actual = serde_json::to_value(config).unwrap();
    for field in [
        "discovery_bootstrap_addresses",
        "control_bootstrap_addresses",
        "discovery_proof",
    ] {
        expected[field] = actual[field].clone();
    }
    assert_eq!(expected, actual);
}

#[test]
fn durable_roster_refresh_rejects_rollback_substitution_and_expiry() {
    use cat4igp_shared::discovery::*;
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id();
    let mut config = ServerConfig::new(String::new(), String::new());
    config.controller_signing_key = Some(hex_encode(&key.public().encode_protobuf()));
    config.controller_peer_id = Some(peer.to_string());
    config.discovery_bootstrap_addresses = vec!["enabled".into()];
    let requester = config
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    let endpoint = ControllerEndpoint {
        peer_id: peer,
        addresses: vec![
            format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}")
                .parse()
                .unwrap(),
        ],
    };
    let make = |revision, expires| {
        ControllerAvailable {
            version: VERSION,
            cluster_id: "default".into(),
            role: Role::Client,
            recipient: requester,
            nonce: [1; 16],
            issued_at_ms: 1000,
            expires_at_ms: 2000,
            endpoint: endpoint.clone(),
            roster: ControllerRoster {
                version: VERSION,
                cluster_id: "default".into(),
                revision,
                issued_at_ms: 1000,
                expires_at_ms: expires,
                controllers: vec![endpoint.clone()],
                discovery_endpoints: vec![],
            }
            .sign(&key)
            .unwrap(),
        }
        .sign(&key)
        .unwrap()
    };
    assert!(!config.discovery_authorized(1000));
    config
        .accept_discovery_proof(make(7, 60_000), 1000)
        .unwrap();
    let directory = TempDir::new().unwrap();
    config.save(directory.path()).unwrap();
    let mut config = ServerConfig::load(directory.path()).unwrap();
    assert!(config.discovery_authorized(59_999));
    assert!(!config.discovery_authorized(60_000));
    assert!(
        config
            .accept_discovery_proof(make(6, 60_000), 1000)
            .is_err()
    );
    assert!(
        config
            .accept_discovery_proof(make(7, 61_000), 1000)
            .is_err()
    );
    assert!(
        config
            .accept_discovery_proof(make(8, 61_000), 2000)
            .is_err()
    );
    let mut wrong = make(8, 61_000).body;
    wrong.recipient = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    assert!(
        config
            .accept_discovery_proof(wrong.sign(&key).unwrap(), 1000)
            .is_err()
    );
    let mut wrong_source = make(8, 61_000).body;
    let other = libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id();
    wrong_source.endpoint = ControllerEndpoint {
        peer_id: other,
        addresses: vec![
            format!("/ip4/127.0.0.1/tcp/9001/p2p/{other}")
                .parse()
                .unwrap(),
        ],
    };
    assert!(
        config
            .accept_discovery_proof(wrong_source.sign(&key).unwrap(), 1000)
            .is_err()
    );
    let forged = make(8, 61_000)
        .body
        .sign(&libp2p::identity::Keypair::generate_ed25519())
        .unwrap();
    assert!(config.accept_discovery_proof(forged, 1000).is_err());
    assert_eq!(
        config
            .discovery_proof
            .as_ref()
            .unwrap()
            .body
            .roster
            .body
            .revision,
        7
    );
    config
        .accept_discovery_proof(make(8, 61_000), 1000)
        .unwrap();
    config.save(directory.path()).unwrap();
    assert_eq!(
        ServerConfig::load(directory.path())
            .unwrap()
            .discovery_proof
            .unwrap()
            .body
            .roster
            .body
            .revision,
        8
    );
    let mut replica = make(9, 62_000).body;
    replica.endpoint = ControllerEndpoint {
        peer_id: other,
        addresses: vec![
            format!("/ip4/127.0.0.1/tcp/9001/p2p/{other}")
                .parse()
                .unwrap(),
        ],
    };
    replica.roster.body.controllers = vec![replica.endpoint.clone()];
    replica.roster = replica.roster.body.sign(&key).unwrap();
    config
        .accept_discovery_proof(replica.sign(&key).unwrap(), 1000)
        .unwrap();
    config.save(directory.path()).unwrap();
    assert_eq!(
        ServerConfig::load(directory.path())
            .unwrap()
            .discovery_proof
            .unwrap()
            .body
            .endpoint
            .peer_id,
        other
    );
    let (updates, _) = tokio::sync::mpsc::channel(1);
    assert!(
        crate::daemon::control::start(
            config.clone(),
            updates,
            std::sync::Arc::new(tokio::sync::Mutex::new(Some(config.clone())))
        )
        .is_err()
    );
    config.discovery_bootstrap_addresses.clear();
    assert!(config.discovery_authorized(100_000));
}

#[test]
fn trusted_bundle_validates_and_persists_pin() {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let peer = key.public().to_peer_id().to_string();
    let address = format!("/ip4/127.0.0.1/tcp/2025/p2p/{peer}");
    let bundle = cat4igp_shared::control::EnrollmentBundle {
        version: 1,
        bootstrap_addresses: vec![address.clone()],
        controller_peer_id: peer,
        controller_signing_key: hex_encode(&key.public().encode_protobuf()),
        network_id: "bundle-test".into(),
        private_network_key: format!("/key/swarm/psk/1.0.0/\n/base16/\n{}", "01".repeat(32)),
        invitation_code: "secret-invite".into(),
        discovery_bootstrap_addresses: vec![address],
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let config = ServerConfig::from_bundle(&json).unwrap();
    let directory = TempDir::new().unwrap();
    config.save(directory.path()).unwrap();
    config.save(directory.path()).unwrap();
    let loaded = ServerConfig::load(directory.path()).unwrap();
    assert_eq!(
        loaded.controller_signing_key.as_deref(),
        Some(bundle.controller_signing_key.as_str())
    );
    assert_eq!(
        loaded.discovery_bootstrap_addresses,
        bundle.discovery_bootstrap_addresses
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(directory.path().join("server.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let mut invalid = serde_json::to_value(&bundle).unwrap();
    for (field, value) in [
        ("version", serde_json::json!(2)),
        (
            "controller_signing_key",
            serde_json::json!(hex_encode(
                &libp2p::identity::Keypair::generate_ed25519()
                    .public()
                    .encode_protobuf()
            )),
        ),
        (
            "bootstrap_addresses",
            serde_json::json!(["/ip4/127.0.0.1/tcp/2025"]),
        ),
        ("private_network_key", serde_json::json!("invalid")),
        ("invitation_code", serde_json::json!("")),
        ("extra_secret", serde_json::json!("rejected")),
    ] {
        let original = invalid.clone();
        invalid[field] = value;
        assert!(
            ServerConfig::from_bundle(&invalid.to_string()).is_err(),
            "{field}"
        );
        invalid = original;
    }
    assert!(ServerConfig::from_bundle(&" ".repeat(16 * 1024 + 1)).is_err());
    assert!(hex_decode("é").is_err());
    let mut legacy = serde_json::to_value(&config).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("discovery_bootstrap_addresses");
    legacy.as_object_mut().unwrap().remove("discovery_proof");
    assert!(
        serde_json::from_value::<ServerConfig>(legacy)
            .unwrap()
            .discovery_bootstrap_addresses
            .is_empty()
    );
}

#[test]
fn test_server_config_creation() {
    let config = ServerConfig::new(
        "https://example.com:8443".to_string(),
        "invite123".to_string(),
    );
    assert_eq!(config.address, "https://example.com:8443");
    assert_eq!(config.invite_code, "invite123");
}

#[test]
fn test_server_config_save_load() {
    let temp_dir = TempDir::new().unwrap();
    let config = ServerConfig::new("https://example.com".to_string(), "test-invite".to_string());

    config.save(temp_dir.path()).unwrap();
    let loaded = ServerConfig::load(temp_dir.path()).unwrap();

    assert_eq!(loaded.address, config.address);
    assert_eq!(loaded.invite_code, config.invite_code);
}

#[test]
fn control_identity_is_persistent() {
    let mut config = ServerConfig::new("control".to_string(), "invite".to_string());
    let first = config
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    let second = config
        .ensure_control_keypair()
        .unwrap()
        .public()
        .to_peer_id();
    assert_eq!(first, second);
}

#[test]
fn control_encryption_identity_is_persistent() {
    let mut config = ServerConfig::new("control".to_string(), "invite".to_string());
    assert_eq!(
        config.ensure_control_encryption_key().unwrap(),
        config.ensure_control_encryption_key().unwrap()
    );
}
