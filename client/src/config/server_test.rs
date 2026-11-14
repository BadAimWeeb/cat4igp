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
    assert_eq!(loaded.control_bootstrap_addresses, bundle.bootstrap_addresses);
    assert!(loaded.control_peer_authorized(key.public().to_peer_id()));
    assert!(!loaded.control_peer_authorized(libp2p::identity::Keypair::generate_ed25519().public().to_peer_id()));
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
        ("bootstrap_addresses", serde_json::json!([format!("/ip4/127.0.0.1/tcp/2025/p2p/{}", libp2p::identity::Keypair::generate_ed25519().public().to_peer_id())])),
        ("network_id", serde_json::json!("bad/network")),
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
    legacy["discovery_bootstrap_addresses"] = serde_json::json!(["obsolete"]);
    legacy["discovery_proof"] = serde_json::json!({"obsolete": true});
    let loaded: ServerConfig = serde_json::from_value(legacy).unwrap();
    assert_eq!(loaded.controller_peer_id, config.controller_peer_id);
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
