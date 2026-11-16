use super::*;

#[test]
fn test_port_range() {
    let range = PortRange::new(1000, 2000).unwrap();
    assert!(range.contains(1500));
    assert!(!range.contains(500));
    assert!(!range.contains(2000));
}

#[test]
fn test_default_config() {
    let config = ClientConfig::default();
    assert_eq!(config.daemon_socket, PathBuf::from("/run/cat4igp-client.sock"));
    assert!(config.tunnel_protocols.wireguard);
    assert_eq!(config.public_hostname_ipv4, None);
    assert_eq!(config.public_hostname_ipv6, None);
}

#[test]
fn l2tp_requires_explicit_opt_in() {
    let default = ClientConfig::default();
    assert!(!default.tunnel_protocols.l2tp);
    assert!(!default.allow_insecure_l2tp);
    assert!(!default.l2tp_v2_userspace);
    let mut config = toml::to_string(&default).unwrap();
    config = config.replace("\nl2tp = false", "\nl2tp = true");
    let parsed: ClientConfig = toml::from_str(&config).unwrap();
    assert!(parsed.tunnel_protocols.l2tp);
    assert!(!parsed.allow_insecure_l2tp);
    let userspace: ClientConfig = toml::from_str(&config.replace("l2tp_v2_userspace = false", "l2tp_v2_userspace = true")).unwrap();
    assert!(userspace.l2tp_v2_userspace);
}

#[test]
fn packaged_configs_parse() {
    for (sample, data_dir) in [
        (
            include_str!("../../../packaging/client.toml"),
            "/var/lib/cat4igp-client",
        ),
        (
            include_str!("../../../packaging/openwrt/files/client.toml"),
            "/etc/cat4igp/state",
        ),
    ] {
        let config: ClientConfig = toml::from_str(sample).unwrap();
        assert_eq!(
            config.daemon_socket,
            PathBuf::from("/run/cat4igp-client.sock")
        );
        assert_eq!(config.data_dir, PathBuf::from(data_dir));
        assert!(config.tunnel_protocols.wireguard);
        assert!(PortRange::new(config.port_range.min, config.port_range.max).is_ok());
    }
}

#[test]
fn registration_material_is_not_client_configuration() {
    let config = ClientConfig::default();
    let toml = toml::to_string_pretty(&config).unwrap();
    let json = config.to_json().unwrap();
    for text in [&toml, &json] {
        assert!(!text.contains("control_bootstrap_addresses"));
        assert!(!text.contains("control_private_network_key"));
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.toml");
    for field in [
        "control_bootstrap_addresses = [\"secret-address\"]",
        "control_private_network_key = \"secret-key\"",
    ] {
        let source = format!("{field}\n{toml}");
        std::fs::write(&path, &source).unwrap();
        let error = ClientConfig::from_file(&path).unwrap_err().to_string();
        assert!(error.contains("legacy control"));
        assert!(!error.contains("secret-"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
        assert!(toml::from_str::<ClientConfig>(&source).is_err());
    }
    for field in ["control_bootstrap_addresses", "control_private_network_key"] {
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value[field] = serde_json::json!("secret-value");
        let error = ClientConfig::from_json(&value.to_string()).unwrap_err().to_string();
        assert!(error.contains("legacy control"));
        assert!(!error.contains("secret-value"));
    }
    let unknown = format!("future_setting = true\n{toml}");
    assert!(toml::from_str::<ClientConfig>(&unknown).is_ok());
}
