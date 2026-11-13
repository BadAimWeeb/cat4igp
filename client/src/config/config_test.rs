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
    assert!(config.tunnel_protocols.wireguard);
    assert_eq!(config.public_hostname_ipv4, None);
    assert_eq!(config.public_hostname_ipv6, None);
}

#[test]
fn l2tp_requires_explicit_opt_in() {
    let default = ClientConfig::default();
    assert!(!default.tunnel_protocols.l2tp);
    assert!(!default.allow_insecure_l2tp);
    let mut config = toml::to_string(&default).unwrap();
    config = config.replace("\nl2tp = false", "\nl2tp = true");
    let parsed: ClientConfig = toml::from_str(&config).unwrap();
    assert!(parsed.tunnel_protocols.l2tp);
    assert!(!parsed.allow_insecure_l2tp);
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
            PathBuf::from("/var/run/cat4igp-client.sock")
        );
        assert_eq!(config.data_dir, PathBuf::from(data_dir));
        assert!(config.tunnel_protocols.wireguard);
        assert!(PortRange::new(config.port_range.min, config.port_range.max).is_ok());
    }
}
