use super::PortRange;

#[test]
fn max_port_is_exclusive() {
    let ports = PortRange::new(10, 12);
    assert_eq!(ports.allocate(Some(12)).unwrap(), 10);
    assert_eq!(ports.allocate(Some(11)).unwrap(), 11);
}
