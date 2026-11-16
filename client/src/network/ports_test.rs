use super::PortRange;

#[test]
fn max_port_is_exclusive() {
    let ports = PortRange::new(10, 12);
    assert_eq!(ports.allocate(Some(12)).unwrap(), 10);
    assert_eq!(ports.allocate(Some(11)).unwrap(), 11);
}

#[test]
fn exhaustion_is_shared_and_released_ports_are_reused() {
    let ports = PortRange::new(30000, 30002);
    let other = ports.clone();
    assert_eq!(ports.allocate(Some(30001)).unwrap(), 30001);
    assert_eq!(other.allocate(Some(30001)).unwrap(), 30000);
    assert_eq!(ports.allocate(None).unwrap_err().kind(), std::io::ErrorKind::AddrNotAvailable);
    other.release(30001);
    assert_eq!(ports.allocate(None).unwrap(), 30001);
    assert_eq!(other.allocate(None).unwrap_err().kind(), std::io::ErrorKind::AddrNotAvailable);
}

#[test]
fn concurrent_allocations_never_duplicate_ports() {
    let ports = PortRange::new(30000, 30004);
    let threads: Vec<_> = (0..8).map(|_| {
        let ports = ports.clone();
        std::thread::spawn(move || ports.allocate(None))
    }).collect();
    let mut allocated = Vec::new();
    for thread in threads {
        match thread.join().unwrap() {
            Ok(port) => allocated.push(port),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable),
        }
    }
    allocated.sort_unstable();
    assert_eq!(allocated, vec![30000, 30001, 30002, 30003]);
}
