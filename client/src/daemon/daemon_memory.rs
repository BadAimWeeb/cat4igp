use std::collections::HashMap;

pub mod wireguard;

pub struct DaemonMemory {
    wireguard: HashMap<i32, wireguard::WireguardTunnelC>,
}

impl DaemonMemory {
    pub fn new() -> Self {
        Self {
            wireguard: HashMap::new(),
        }
    }
}
