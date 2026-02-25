use crate::tunnel::TunnelType;

pub trait Tunnel {
    async fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    async fn destroy(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn get_interface_name(&self) -> &str;
    fn get_type(&self) -> TunnelType;
    async fn get_mtu(&self) -> Result<u32, Box<dyn std::error::Error>>;
    fn is_ift_created(&self) -> bool;
    fn is_connected(&self) -> Result<bool, Box<dyn std::error::Error>>;
}


