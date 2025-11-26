use crate::tunnel::TunnelType;

pub trait Tunnel {
    async fn setup(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    async fn destroy(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn get_interface_name(&self) -> &str;
    fn get_type(&self) -> TunnelType;
}


