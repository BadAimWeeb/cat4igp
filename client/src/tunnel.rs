pub mod shared;
pub mod wireguard;

pub mod l2tp;
#[cfg(target_os = "linux")]
pub(crate) mod l2tp_v2;

pub enum TunnelType {
    WireGuard,
    L2tp,
}
