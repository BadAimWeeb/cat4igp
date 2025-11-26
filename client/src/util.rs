use std::net::IpAddr;

pub const IPV4_DEFAULT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
pub const IPV6_DEFAULT: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
