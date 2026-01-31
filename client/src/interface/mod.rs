use futures_util::StreamExt;
use ipnet::IpNet;
use rtnetlink::{new_connection, packet_route::link::{LinkFlags, LinkHeader, LinkMessage, LinkAttribute}};

use blake2::{Blake2s256, Digest};
use std::net::IpAddr;
use std::net::Ipv6Addr;

pub const IPV4_DEFAULT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
pub const IPV6_DEFAULT: IpAddr = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

pub fn generate_ipv6_lla_from_mac(mac: [u8; 6]) -> IpAddr {
    let mut addr = [0u8; 16];
    addr[0] = 0xfe;
    addr[1] = 0x80;
    addr[8] = mac[0] ^ 0x02;
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xff;
    addr[12] = 0xfe;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    IpAddr::V6(std::net::Ipv6Addr::from(addr))
}

pub fn generate_ipv6_lla_from_seed(seed: Vec<u8>) -> IpAddr {
    let mut hasher = Blake2s256::new();

    hasher.update(seed);
    let hash = hasher.finalize();

    let prefix: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mask: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0];
    let not_mask: [u8; 16] = mask.map(|b| !b);

    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = (prefix[i] & mask[i]) | (hash[i] & not_mask[i]);
    }

    IpAddr::V6(Ipv6Addr::from(result))
}


pub async fn set_addr(interface: String, addr: IpNet) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;

    let conn_poll = tokio::spawn(connection);

    let mut link_list_stream = handle.link().get().match_name(interface).execute();

    let mut id = None;
    if let Some(Ok(link_msg)) = link_list_stream.next().await {
        id = Some(link_msg.header.index);
    }

    let link_index = id.ok_or("failed to find interface")?;

    handle
        .address()
        .add(link_index, addr.addr(), addr.prefix_len())
        .execute()
        .await?;

    conn_poll.abort();
    Ok(())
}

pub async fn link_up_with_mtu(interface: String, mtu: u32) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;

    let conn_poll = tokio::spawn(connection);

    let mut link_list_stream = handle.link().get().match_name(interface).execute();

    let mut id = None;
    if let Some(Ok(link_msg)) = link_list_stream.next().await {
        id = Some(link_msg.header.index);
    }

    let link_index = id.ok_or("failed to find interface")?;

    let header = LinkHeader {
        index: link_index,
        flags: LinkFlags::Up,
        ..Default::default()
    };
    let mut message = LinkMessage::default();
    message.header = header;
    message.attributes = vec![LinkAttribute::Mtu(mtu)];

    handle.link().set(message).execute().await?;

    conn_poll.abort();
    Ok(())
}
