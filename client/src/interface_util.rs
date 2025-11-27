use futures_util::StreamExt;
use ipnet::IpNet;
use rtnetlink::{new_connection, packet_route::link::{LinkFlags, LinkHeader, LinkMessage, LinkAttribute}};

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
