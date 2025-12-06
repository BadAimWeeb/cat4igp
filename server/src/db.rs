use diesel::prelude::*;
use std::env;
use crate::{ext, models::{Invite, Node}};
use uuid::Uuid;

pub fn establish_connection() -> SqliteConnection {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn authenticate(conn: &mut SqliteConnection, key: &str) -> Result<Node, diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .filter(auth_key.eq(key))
        .select(Node::as_select())
        .first(conn)
}

pub fn register_node(conn: &mut SqliteConnection, node_name: &str, invitation_key: &str) -> Result<String, diesel::result::Error> {
    use crate::schema::nodes;
    use crate::schema::invites::dsl::*;

    let inv = invites
        .filter(code.eq(invitation_key))
        .first::<Invite>(conn)?;

    if let Some(max) = inv.max_uses {
        if inv.used_count >= max {
            return Err(diesel::result::Error::NotFound);
        }
    }

    diesel::update(invites.filter(id.eq(inv.id)))
        .set(used_count.eq(used_count + 1))
        .execute(conn)?;

    let nauthk = Uuid::new_v4().to_string();

    let new_node = crate::models::NewNode {
        name: node_name,
        auth_key: &nauthk,
    };

    diesel::insert_into(nodes::table)
        .values(&new_node)
        .execute(conn)?;

    Ok(nauthk)
}

pub fn update_node_name(conn: &mut SqliteConnection, node_id_val: i32, new_name: &str) -> Result<(), diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    diesel::update(nodes.filter(id.eq(node_id_val)))
        .set(name.eq(new_name))
        .execute(conn)?;
    
    Ok(())
}

pub fn get_server_side_node_info(conn: &mut SqliteConnection, node_id_val: i32) -> Result<(String, chrono::NaiveDateTime), diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .filter(id.eq(node_id_val))
        .select((name, created_at))
        .first::<(String, chrono::NaiveDateTime)>(conn)
}

pub fn get_node_list(conn: &mut SqliteConnection) -> Result<Vec<crate::models::Node>, diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .select(crate::models::Node::as_select())
        .load::<crate::models::Node>(conn)
}

pub fn update_wireguard_pubkey(conn: &mut SqliteConnection, node_id_val: i32, pubkey: &str) -> Result<(), diesel::result::Error> {
    use crate::schema::wireguard_static_key;
    use crate::schema::wireguard_static_key::dsl::*;

    let new_pk = crate::models::NewWireguardStaticKey {
        node_id: node_id_val,
        public_key: pubkey,
    };

    diesel::insert_into(wireguard_static_key::table)
        .values(&new_pk)
        .on_conflict(node_id)
        .do_update()
        .set(public_key.eq(pubkey))
        .execute(conn)?;
    Ok(())
}

pub fn get_wireguard_pubkey(conn: &mut SqliteConnection, node_id_val: i32) -> Result<String, diesel::result::Error> {
    use crate::schema::wireguard_static_key::dsl::*;

    let key_record = wireguard_static_key
        .filter(node_id.eq(node_id_val))
        .select(public_key)
        .first::<String>(conn)?;

    Ok(key_record) 
}

pub fn create_wireguard_tunnel(
    conn: &mut SqliteConnection,
    peer1_id: i32,
    peer2_id: i32,
    mtu_val: i32,
    endpoint_should_be_ipv6: bool
) -> Result<(), diesel::result::Error> {
    use crate::schema::wireguard_tunnels;

    let new_tunnel = crate::models::NewWireguardTunnel {
        node_id_peer1: peer1_id,
        node_id_peer2: peer2_id,
        endpoint_peer1: None,
        endpoint_peer2: None,
        mtu: mtu_val,
        endpoint_ipv6: endpoint_should_be_ipv6,
    };

    diesel::insert_into(wireguard_tunnels::table)
        .values(&new_tunnel)
        .execute(conn)?;

    Ok(())
}

pub fn get_wireguard_answers(
    conn: &mut SqliteConnection,
    node_id_val: i32
) -> Result<Vec<crate::models::WireguardTunnel>, diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;

    let results = wireguard_tunnels
        .filter(
            (node_id_peer1.eq(node_id_val))
            .or(node_id_peer2.eq(node_id_val))
        )
        .select(crate::models::WireguardTunnel::as_select())
        .load::<crate::models::WireguardTunnel>(conn)?;

    Ok(results)
}

pub fn answer_wireguard_tunnel(
    conn: &mut SqliteConnection,
    tunnel_id_val: i32,
    node_id_val: i32,
    endpoint: Option<String>,
    decline_type: Option<i16>
) -> Result<(), diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;

    let target = wireguard_tunnels.filter(id.eq(tunnel_id_val));

    if target
        .filter(node_id_peer1.eq(node_id_val))
        .first::<crate::models::WireguardTunnel>(conn)
        .is_ok()
    {
        if let Some(decline) = decline_type {
            diesel::update(target)
                .set((
                    peer1_answered.eq(decline),
                    endpoint_peer1.eq(endpoint),
                    updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)?;
        } else {
            diesel::update(target)
                .set((
                    peer1_answered.eq(ext::WireguardAnswered::Answered as i16),
                    endpoint_peer1.eq(endpoint),
                    updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)?;
        }
    } else {
        if let Some(decline) = decline_type {
            diesel::update(target)
                .set((
                    peer2_answered.eq(decline),
                    endpoint_peer2.eq(endpoint),
                    updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)?;
        } else {
            diesel::update(target)
                .set((
                    peer2_answered.eq(ext::WireguardAnswered::Answered as i16),
                    endpoint_peer2.eq(endpoint),
                    updated_at.eq(chrono::Utc::now().naive_utc()),
                ))
                .execute(conn)?;
        }
    }

    Ok(())
}
