use crate::{
    ext,
    models::{Invite, Node},
};
use diesel::prelude::*;
use std::env;
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

pub fn create_invite_key(
    conn: &mut SqliteConnection,
    expires_at: Option<chrono::NaiveDateTime>,
    max_uses: Option<i32>,
) -> Result<String, diesel::result::Error> {
    use crate::schema::invites;

    let invite_code = Uuid::new_v4().to_string();

    let new_invite = crate::models::NewInvite {
        code: &invite_code,
        expires_at,
        max_uses,
    };

    diesel::insert_into(invites::table)
        .values(&new_invite)
        .execute(conn)?;

    Ok(invite_code)
}

pub fn register_node(
    conn: &mut SqliteConnection,
    node_name: &str,
    invitation_key: &str,
) -> Result<(i32, String), diesel::result::Error> {
    use crate::schema::invites::dsl::*;
    use crate::schema::nodes;

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

    let node = diesel::insert_into(nodes::table)
        .values(&new_node)
        .get_result::<crate::models::Node>(conn)?;

    Ok((node.id, nauthk))
}

pub fn update_node_name(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    new_name: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    diesel::update(nodes.filter(id.eq(node_id_val)))
        .set(name.eq(new_name))
        .execute(conn)?;

    Ok(())
}

pub fn get_server_side_node_info(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<(String, chrono::NaiveDateTime), diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .filter(id.eq(node_id_val))
        .select((name, created_at))
        .first::<(String, chrono::NaiveDateTime)>(conn)
}

pub fn get_node_list(
    conn: &mut SqliteConnection,
) -> Result<Vec<crate::models::Node>, diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .select(crate::models::Node::as_select())
        .load::<crate::models::Node>(conn)
}

pub fn update_wireguard_pubkey(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    pubkey: &str,
) -> Result<(), diesel::result::Error> {
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

pub fn get_wireguard_pubkey(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<String, diesel::result::Error> {
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
    endpoint_should_be_ipv6: bool,
) -> Result<(), diesel::result::Error> {
    use crate::schema::wireguard_tunnels;

    // guard pair peer1-peer2 and ipv6 uniqueness
    use crate::schema::wireguard_tunnels::dsl as wgt_dsl;

    let existing_tunnel = wgt_dsl::wireguard_tunnels
        .filter(
            ((wgt_dsl::node_id_peer1.eq(peer1_id).and(wgt_dsl::node_id_peer2.eq(peer2_id)))
                .or(wgt_dsl::node_id_peer1.eq(peer2_id).and(wgt_dsl::node_id_peer2.eq(peer1_id))))
            .and(wgt_dsl::endpoint_ipv6.eq(endpoint_should_be_ipv6)),
        )
        .first::<crate::models::WireguardTunnel>(conn)
        .optional()?;

    if existing_tunnel.is_some() {
        return Err(diesel::result::Error::NotFound);
    }

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
    node_id_val: i32,
) -> Result<Vec<crate::models::WireguardTunnel>, diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;

    let results = wireguard_tunnels
        .filter((node_id_peer1.eq(node_id_val)).or(node_id_peer2.eq(node_id_val)))
        .select(crate::models::WireguardTunnel::as_select())
        .load::<crate::models::WireguardTunnel>(conn)?;

    Ok(results)
}

pub fn answer_wireguard_tunnel(
    conn: &mut SqliteConnection,
    tunnel_id_val: i32,
    node_id_val: i32,
    endpoint: Option<String>,
    decline_type: Option<i16>,
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

pub fn get_mesh_members(
    conn: &mut SqliteConnection,
    mesh_id_val: i32,
) -> Result<Vec<crate::models::Node>, diesel::result::Error> {
    use crate::schema::mesh_group_memberships::dsl as mm_dsl;
    use crate::schema::nodes::dsl as nodes_dsl;

    let results = mm_dsl::mesh_group_memberships
        .inner_join(nodes_dsl::nodes.on(mm_dsl::node_id.eq(nodes_dsl::id)))
        .filter(mm_dsl::mesh_group_id.eq(mesh_id_val))
        .select(crate::models::Node::as_select())
        .load::<crate::models::Node>(conn)?;

    Ok(results)
}

pub fn get_joined_meshes(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<Vec<crate::models::MeshGroup>, diesel::result::Error> {
    use crate::schema::mesh_group_memberships::dsl as mm_dsl;
    use crate::schema::mesh_groups::dsl as mg_dsl;

    let results = mm_dsl::mesh_group_memberships
        .filter(mm_dsl::node_id.eq(node_id_val))
        .inner_join(mg_dsl::mesh_groups.on(mm_dsl::mesh_group_id.eq(mg_dsl::id)))
        .select(crate::models::MeshGroup::as_select())
        .load::<crate::models::MeshGroup>(conn)?;

    Ok(results)
}

pub fn join_mesh(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    mesh_id_val: i32,
) -> Result<(), diesel::result::Error> {
    use crate::schema::mesh_group_memberships;
    use crate::schema::mesh_group_memberships::dsl as mgm_dsl;
    use crate::schema::mesh_groups::dsl as mg_dsl;

    let mesh_exists = mg_dsl::mesh_groups
        .filter(mg_dsl::id.eq(mesh_id_val))
        .first::<crate::models::MeshGroup>(conn)
        .optional()?;

    if mesh_exists.is_none() {
        return Err(diesel::result::Error::NotFound);
    }

    let new_membership = crate::models::NewMeshGroupMembership {
        mesh_group_id: mesh_id_val,
        node_id: node_id_val,
    };

    diesel::insert_into(mesh_group_memberships::table)
        .values(&new_membership)
        .on_conflict((mgm_dsl::mesh_group_id, mgm_dsl::node_id))
        .do_nothing()
        .execute(conn)?;

    // should be safe to unwrap here
    let mesh = mesh_exists.unwrap();

    if mesh.auto_wireguard {
        let peer_nodes = get_mesh_members(conn, mesh_id_val)?;

        for peer in peer_nodes {
            if peer.id != node_id_val {
                // create wireguard tunnel for both ipv4 and ipv6 channel
                // we do not care about errors here, as the tunnel may already exist
                let _ = create_wireguard_tunnel(
                    conn,
                    node_id_val,
                    peer.id,
                    mesh.auto_wireguard_mtu,
                    false,
                );

                let _ = create_wireguard_tunnel(
                    conn,
                    node_id_val,
                    peer.id,
                    mesh.auto_wireguard_mtu,
                    true,
                );
            }
        }
    }

    Ok(())
}

pub fn leave_mesh(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    mesh_id_val: i32,
) -> Result<(), diesel::result::Error> {
    use crate::schema::mesh_group_memberships::dsl::*;

    diesel::delete(
        mesh_group_memberships
            .filter(node_id.eq(node_id_val))
            .filter(mesh_group_id.eq(mesh_id_val)),
    )
    .execute(conn)?;

    Ok(())
}

pub fn create_mesh_group(
    conn: &mut SqliteConnection,
    name_val: &str,
    auto_wg: bool,
    auto_wg_mtu: i32,
) -> Result<i32, diesel::result::Error> {
    use crate::schema::mesh_groups;

    let new_mesh = crate::models::NewMeshGroup {
        name: name_val,
        auto_wireguard: auto_wg,
        auto_wireguard_mtu: auto_wg_mtu,
    };

    let result = diesel::insert_into(mesh_groups::table)
        .values(&new_mesh)
        .get_result::<crate::models::MeshGroup>(conn)?;

    let mesh_id = result.id;

    Ok(mesh_id)
}

pub fn delete_mesh_group(
    conn: &mut SqliteConnection,
    mesh_id_val: i32,
) -> Result<(), diesel::result::Error> {
    use crate::schema::mesh_group_memberships::dsl as mgm_dsl;
    use crate::schema::mesh_groups::dsl::*;

    diesel::delete(mgm_dsl::mesh_group_memberships.filter(mgm_dsl::mesh_group_id.eq(mesh_id_val)))
        .execute(conn)?;

    diesel::delete(mesh_groups.filter(id.eq(mesh_id_val))).execute(conn)?;

    Ok(())
}

pub fn get_setting(
    conn: &mut SqliteConnection,
    key_val: &str,
) -> Result<String, diesel::result::Error> {
    use crate::schema::settings::dsl::*;

    let result = settings
        .filter(key.eq(key_val))
        .select(value)
        .first::<String>(conn)?;

    Ok(result)
}

pub fn set_setting(
    conn: &mut SqliteConnection,
    key_val: &str,
    value_val: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::settings;
    use crate::schema::settings::dsl::*;

    let new_setting = crate::models::NewSetting {
        key: key_val,
        value: value_val,
    };

    diesel::insert_into(settings::table)
        .values(&new_setting)
        .on_conflict(key)
        .do_update()
        .set((
            value.eq(value_val),
            updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(conn)?;

    Ok(())
}
