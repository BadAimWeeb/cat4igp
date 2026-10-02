use crate::{
    ext,
    models::{Invite, Node},
};
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::env;
use uuid::Uuid;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[cfg(test)]
mod migration_tests {
    use super::*;
    use diesel::{connection::SimpleConnection, migration::MigrationSource};

    #[test]
    fn embedded_migration_lifecycle() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        assert!(migrate(&mut conn, false).is_err());
        migrate(&mut conn, true).unwrap();
        assert_eq!(conn.applied_migrations().unwrap().len(), 5);
        migrate(&mut conn, true).unwrap();
        migrate(&mut conn, false).unwrap();
        assert_eq!(conn.applied_migrations().unwrap().len(), 5);
        crate::schema::node_control_identities::table
            .count()
            .get_result::<i64>(&mut conn)
            .unwrap();

        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        let mut migrations =
            <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(
                &MIGRATIONS,
            )
            .unwrap();
        migrations.sort_by(|a, b| a.name().version().cmp(&b.name().version()));
        assert!(conn.applied_migrations().unwrap().is_empty());
        conn.run_migrations(&migrations[..3]).unwrap();
        conn.batch_execute("INSERT INTO wireguard_tunnels (id, node_id_peer1, node_id_peer2, endpoint_ipv6) VALUES (1, 10, 20, 0);
            ALTER TABLE wireguard_tunnels ADD COLUMN faketcp BOOL NOT NULL DEFAULT 0;").unwrap();
        // The UDP migration adds fec before hitting this deliberately conflicting column.
        assert!(migrate(&mut conn, true).is_err());
        assert_eq!(conn.applied_migrations().unwrap().len(), 3);
        assert!(
            conn.batch_execute("SELECT fec FROM wireguard_tunnels")
                .is_err()
        );
        conn.batch_execute("ALTER TABLE wireguard_tunnels DROP COLUMN faketcp")
            .unwrap();
        migrate(&mut conn, true).unwrap();
        use crate::schema::wireguard_tunnels::dsl::*;
        assert_eq!(
            wireguard_tunnels
                .select((id, node_id_peer1, node_id_peer2, fec, faketcp))
                .first::<(i32, i32, i32, bool, bool)>(&mut conn)
                .unwrap(),
            (1, 10, 20, false, false)
        );
        conn.revert_last_migration(MIGRATIONS).unwrap();
        conn.revert_last_migration(MIGRATIONS).unwrap();
        conn.batch_execute("SELECT override_join_mesh FROM invites")
            .unwrap();
        migrate(&mut conn, true).unwrap();
    }
}

pub fn migrate(conn: &mut SqliteConnection, apply: bool) -> Result<(), String> {
    if !apply {
        if conn
            .has_pending_migration(MIGRATIONS)
            .map_err(|e| e.to_string())?
        {
            return Err("pending database migrations; run cat4igp-server migrate".into());
        }
        return Ok(());
    }
    // ponytail: one migration writer; coordinate externally before multi-instance upgrades.
    let versions = conn
        .run_pending_migrations(MIGRATIONS)
        .map_err(|e| e.to_string())?;
    for version in &versions {
        eprintln!("Applied database migration {version}");
    }
    eprintln!(
        "Database is up to date ({} migrations applied)",
        versions.len()
    );
    Ok(())
}

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
    override_join_mesh: Option<i32>,
) -> Result<String, diesel::result::Error> {
    use crate::schema::invites;

    let invite_code = Uuid::new_v4().to_string();

    let new_invite = crate::models::NewInvite {
        code: &invite_code,
        expires_at,
        max_uses,
        override_join_mesh,
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
) -> Result<(i32, String, Option<i32>), diesel::result::Error> {
    use crate::schema::invites::dsl::*;
    use crate::schema::nodes;

    let inv = invites
        .filter(code.eq(invitation_key))
        .first::<Invite>(conn)?;

    if inv
        .expires_at
        .is_some_and(|expires| expires < chrono::Utc::now().naive_utc())
    {
        return Err(diesel::result::Error::NotFound);
    }

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

    Ok((node.id, nauthk, inv.override_join_mesh))
}

pub fn register_control_identity(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    peer_id_val: &str,
    signing_key_val: &str,
    encryption_key_val: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::node_control_identities;

    diesel::insert_into(node_control_identities::table)
        .values(&crate::models::NewNodeControlIdentity {
            node_id: node_id_val,
            peer_id: peer_id_val,
            signing_key: signing_key_val,
            encryption_key: encryption_key_val,
        })
        .execute(conn)?;
    Ok(())
}

pub fn control_identity_for_peer(
    conn: &mut SqliteConnection,
    peer_id_val: &str,
) -> Result<crate::models::NodeControlIdentity, diesel::result::Error> {
    use crate::schema::node_control_identities::dsl::*;

    node_control_identities
        .filter(peer_id.eq(peer_id_val))
        .select(crate::models::NodeControlIdentity::as_select())
        .first(conn)
}

pub fn control_identity_for_node(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<crate::models::NodeControlIdentity, diesel::result::Error> {
    use crate::schema::node_control_identities::dsl::*;

    node_control_identities
        .filter(node_id.eq(node_id_val))
        .select(crate::models::NodeControlIdentity::as_select())
        .first(conn)
}

pub fn bump_control_revision(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<i64, diesel::result::Error> {
    use crate::schema::node_control_identities::dsl::*;

    diesel::update(node_control_identities.filter(node_id.eq(node_id_val)))
        .set((
            topology_revision.eq(topology_revision + 1),
            updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(conn)?;
    node_control_identities
        .filter(node_id.eq(node_id_val))
        .select(topology_revision)
        .first(conn)
}

pub fn get_invites(
    conn: &mut SqliteConnection,
) -> Result<Vec<crate::models::Invite>, diesel::result::Error> {
    use crate::schema::invites::dsl::*;

    let results = invites
        .select(crate::models::Invite::as_select())
        .load::<crate::models::Invite>(conn)?;

    Ok(results)
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
            ((wgt_dsl::node_id_peer1
                .eq(peer1_id)
                .and(wgt_dsl::node_id_peer2.eq(peer2_id)))
            .or(wgt_dsl::node_id_peer1
                .eq(peer2_id)
                .and(wgt_dsl::node_id_peer2.eq(peer1_id))))
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

/// The transport-independent desired WireGuard state for one node.
pub fn topology_snapshot(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    revision: i64,
) -> Result<cat4igp_shared::control::TopologySnapshot, diesel::result::Error> {
    let tunnels = get_wireguard_answers(conn, node_id_val)?;
    let tunnels = tunnels
        .into_iter()
        .map(|tunnel| {
            let self_p1 = tunnel.node_id_peer1 == node_id_val;
            let peer_node_id = if self_p1 {
                tunnel.node_id_peer2
            } else {
                tunnel.node_id_peer1
            };
            let local_endpoint = if self_p1 {
                tunnel.endpoint_peer1.clone()
            } else {
                tunnel.endpoint_peer2.clone()
            };
            Ok(cat4igp_shared::control::WireguardTunnelInfo {
                tunnel_id: tunnel.id,
                peer_node_id,
                public_key: get_wireguard_pubkey(conn, peer_node_id).unwrap_or_default(),
                preferred_port: local_endpoint
                    .as_deref()
                    .and_then(|endpoint| endpoint.parse::<std::net::SocketAddr>().ok())
                    .map_or(0, |endpoint| endpoint.port()),
                remote_endpoint: if self_p1 {
                    tunnel.endpoint_peer2
                } else {
                    tunnel.endpoint_peer1
                },
                local_answered: if self_p1 {
                    tunnel.peer1_answered.into()
                } else {
                    tunnel.peer2_answered.into()
                },
                remote_response: if self_p1 {
                    tunnel.peer2_answered.into()
                } else {
                    tunnel.peer1_answered.into()
                },
                mtu: tunnel.mtu,
                endpoint_ipv6: tunnel.endpoint_ipv6,
                fec: tunnel.fec,
                faketcp: tunnel.faketcp,
                created_at: tunnel.created_at.and_utc().timestamp_millis(),
                updated_at: tunnel.updated_at.and_utc().timestamp_millis(),
            })
        })
        .collect::<Result<Vec<_>, diesel::result::Error>>()?;

    Ok(cat4igp_shared::control::TopologySnapshot {
        node_id: node_id_val,
        revision,
        tunnels,
    })
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
    let tunnel = target.first::<crate::models::WireguardTunnel>(conn)?;

    if tunnel.node_id_peer1 == node_id_val {
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
    } else if tunnel.node_id_peer2 == node_id_val {
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
    } else {
        return Err(diesel::result::Error::NotFound);
    }

    Ok(())
}

pub fn tunnel_peer_node_ids(
    conn: &mut SqliteConnection,
    tunnel_id_val: i32,
) -> Result<(i32, i32), diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;

    wireguard_tunnels
        .filter(id.eq(tunnel_id_val))
        .select((node_id_peer1, node_id_peer2))
        .first(conn)
}

pub fn tunnel_endpoint_ipv6(
    conn: &mut SqliteConnection,
    tunnel_id_val: i32,
) -> Result<bool, diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;
    wireguard_tunnels
        .filter(id.eq(tunnel_id_val))
        .select(endpoint_ipv6)
        .first(conn)
}

pub fn tunnel_node_ids_for_node(
    conn: &mut SqliteConnection,
    node_id_val: i32,
) -> Result<Vec<i32>, diesel::result::Error> {
    use crate::schema::wireguard_tunnels::dsl::*;

    let pairs = wireguard_tunnels
        .filter(
            node_id_peer1
                .eq(node_id_val)
                .or(node_id_peer2.eq(node_id_val)),
        )
        .select((node_id_peer1, node_id_peer2))
        .load::<(i32, i32)>(conn)?;
    let mut node_ids = vec![node_id_val];
    for (peer1, peer2) in pairs {
        for node_id in [peer1, peer2] {
            if !node_ids.contains(&node_id) {
                node_ids.push(node_id);
            }
        }
    }
    Ok(node_ids)
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
