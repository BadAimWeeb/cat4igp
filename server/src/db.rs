use crate::{
    ext,
    models::{Invite, Node},
};
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use std::env;
use uuid::Uuid;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub(crate) fn verify_schema(conn: &mut SqliteConnection) -> Result<(), String> {
    use diesel::migration::MigrationSource;
    let expected =
        <EmbeddedMigrations as MigrationSource<diesel::sqlite::Sqlite>>::migrations(&MIGRATIONS)
            .map_err(|_| "cannot read embedded schema")?
            .into_iter()
            .map(|m| m.name().version().as_owned())
            .collect::<std::collections::BTreeSet<_>>();
    let actual = conn
        .applied_migrations()
        .map_err(|_| "cannot read backup schema")?
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err("backup schema differs from this binary; coordinated upgrade required".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "db_test.rs"]
mod migration_tests;

pub fn migrate(conn: &mut SqliteConnection, apply: bool) -> Result<(), String> {
    if !apply {
        if conn
            .has_pending_migration(MIGRATIONS)
            .map_err(|e| e.to_string())?
        {
            return Err("pending database migrations; run cat4igp-server migrate".into());
        }
        return verify_schema(conn);
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
    let mut conn = SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url));
    configure_connection(&mut conn).expect("cannot configure SQLite durability");
    conn
}

pub fn configure_connection(conn: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
    use diesel::connection::SimpleConnection;
    conn.batch_execute(
        "PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
    )
}

pub fn authenticate(conn: &mut SqliteConnection, key: &str) -> Result<Node, diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .filter(auth_key.eq(key))
        .select(Node::as_select())
        .first(conn)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InviteCommand {
    pub request_id: String,
    pub id: i32,
    pub code: String,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub max_uses: Option<i32>,
    pub join_mesh: Option<i32>,
    pub applied_at: chrono::NaiveDateTime,
}

pub fn apply_invite(
    conn: &mut SqliteConnection,
    command: &InviteCommand,
) -> Result<Result<String, String>, diesel::result::Error> {
    use diesel::sql_types::Text;
    #[derive(QueryableByName)]
    struct Previous {
        #[diesel(sql_type = Text)]
        fingerprint: String,
        #[diesel(sql_type = Text)]
        result: String,
    }
    if command.request_id.is_empty() || command.request_id.len() > 128 {
        return Ok(Err("request ID must contain 1..128 bytes".into()));
    }
    if command.id <= 0 || command.code.is_empty() || command.code.len() > 128 {
        return Ok(Err("invalid selected invite ID/code".into()));
    }
    // One authenticated operator principal today; scope by operator ID when multi-operator auth exists.
    let fingerprint =
        serde_json::to_string(&(command.expires_at, command.max_uses, command.join_mesh)).unwrap();
    // The Raft adapter supplies the outer immediate transaction; nested calls use savepoints.
    conn.transaction(|conn| {
        if let Some(previous) = diesel::sql_query("SELECT fingerprint, result FROM operator_invite_results WHERE request_id = ?")
            .bind::<Text, _>(&command.request_id).get_result::<Previous>(conn).optional()? {
            return Ok(if previous.fingerprint == fingerprint {
                serde_json::from_str(&previous.result).map_err(|e| diesel::result::Error::DeserializationError(Box::new(e)))?
            } else { Err("request ID reused with different invite settings".into()) });
        }
        let result = if command.max_uses.is_some_and(|n| n <= 0)
            || command.expires_at.is_some_and(|t| t <= command.applied_at) {
            Err("invite capacity must be positive and expiry must be in the future".into())
        } else if let Some(mesh) = command.join_mesh {
            use crate::schema::mesh_groups::dsl::*;
            if !diesel::select(diesel::dsl::exists(mesh_groups.filter(id.eq(mesh)))).get_result::<bool>(conn)? {
                Err("unknown invite mesh".into())
            } else { Ok(command.code.clone()) }
        } else { Ok(command.code.clone()) };
        if result.is_ok() {
            use crate::schema::invites::dsl::*;
            diesel::insert_into(invites).values((id.eq(command.id), code.eq(&command.code),
                created_at.eq(command.applied_at), expires_at.eq(command.expires_at), used_count.eq(0),
                max_uses.eq(command.max_uses), override_join_mesh.eq(command.join_mesh))).execute(conn)?;
        }
        // ponytail: lifetime retries retain one row/request; prune only with an explicit retry-window contract.
        diesel::sql_query("INSERT INTO operator_invite_results (request_id, fingerprint, result) VALUES (?, ?, ?)")
            .bind::<Text, _>(&command.request_id).bind::<Text, _>(&fingerprint)
            .bind::<Text, _>(serde_json::to_string(&result).unwrap()).execute(conn)?;
        Ok(result)
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InitializeCommand {
    pub signing_private_key: String,
    pub encryption_private_key: String,
    pub network_id: String,
    pub applied_at: chrono::NaiveDateTime,
}

pub fn apply_initialization(
    conn: &mut SqliteConnection,
    command: &InitializeCommand,
) -> Result<(), diesel::result::Error> {
    use crate::schema::settings::dsl::*;
    let valid = command.signing_private_key.len() <= 1024
        && crate::hex_decode(&command.signing_private_key)
            .ok()
            .is_some_and(|bytes| libp2p::identity::Keypair::from_protobuf_encoding(&bytes).is_ok())
        && command.encryption_private_key.len() == 64
        && crate::hex_decode(&command.encryption_private_key).is_ok()
        && !command.network_id.is_empty()
        && command.network_id.len() <= 128;
    if !valid {
        return Err(diesel::result::Error::RollbackTransaction);
    }
    // Import preserves existing identities, including partially initialized legacy databases.
    conn.transaction(|conn| {
        for (name, value_) in [
            ("control_private_key", &command.signing_private_key),
            (
                "control_encryption_private_key",
                &command.encryption_private_key,
            ),
            ("control_network_id", &command.network_id),
        ] {
            diesel::insert_into(settings)
                .values((
                    key.eq(name),
                    value.eq(value_),
                    created_at.eq(command.applied_at),
                    updated_at.eq(command.applied_at),
                ))
                .on_conflict(key)
                .do_nothing()
                .execute(conn)?;
        }
        Ok(())
    })
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
    bump_control_revision_at(conn, node_id_val, chrono::Utc::now().naive_utc())
}

fn bump_control_revision_at(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    applied_at: chrono::NaiveDateTime,
) -> Result<i64, diesel::result::Error> {
    use crate::schema::node_control_identities::dsl::*;

    diesel::update(node_control_identities.filter(node_id.eq(node_id_val)))
        .set((
            topology_revision.eq(topology_revision + 1),
            updated_at.eq(applied_at),
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
    create_wireguard_tunnel_at(
        conn,
        peer1_id,
        peer2_id,
        mtu_val,
        endpoint_should_be_ipv6,
        chrono::Utc::now().naive_utc(),
    )
}

fn create_wireguard_tunnel_at(
    conn: &mut SqliteConnection,
    peer1_id: i32,
    peer2_id: i32,
    mtu_val: i32,
    endpoint_should_be_ipv6: bool,
    applied_at: chrono::NaiveDateTime,
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
        return Ok(());
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
        .values((
            &new_tunnel,
            wgt_dsl::created_at.eq(applied_at),
            wgt_dsl::updated_at.eq(applied_at),
        ))
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
        .order(id.asc())
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
                public_key: get_wireguard_pubkey(conn, peer_node_id)?,
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

fn answer_wireguard_tunnel(
    conn: &mut SqliteConnection,
    tunnel_id_val: i32,
    node_id_val: i32,
    endpoint: Option<String>,
    decline_type: Option<i16>,
    applied_at: chrono::NaiveDateTime,
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
                    updated_at.eq(applied_at),
                ))
                .execute(conn)?;
        } else {
            diesel::update(target)
                .set((
                    peer1_answered.eq(ext::WireguardAnswered::Answered as i16),
                    endpoint_peer1.eq(endpoint),
                    updated_at.eq(applied_at),
                ))
                .execute(conn)?;
        }
    } else if tunnel.node_id_peer2 == node_id_val {
        if let Some(decline) = decline_type {
            diesel::update(target)
                .set((
                    peer2_answered.eq(decline),
                    endpoint_peer2.eq(endpoint),
                    updated_at.eq(applied_at),
                ))
                .execute(conn)?;
        } else {
            diesel::update(target)
                .set((
                    peer2_answered.eq(ext::WireguardAnswered::Answered as i16),
                    endpoint_peer2.eq(endpoint),
                    updated_at.eq(applied_at),
                ))
                .execute(conn)?;
        }
    } else {
        return Err(diesel::result::Error::NotFound);
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentCommand {
    pub request: cat4igp_shared::control::EnrollmentRequest,
    pub node_id: i32,
    pub auth_key: String,
    pub applied_at: chrono::NaiveDateTime,
    pub response: cat4igp_shared::control::EnrollmentResponse,
    pub allocation: EnrollmentAllocation,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentAllocation {
    pub membership: Option<(i32, i32)>, // (explicit row ID, mesh ID)
    pub tunnels: Vec<(i32, i32, i32, bool)>, // (ID, peer, MTU, IPv6)
}

/// Leader/singleton preparation only: never called by ordered application.
pub fn prepare_enrollment_allocation(
    conn: &mut SqliteConnection,
    invitation: &str,
) -> Result<EnrollmentAllocation, diesel::result::Error> {
    use crate::schema::{invites, mesh_group_memberships as mm, wireguard_tunnels as wt};
    let mesh = invites::table
        .filter(invites::code.eq(invitation))
        .select(invites::override_join_mesh)
        .first::<Option<i32>>(conn)
        .optional()?
        .flatten();
    let mesh = match mesh.filter(|id| *id != 0) {
        Some(id) => crate::schema::mesh_groups::table
            .find(id)
            .first::<crate::models::MeshGroup>(conn)
            .optional()?,
        None => None,
    };
    let mut allocation = EnrollmentAllocation {
        membership: None,
        tunnels: vec![],
    };
    if let Some(mesh) = mesh {
        let membership = mm::table
            .select(diesel::dsl::max(mm::id))
            .first::<Option<i32>>(conn)?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(diesel::result::Error::RollbackTransaction)?;
        allocation.membership = Some((membership, mesh.id));
        if mesh.auto_wireguard {
            let mut id = wt::table
                .select(diesel::dsl::max(wt::id))
                .first::<Option<i32>>(conn)?
                .unwrap_or(0);
            let mut peers = get_mesh_members(conn, mesh.id)?;
            peers.sort_by_key(|peer| peer.id);
            for peer in peers {
                for ipv6 in [false, true] {
                    id = id
                        .checked_add(1)
                        .ok_or(diesel::result::Error::RollbackTransaction)?;
                    allocation
                        .tunnels
                        .push((id, peer.id, mesh.auto_wireguard_mtu, ipv6));
                }
            }
        }
    }
    Ok(allocation)
}

#[derive(diesel::QueryableByName)]
struct EnrollmentResult {
    #[diesel(sql_type = diesel::sql_types::Text)]
    peer_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    request_id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    fingerprint: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    result: String,
}

fn json_error(error: serde_json::Error) -> diesel::result::Error {
    diesel::result::Error::DeserializationError(Box::new(error))
}

pub fn apply_enrollment(
    conn: &mut SqliteConnection,
    command: &EnrollmentCommand,
) -> Result<
    (
        cat4igp_shared::control::ControlResponse,
        Vec<cat4igp_shared::control::TopologySnapshot>,
    ),
    diesel::result::Error,
> {
    use crate::schema::{invites, node_control_identities, nodes, wireguard_static_key};
    use cat4igp_shared::control::ControlResponse;
    use diesel::sql_types::Text;
    let request = &command.request;
    if request.request_id.len() > 256
        || request.client_peer_id.is_empty()
        || request.client_peer_id.len() > 256
        || request.node_name.is_empty()
        || request.node_name.len() > 256
        || request.invitation_code.is_empty()
        || request.invitation_code.len() > 256
        || request.client_signing_key.is_empty()
        || request.client_signing_key.len() > 1024
        || request.client_encryption_key.is_empty()
        || request.client_encryption_key.len() > 64
        || request.wireguard_public_key.is_empty()
        || request.wireguard_public_key.len() > 256
    {
        return Ok((
            ControlResponse::Rejected("invalid enrollment request".into()),
            vec![],
        ));
    }
    // Store the exact bounded request, not a lossy hash; never log this secret-bearing row.
    let fingerprint = serde_json::to_string(request).map_err(json_error)?;
    conn.transaction(|conn| {
        // ponytail: lifetime identity-scoped dedup, one enrollment per peer; add retention only with identity recovery.
        if let Some(previous) = diesel::sql_query("SELECT peer_id, request_id, fingerprint, result FROM control_enrollment_results WHERE peer_id = ? OR (request_id = ? AND request_id <> '') ORDER BY peer_id LIMIT 1")
            .bind::<Text, _>(&request.client_peer_id)
            .bind::<Text, _>(&request.request_id)
            .get_result::<EnrollmentResult>(conn).optional()? {
            return Ok((if previous.peer_id == request.client_peer_id && previous.request_id == request.request_id && previous.fingerprint == fingerprint {
                serde_json::from_str(&previous.result).map_err(json_error)?
            } else {
                ControlResponse::Rejected("enrollment identity or request ID reused with different request".into())
            }, vec![]));
        }
        let inv = invites::table.filter(invites::code.eq(&request.invitation_code)).select(Invite::as_select()).first::<Invite>(conn).optional()?;
        let mesh = inv.as_ref().and_then(|inv| inv.override_join_mesh).filter(|id| *id != 0);
        let mesh_valid = match mesh {
            Some(mesh_id) => crate::schema::mesh_groups::table.find(mesh_id).first::<crate::models::MeshGroup>(conn).optional()?.is_some(),
            None => true,
        };
        let allocation_valid = if mesh_valid {
            let expected = match mesh {
                Some(id) => {
                    let group = crate::schema::mesh_groups::table.find(id).first::<crate::models::MeshGroup>(conn)?;
                    let mut peers = get_mesh_members(conn, id)?;
                    peers.sort_by_key(|peer| peer.id);
                    if group.auto_wireguard {
                        peers.into_iter().flat_map(|peer| [(peer.id, group.auto_wireguard_mtu, false), (peer.id, group.auto_wireguard_mtu, true)]).collect::<Vec<_>>()
                    } else { vec![] }
                }
                None => vec![],
            };
            let mut ids = std::collections::BTreeSet::new();
            command.node_id > 0 && !command.auth_key.is_empty()
                && command.allocation.membership.map(|(id, mesh)| (id > 0, mesh)) == mesh.map(|mesh| (true, mesh))
                && command.allocation.tunnels.iter().map(|&(_, peer, mtu, ipv6)| (peer, mtu, ipv6)).collect::<Vec<_>>() == expected
                && command.allocation.tunnels.iter().all(|&(id, _, _, _)| id > 0 && ids.insert(id))
        } else { false };
        let mut allocation_available = nodes::table.find(command.node_id)
            .select(nodes::id).first::<i32>(conn).optional()?.is_none();
        if let Some((id, _)) = command.allocation.membership {
            allocation_available &= crate::schema::mesh_group_memberships::table.find(id)
                .select(crate::schema::mesh_group_memberships::id).first::<i32>(conn).optional()?.is_none();
        }
        for &(id, _, _, _) in &command.allocation.tunnels {
            allocation_available &= crate::schema::wireguard_tunnels::table.find(id)
                .select(crate::schema::wireguard_tunnels::id).first::<i32>(conn).optional()?.is_none();
        }
        let mut snapshots = vec![];
        let response = if control_identity_for_peer(conn, &request.client_peer_id).optional()?.is_some() {
            ControlResponse::Rejected("control identity already enrolled".into())
        } else if let Some(inv) = inv.filter(|inv| {
            allocation_valid && allocation_available && inv.expires_at.is_none_or(|expiry| expiry > command.applied_at)
                && inv.max_uses.is_none_or(|max| inv.used_count < max)
        }) {
            diesel::update(invites::table.find(inv.id)).set(invites::used_count.eq(invites::used_count + 1)).execute(conn)?;
            diesel::insert_into(nodes::table).values((nodes::id.eq(command.node_id), nodes::name.eq(&request.node_name), nodes::auth_key.eq(&command.auth_key), nodes::created_at.eq(command.applied_at))).execute(conn)?;
            diesel::insert_into(node_control_identities::table).values((node_control_identities::node_id.eq(command.node_id), node_control_identities::peer_id.eq(&request.client_peer_id), node_control_identities::signing_key.eq(&request.client_signing_key), node_control_identities::encryption_key.eq(&request.client_encryption_key), node_control_identities::created_at.eq(command.applied_at), node_control_identities::updated_at.eq(command.applied_at))).execute(conn)?;
            diesel::insert_into(wireguard_static_key::table).values((wireguard_static_key::node_id.eq(command.node_id), wireguard_static_key::public_key.eq(&request.wireguard_public_key), wireguard_static_key::created_at.eq(command.applied_at))).execute(conn)?;
            if let Some((id, mesh_id)) = command.allocation.membership {
                diesel::insert_into(crate::schema::mesh_group_memberships::table).values((
                    crate::schema::mesh_group_memberships::id.eq(id),
                    crate::schema::mesh_group_memberships::mesh_group_id.eq(mesh_id),
                    crate::schema::mesh_group_memberships::node_id.eq(command.node_id),
                    crate::schema::mesh_group_memberships::created_at.eq(command.applied_at),
                )).execute(conn)?;
            }
            for &(id, peer, mtu, ipv6) in &command.allocation.tunnels {
                use crate::schema::wireguard_tunnels::dsl as wt;
                diesel::insert_into(wt::wireguard_tunnels).values((wt::id.eq(id),
                    wt::node_id_peer1.eq(command.node_id), wt::node_id_peer2.eq(peer),
                    wt::mtu.eq(mtu), wt::endpoint_ipv6.eq(ipv6),
                    wt::created_at.eq(command.applied_at), wt::updated_at.eq(command.applied_at))).execute(conn)?;
            }
            for node_id in tunnel_node_ids_for_node(conn, command.node_id)? {
                let revision = bump_control_revision_at(conn, node_id, command.applied_at)?;
                snapshots.push(topology_snapshot(conn, node_id, revision)?);
            }
            let mut result = command.response.clone();
            result.node_id = command.node_id;
            result.topology_revision = control_identity_for_node(conn, command.node_id)?.topology_revision;
            ControlResponse::Enrolled(result)
        } else {
            ControlResponse::Rejected("enrollment rejected".into())
        };
        diesel::sql_query("INSERT INTO control_enrollment_results (peer_id, request_id, fingerprint, result) VALUES (?, ?, ?, ?)")
            .bind::<Text, _>(&request.client_peer_id).bind::<Text, _>(&request.request_id)
            .bind::<Text, _>(&fingerprint).bind::<Text, _>(serde_json::to_string(&response).map_err(json_error)?)
            .execute(conn)?;
        Ok((response, snapshots))
    })
}

/// Chosen at ingress; ordered application performs no clock or randomness reads.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnswerCommand {
    pub node_id: i32,
    pub request_id: String,
    pub answer: cat4igp_shared::control::TunnelAnswer,
    pub applied_at: chrono::NaiveDateTime,
}

#[derive(diesel::QueryableByName)]
struct AnswerResult {
    #[diesel(sql_type = diesel::sql_types::Text)]
    fingerprint: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    result: String,
}

pub fn apply_answer(
    conn: &mut SqliteConnection,
    command: &AnswerCommand,
) -> Result<String, diesel::result::Error> {
    use diesel::sql_types::{Integer, Text, Timestamp};
    if command.request_id.is_empty() || command.request_id.len() > 256 {
        return Ok("invalid request ID".into());
    }
    // Exact canonical semantic content avoids hash collisions and excludes retry-local time.
    let fingerprint = serde_json::to_string(&command.answer)
        .map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
    conn.transaction(|conn| {
        diesel::sql_query("DELETE FROM control_answer_results WHERE expires_at <= ?")
            .bind::<Timestamp, _>(command.applied_at)
            .execute(conn)?;
        if let Some(previous) = diesel::sql_query("SELECT fingerprint, result FROM control_answer_results WHERE node_id = ? AND request_id = ?")
            .bind::<Integer, _>(command.node_id)
            .bind::<Text, _>(&command.request_id)
            .get_result::<AnswerResult>(conn).optional()?
        {
            return Ok(if previous.fingerprint == fingerprint {
                previous.result
            } else {
                "request ID reused with different answer".into()
            });
        }
        let peers = tunnel_peer_node_ids(conn, command.answer.tunnel_id).optional()?;
        let result = match peers {
            Some((peer1, peer2)) if [peer1, peer2].contains(&command.node_id) => {
                let invalid_endpoint = command.answer.endpoint.as_deref().is_some_and(|value| {
                    match value.parse::<std::net::SocketAddr>() {
                        Ok(endpoint) => endpoint.ip().is_unspecified() || endpoint.ip().is_multicast(),
                        Err(_) => true,
                    }
                });
                let wrong_family = match command.answer.endpoint.as_deref().and_then(|v| v.parse::<std::net::SocketAddr>().ok()) {
                    Some(endpoint) => tunnel_endpoint_ipv6(conn, command.answer.tunnel_id)? != endpoint.is_ipv6(),
                    None => false,
                };
                if command.answer.decline_type.is_some_and(|value| !matches!(value, 2 | 3)) {
                    "invalid decline type".to_string()
                } else if invalid_endpoint || wrong_family {
                    "invalid tunnel endpoint".to_string()
                } else {
                    answer_wireguard_tunnel(conn, command.answer.tunnel_id, command.node_id,
                        command.answer.endpoint.clone(), command.answer.decline_type, command.applied_at)?;
                    bump_control_revision_at(conn, peer1, command.applied_at)?;
                    if peer2 != peer1 {
                        bump_control_revision_at(conn, peer2, command.applied_at)?;
                    }
                    "accepted".to_string()
                }
            }
            _ => "unknown tunnel or unauthorized peer".to_string(),
        };
        // ponytail: 24-hour durable answer retries; extend with replicated client retry contracts before HA rollout.
        let expires_at = command.applied_at.checked_add_signed(chrono::Duration::hours(24))
            .ok_or(diesel::result::Error::RollbackTransaction)?;
        diesel::sql_query("INSERT INTO control_answer_results (node_id, request_id, fingerprint, result, expires_at) VALUES (?, ?, ?, ?, ?)")
            .bind::<Integer, _>(command.node_id)
            .bind::<Text, _>(&command.request_id)
            .bind::<Text, _>(&fingerprint)
            .bind::<Text, _>(&result)
            .bind::<Timestamp, _>(expires_at)
            .execute(conn)?;
        Ok(result)
    })
}

pub(crate) fn accepted_answer_recipients(
    conn: &mut SqliteConnection,
    node: i32,
    request: &str,
    answer: &cat4igp_shared::control::TunnelAnswer,
) -> Result<Vec<i32>, diesel::result::Error> {
    use diesel::sql_types::{Integer, Text};
    let previous = diesel::sql_query("SELECT fingerprint, result FROM control_answer_results WHERE node_id = ? AND request_id = ?")
        .bind::<Integer, _>(node)
        .bind::<Text, _>(request)
        .get_result::<AnswerResult>(conn).optional()?;
    let fingerprint = serde_json::to_string(answer)
        .map_err(|e| diesel::result::Error::SerializationError(Box::new(e)))?;
    if !previous.is_some_and(|p| p.result == "accepted" && p.fingerprint == fingerprint) {
        return Ok(Vec::new());
    }
    let (a, b) = tunnel_peer_node_ids(conn, answer.tunnel_id)?;
    if ![a, b].contains(&node) {
        return Ok(Vec::new());
    }
    Ok(if a == b { vec![a] } else { vec![a, b] })
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
    node_ids.sort_unstable();
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
    join_mesh_at(
        conn,
        node_id_val,
        mesh_id_val,
        chrono::Utc::now().naive_utc(),
    )
}

fn join_mesh_at(
    conn: &mut SqliteConnection,
    node_id_val: i32,
    mesh_id_val: i32,
    applied_at: chrono::NaiveDateTime,
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
        .values((&new_membership, mgm_dsl::created_at.eq(applied_at)))
        .on_conflict((mgm_dsl::mesh_group_id, mgm_dsl::node_id))
        .do_nothing()
        .execute(conn)?;

    // should be safe to unwrap here
    let mesh = mesh_exists.unwrap();

    if mesh.auto_wireguard {
        let mut peer_nodes = get_mesh_members(conn, mesh_id_val)?;
        peer_nodes.sort_by_key(|peer| peer.id);

        for peer in peer_nodes {
            if peer.id != node_id_val {
                // create wireguard tunnel for both ipv4 and ipv6 channel
                create_wireguard_tunnel_at(
                    conn,
                    node_id_val,
                    peer.id,
                    mesh.auto_wireguard_mtu,
                    false,
                    applied_at,
                )?;

                create_wireguard_tunnel_at(
                    conn,
                    node_id_val,
                    peer.id,
                    mesh.auto_wireguard_mtu,
                    true,
                    applied_at,
                )?;
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
        .values((
            &new_mesh,
            mesh_groups::created_at.eq(chrono::Utc::now().naive_utc()),
        ))
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
        .values((
            &new_setting,
            created_at.eq(chrono::Utc::now().naive_utc()),
            updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .on_conflict(key)
        .do_update()
        .set((
            value.eq(value_val),
            updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(conn)?;

    Ok(())
}
