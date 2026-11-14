use std::{collections::BTreeMap, sync::Arc};

use crate::schema::{
    application_kv,
    invites, mesh_group_memberships, mesh_groups, node_control_identities, nodes,
    tunnel_intents, wireguard_tunnels,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use diesel::{
    dsl::{exists, not},
    prelude::*,
    sql_types::{Integer, Nullable, Text},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

type Error = Box<dyn std::error::Error + Send + Sync>;
const COOKIE: &str = "__Host-cat4igp";
const LIFE: u64 = 900;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Operation {
    Account,
    SessionRevoked(String),
    RevokeSession(String),
    Inventory,
    Status,
    Mutate(Mutation),
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Mutation {
    pub request_id: String,
    pub action: Action,
    pub applied_at: chrono::NaiveDateTime,
}

impl std::fmt::Debug for Mutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdministratorMutation([redacted])")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Bootstrap {
        username: String,
        password_hash: String,
    },
    RenameNode {
        id: i32,
        name: String,
    },
    RenameMesh {
        id: i32,
        name: String,
    },
    InvalidateInvite {
        id: i32,
    },
    CreateMesh {
        name: String,
        auto_wireguard: bool,
        mtu: i32,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        fec: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        faketcp: bool,
    },
    SetMeshFec {
        id: i32,
        fec: bool,
    },
    SetMeshFaketcp {
        id: i32,
        faketcp: bool,
    },
    SetMeshMtu {
        id: i32,
        mtu: i32,
    },
    AddMembership {
        mesh_id: i32,
        node_id: i32,
    },
    RemoveMembership {
        mesh_id: i32,
        node_id: i32,
    },
    DeleteMesh {
        id: i32,
    },
    DeleteNode {
        id: i32,
    },
    RemoveTunnelIntent {
        tunnel_id: i32,
        kind: IntentKind,
    },
    CreateL2tpTunnel {
        node_id_peer1: i32, node_id_peer2: i32,
        endpoint_peer1: String, endpoint_peer2: String,
        udp_port_peer1: u16, udp_port_peer2: u16,
        session_id_peer1: u32, session_id_peer2: u32,
        cookie_peer1: String, cookie_peer2: String,
        security_mode: String, wireguard_tunnel_id: Option<i32>, mtu: i32,
    },
    DeleteL2tpTunnel { id: i32 },
    CreateL2tpV2Tunnel {
        node_id_peer1: i32, node_id_peer2: i32,
        endpoint_peer1: String, endpoint_peer2: String,
        udp_port_peer1: u16, udp_port_peer2: u16,
        address_peer1: String, address_peer2: String,
        secret: String, mtu: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wireguard_tunnel_id: Option<i32>,
    },
    DeleteL2tpV2Tunnel { id: i32 },
}


#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IntentKind {
    Manual,
    Legacy,
}

// Preserve SQLite timestamp text verbatim instead of reformatting it through Chrono.
#[derive(diesel::deserialize::FromSqlRow, Serialize)]
#[serde(transparent)]
struct TimestampText(String);

impl diesel::deserialize::FromSql<diesel::sql_types::Timestamp, diesel::sqlite::Sqlite>
    for TimestampText
{
    fn from_sql(
        value: diesel::sqlite::SqliteValue<'_, '_, '_>,
    ) -> diesel::deserialize::Result<Self> {
        <String as diesel::deserialize::FromSql<Text, diesel::sqlite::Sqlite>>::from_sql(value)
            .map(Self)
    }
}

// SQLite JSON extraction is not exposed by Diesel's built-in SQLite functions.
mod json_functions {
    use super::*;
    diesel::define_sql_function! {
        #[sql_name = "json_extract"]
        fn text(value: Text, path: Text) -> Nullable<Text>;
    }
    diesel::define_sql_function! {
        #[sql_name = "json_extract"]
        fn integer(value: Text, path: Text) -> Nullable<Integer>;
    }
}

fn invalidate_invites(
    conn: &mut diesel::SqliteConnection,
    predicate: impl BoxableExpression<
        invites::table,
        diesel::sqlite::Sqlite,
        SqlType = Nullable<diesel::sql_types::Bool>,
    > + Clone
    + 'static,
    reason: &str,
) -> Result<(), Error> {
    let selection: Box<
        dyn BoxableExpression<
                invites::table,
                diesel::sqlite::Sqlite,
                SqlType = Nullable<diesel::sql_types::Bool>,
            >,
    > = Box::new(predicate.clone());
    let deletion: Box<
        dyn BoxableExpression<
                invites::table,
                diesel::sqlite::Sqlite,
                SqlType = Nullable<diesel::sql_types::Bool>,
            >,
    > = Box::new(predicate);
    let codes = invites::table
        .select(invites::code.nullable())
        .into_boxed()
        .filter(selection).load::<Option<String>>(conn)?;
    let result = serde_json::to_string(&Result::<String, String>::Err(reason.into()))?;
    for code in codes.into_iter().flatten() {
        diesel::sql_query("UPDATE application_kv SET value=json_set(value,'$.result',?) WHERE substr(key,1,23)='operator_invite_result/' AND json_extract(json_extract(value,'$.result'),'$.Ok')=?")
            .bind::<Text, _>(&result).bind::<Text, _>(code).execute(conn)?;
    }
    diesel::delete(invites::table.filter(deletion)).execute(conn)?;
    Ok(())
}

fn tunnel_ports_in_use(conn: &mut diesel::SqliteConnection, peers: [(i32, u16); 2]) -> Result<bool, Error> {
    let used = |node1: i32, port1: i32, node2: i32, port2: i32| {
        peers.iter().any(|&(node, port)| (node == node1 && i32::from(port) == port1) || (node == node2 && i32::from(port) == port2))
    };
    Ok(crate::db::all_l2tp_rows(conn)?.iter().any(|r| used(r.node_id_peer1, r.udp_port_peer1, r.node_id_peer2, r.udp_port_peer2))
        || crate::db::l2tp_v2_rows(conn)?.iter().any(|r| used(r.node_id_peer1, r.udp_port_peer1, r.node_id_peer2, r.udp_port_peer2)))
}


fn topology_mutation(
    conn: &mut diesel::SqliteConnection,
    command: &Mutation,
) -> Result<Result<Option<String>, String>, Error> {
    use diesel::prelude::*;
    let missing = match &command.action {
        Action::AddMembership { mesh_id, node_id }
        | Action::RemoveMembership { mesh_id, node_id } => (!(*mesh_id > 0
            && diesel::select(exists(mesh_groups::table.find(mesh_id)))
                .get_result::<bool>(conn)?)
            || !(*node_id > 0
                && diesel::select(exists(nodes::table.find(node_id))).get_result::<bool>(conn)?))
        .then_some("node or mesh not found"),
        Action::DeleteMesh { id } | Action::SetMeshFec { id, .. } | Action::SetMeshFaketcp { id, .. } | Action::SetMeshMtu { id, .. } => (!(*id > 0
            && diesel::select(exists(mesh_groups::table.find(id))).get_result::<bool>(conn)?))
        .then_some("mesh not found"),
        Action::DeleteNode { id } => (!(*id > 0
            && diesel::select(exists(nodes::table.find(id))).get_result::<bool>(conn)?))
        .then_some("node not found"),
        Action::RemoveTunnelIntent { tunnel_id, .. } => (!(*tunnel_id > 0
            && diesel::select(exists(wireguard_tunnels::table.find(tunnel_id)))
                .get_result::<bool>(conn)?))
        .then_some("tunnel not found"),
        Action::CreateL2tpTunnel { node_id_peer1, node_id_peer2, .. } | Action::CreateL2tpV2Tunnel { node_id_peer1, node_id_peer2, .. } => (node_id_peer1 == node_id_peer2 || *node_id_peer1 <= 0 || *node_id_peer2 <= 0 || !diesel::select(exists(nodes::table.find(node_id_peer1))).get_result::<bool>(conn)? || !diesel::select(exists(nodes::table.find(node_id_peer2))).get_result::<bool>(conn)?).then_some("node not found or identical"),
        Action::DeleteL2tpTunnel { id } => (!crate::db::l2tp_rows(conn)?.iter().any(|row| row.id == *id)).then_some("L2TP tunnel not found"),
        Action::DeleteL2tpV2Tunnel { id } => (!crate::db::l2tp_v2_rows(conn)?.iter().any(|row| row.id == *id)).then_some("L2TPv2 tunnel not found"),
        _ => return Err("not a topology mutation".into()),
    };
    if let Some(message) = missing {
        return Ok(Err(message.into()));
    }
    if let Action::CreateL2tpV2Tunnel { node_id_peer1, node_id_peer2, endpoint_peer1, endpoint_peer2, udp_port_peer1, udp_port_peer2, address_peer1, address_peer2, secret, mtu, wireguard_tunnel_id } = &command.action {
        let ipv4 = |s: &str| s.parse::<std::net::Ipv4Addr>().ok().filter(|v| !v.is_unspecified() && !v.is_multicast() && !v.is_broadcast() && !v.is_loopback() && !v.is_link_local() && v.octets()[0] != 0 && v.octets()[0] < 240);
        let (a, b) = (ipv4(endpoint_peer1), ipv4(endpoint_peer2));
        let (p, q) = (ipv4(address_peer1), ipv4(address_peer2));
        if a.is_none() || b.is_none() || a == b || p.is_none() || q.is_none() || p == q || *udp_port_peer1 == 0 || *udp_port_peer2 == 0 || !(1280..=if wireguard_tunnel_id.is_some() { 65000 } else { 1500 }).contains(mtu) || secret.is_empty() || secret.len() > 255 || !secret.bytes().all(|b| (b'!'..=b'~').contains(&b) && !matches!(b, b'"' | b'\\' | b'#')) {
            return Ok(Err("invalid L2TPv2 endpoints, PPP addresses, secret or MTU".into()));
        }
        if let Some(id) = wireguard_tunnel_id {
            if !crate::tunnel::supports_underlay(conn, *id, (*node_id_peer1, *node_id_peer2), "wireguard")? { return Ok(Err("WireGuard tunnel must connect the same nodes".into())); }
            let endpoints = [a.unwrap(), b.unwrap()];
            if crate::db::l2tp_v2_rows(conn)?.iter().filter(|r| r.wireguard_tunnel_id.is_some()).any(|r| [&r.endpoint_peer1, &r.endpoint_peer2].iter().any(|s| s.parse::<std::net::Ipv4Addr>().ok().is_some_and(|ip| endpoints.contains(&ip))))
                || crate::db::all_l2tp_rows(conn)?.iter().filter(|r| r.wireguard_tunnel_id.is_some()).any(|r| [&r.endpoint_peer1, &r.endpoint_peer2].iter().any(|s| s.parse::<std::net::Ipv4Addr>().ok().is_some_and(|ip| endpoints.contains(&ip)))) {
                return Ok(Err("WireGuard L2TP address already in use".into()));
            }
            let outer = wireguard_tunnels::table.select((wireguard_tunnels::endpoint_peer1, wireguard_tunnels::endpoint_peer2)).load::<(Option<String>, Option<String>)>(conn)?;
            if outer.iter().flat_map(|(x,y)| [x,y]).flatten().filter_map(|s| s.parse::<std::net::SocketAddr>().ok()).any(|s| matches!(s.ip(), std::net::IpAddr::V4(ip) if endpoints.contains(&ip))) {
                return Ok(Err("WireGuard L2TP address conflicts with an outer endpoint".into()));
            }
        }
        if tunnel_ports_in_use(conn, [(*node_id_peer1, *udp_port_peer1), (*node_id_peer2, *udp_port_peer2)])? { return Ok(Err("L2TP UDP port already used on node".into())); }
    }
    if let Action::CreateL2tpTunnel { node_id_peer1, node_id_peer2, endpoint_peer1, endpoint_peer2, udp_port_peer1, udp_port_peer2, session_id_peer1, session_id_peer2, cookie_peer1, cookie_peer2, security_mode, wireguard_tunnel_id, mtu } = &command.action {
        let address = |s: &str| s.parse::<std::net::IpAddr>().ok().filter(|ip| match ip {
            std::net::IpAddr::V4(v) => !v.is_unspecified() && !v.is_multicast() && !v.is_broadcast() && !v.is_loopback(),
            std::net::IpAddr::V6(v) => !v.is_unspecified() && !v.is_multicast() && !v.is_loopback() && !v.is_unicast_link_local() && v.to_ipv4_mapped().is_none(),
        });
        let a = address(endpoint_peer1); let b = address(endpoint_peer2);
        let cookie = |s: &str| s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if a.is_none() || b.is_none() || a == b || a.unwrap().is_ipv4() != b.unwrap().is_ipv4() || *udp_port_peer1 == 0 || *udp_port_peer2 == 0 || *session_id_peer1 == 0 || *session_id_peer2 == 0 || !cookie(cookie_peer1) || !cookie(cookie_peer2) || !(576..=65477).contains(mtu) {
            return Ok(Err("invalid L2TP endpoints, session, cookie or MTU".into()));
        }
        if tunnel_ports_in_use(conn, [(*node_id_peer1, *udp_port_peer1), (*node_id_peer2, *udp_port_peer2)])? { return Ok(Err("L2TP UDP port already used on node".into())); }
        match (security_mode.as_str(), wireguard_tunnel_id) {
            ("pure", None) => {},
            ("wireguard", Some(id)) => {
                if crate::db::l2tp_v2_rows(conn)?.iter().filter(|r| r.wireguard_tunnel_id.is_some()).any(|r| [&r.endpoint_peer1, &r.endpoint_peer2].iter().any(|s| s.parse::<std::net::IpAddr>().ok().is_some_and(|ip| Some(ip) == a || Some(ip) == b))) {
                    return Ok(Err("WireGuard L2TP address already in use".into()));
                }
                for row in crate::db::all_l2tp_rows(conn)?.iter().filter(|row| row.security_mode == "wireguard") {
                    for (ip, node) in [(a, *node_id_peer1), (b, *node_id_peer2)] {
                        for (other, owner) in [(&row.endpoint_peer1, row.node_id_peer1), (&row.endpoint_peer2, row.node_id_peer2)] {
                            if other.parse::<std::net::IpAddr>().ok() == ip && (owner != node || row.wireguard_tunnel_id != Some(*id)) {
                                return Ok(Err("WireGuard L2TP address belongs to another node or tunnel".into()));
                            }
                        }
                    }
                }
                if !crate::tunnel::supports_underlay(conn, *id, (*node_id_peer1, *node_id_peer2), "wireguard")? { return Ok(Err("WireGuard tunnel must connect the same nodes".into())); }
            },
            _ => return Ok(Err("invalid L2TP security mode".into())),
        }
    }
    if let Action::SetMeshFec { id, fec: true } = &command.action {
        if !mesh_groups::table.find(id).select(mesh_groups::auto_wireguard).first::<bool>(conn)? {
            return Ok(Err("FEC requires Auto WireGuard".into()));
        }
    }
    if let Action::SetMeshFaketcp { id, faketcp: true } = &command.action {
        if !mesh_groups::table.find(id).select(mesh_groups::auto_wireguard).first::<bool>(conn)? {
            return Ok(Err("FakeTCP requires Auto WireGuard".into()));
        }
    }
    if let Action::SetMeshMtu { id, mtu } = &command.action {
        if !(1280..=9000).contains(mtu) {
            return Ok(Err("MTU must be between 1280 and 9000".into()));
        }
        if !mesh_groups::table.find(id).select(mesh_groups::auto_wireguard).first::<bool>(conn)? {
            return Ok(Err("MTU requires Auto WireGuard".into()));
        }
    }
    // ponytail: untracked legacy writers retain ambiguous ownership; upgrade all writers before removing this guard.
    diesel::insert_into(tunnel_intents::table)
        .values(
            wireguard_tunnels::table
                .filter(not(exists(
                    tunnel_intents::table
                        .filter(tunnel_intents::tunnel_id.eq(wireguard_tunnels::id)),
                )))
                .select((
                    wireguard_tunnels::id,
                    "legacy".into_sql::<Text>(),
                    0.into_sql::<Integer>(),
                )),
        )
        .into_columns((
            tunnel_intents::tunnel_id,
            tunnel_intents::kind,
            tunnel_intents::mesh_id,
        ))
        .execute(conn)?;
    // Capture recipients before deleting edges; also include all current identities for additions.
    let recipients = crate::schema::node_control_identities::table
        .select(crate::schema::node_control_identities::node_id)
        .order(crate::schema::node_control_identities::node_id)
        .load::<i32>(conn)?;
    let before = recipients
        .iter()
        .map(|&id| {
            Ok((
                id,
                serde_json::to_value(crate::db::topology_snapshot(conn, id, 0)?)?,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    match &command.action {
        Action::CreateL2tpV2Tunnel { node_id_peer1, node_id_peer2, endpoint_peer1, endpoint_peer2, udp_port_peer1, udp_port_peer2, address_peer1, address_peer2, secret, mtu, wireguard_tunnel_id } => {
            let id = crate::db::next_management_id(conn, "tunnel")?;
            diesel::sql_query("INSERT INTO l2tpv2_tunnels VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
                .bind::<Integer,_>(id).bind::<Integer,_>(node_id_peer1).bind::<Integer,_>(node_id_peer2)
                .bind::<Text,_>(endpoint_peer1).bind::<Text,_>(endpoint_peer2)
                .bind::<Integer,_>(i32::from(*udp_port_peer1)).bind::<Integer,_>(i32::from(*udp_port_peer2))
                .bind::<Text,_>(address_peer1).bind::<Text,_>(address_peer2).bind::<Text,_>(secret).bind::<Integer,_>(mtu).bind::<Nullable<Integer>,_>(wireguard_tunnel_id).execute(conn)?;
        }
        Action::DeleteL2tpV2Tunnel { id } => {
            diesel::sql_query("DELETE FROM l2tpv2_tunnels WHERE id=?").bind::<Integer,_>(id).execute(conn)?;
        }
        Action::CreateL2tpTunnel { node_id_peer1, node_id_peer2, endpoint_peer1, endpoint_peer2, udp_port_peer1, udp_port_peer2, session_id_peer1, session_id_peer2, cookie_peer1, cookie_peer2, security_mode, wireguard_tunnel_id, mtu } => {
            let id = crate::db::next_management_id(conn, "tunnel")?;
            diesel::sql_query("INSERT INTO l2tpv3_tunnels VALUES (?,'static',?,?,?,?,?,?,?,?,?,?,?,?,?)")
                .bind::<Integer,_>(id).bind::<Integer,_>(node_id_peer1).bind::<Integer,_>(node_id_peer2)
                .bind::<Text,_>(endpoint_peer1).bind::<Text,_>(endpoint_peer2)
                .bind::<Integer,_>(i32::from(*udp_port_peer1)).bind::<Integer,_>(i32::from(*udp_port_peer2))
                .bind::<diesel::sql_types::BigInt,_>(i64::from(*session_id_peer1)).bind::<diesel::sql_types::BigInt,_>(i64::from(*session_id_peer2))
                .bind::<Text,_>(cookie_peer1).bind::<Text,_>(cookie_peer2).bind::<Text,_>(security_mode)
                .bind::<Nullable<Integer>,_>(wireguard_tunnel_id).bind::<Integer,_>(mtu).execute(conn)?;
            diesel::insert_into(application_kv::table).values((application_kv::key.eq(format!("l2tp_active/{id}")), application_kv::value.eq("true"))).execute(conn)?;
        }
        Action::DeleteL2tpTunnel { id } => {
            diesel::delete(application_kv::table.find(format!("l2tp_active/{id}"))).execute(conn)?;
            diesel::sql_query("DELETE FROM l2tpv3_tunnels WHERE id=?").bind::<Integer,_>(id).execute(conn)?;
        }
        Action::SetMeshFec { id, fec } => {
            diesel::update(mesh_groups::table.find(id))
                .set(mesh_groups::auto_wireguard_fec.eq(fec))
                .execute(conn)?;
        }
        Action::SetMeshFaketcp { id, faketcp } => {
            diesel::update(mesh_groups::table.find(id))
                .set(mesh_groups::auto_wireguard_faketcp.eq(faketcp))
                .execute(conn)?;
        }
        Action::SetMeshMtu { id, mtu } => {
            diesel::update(mesh_groups::table.find(id))
                .set(mesh_groups::auto_wireguard_mtu.eq(mtu))
                .execute(conn)?;
            // ponytail: shared tunnels use the latest explicit MTU; add per-owner arbitration if required.
            diesel::update(
                wireguard_tunnels::table
                    .filter(wireguard_tunnels::id.eq_any(
                        tunnel_intents::table
                            .filter(tunnel_intents::kind.eq("mesh"))
                            .filter(tunnel_intents::mesh_id.eq(id))
                            .select(tunnel_intents::tunnel_id),
                    ))
                    .filter(wireguard_tunnels::mtu.ne(mtu)),
            )
            .set((
                wireguard_tunnels::mtu.eq(mtu),
                wireguard_tunnels::updated_at.eq(command.applied_at),
            ))
            .execute(conn)?;
        }
        Action::AddMembership { mesh_id, node_id }
        | Action::RemoveMembership { mesh_id, node_id } => {
            if matches!(command.action, Action::AddMembership { .. }) {
                crate::db::join_mesh_at(conn, *node_id, *mesh_id, command.applied_at)?;
            } else {
                diesel::delete(
                    tunnel_intents::table
                        .filter(tunnel_intents::kind.eq("mesh"))
                        .filter(tunnel_intents::mesh_id.eq(mesh_id))
                        .filter(
                            tunnel_intents::tunnel_id.eq_any(
                                wireguard_tunnels::table
                                    .filter(
                                        wireguard_tunnels::node_id_peer1
                                            .eq(node_id)
                                            .or(wireguard_tunnels::node_id_peer2.eq(node_id)),
                                    )
                                    .select(wireguard_tunnels::id),
                            ),
                        ),
                )
                .execute(conn)?;
                diesel::delete(
                    mesh_group_memberships::table
                        .filter(mesh_group_memberships::mesh_group_id.eq(mesh_id))
                        .filter(mesh_group_memberships::node_id.eq(node_id)),
                )
                .execute(conn)?;
            }
        }
        Action::DeleteMesh { id } => {
            invalidate_invites(
                conn,
                invites::override_join_mesh.eq(*id),
                "invite invalidated by mesh deletion",
            )?;
            diesel::delete(
                tunnel_intents::table
                    .filter(tunnel_intents::kind.eq("mesh"))
                    .filter(tunnel_intents::mesh_id.eq(id)),
            )
            .execute(conn)?;
            diesel::delete(
                mesh_group_memberships::table.filter(mesh_group_memberships::mesh_group_id.eq(id)),
            )
            .execute(conn)?;
            diesel::delete(mesh_groups::table.find(id)).execute(conn)?;
        }
        Action::DeleteNode { id } => {
            diesel::sql_query("DELETE FROM application_kv WHERE key IN (SELECT 'l2tp_active/' || id FROM l2tpv3_tunnels WHERE node_id_peer1=? OR node_id_peer2=?)").bind::<Integer,_>(id).bind::<Integer,_>(id).execute(conn)?;
            diesel::sql_query("DELETE FROM l2tpv3_tunnels WHERE node_id_peer1=? OR node_id_peer2=?").bind::<Integer,_>(id).bind::<Integer,_>(id).execute(conn)?;
            diesel::sql_query("DELETE FROM l2tpv2_tunnels WHERE node_id_peer1=? OR node_id_peer2=?").bind::<Integer,_>(id).bind::<Integer,_>(id).execute(conn)?;
            // Enrollment receipts retain identities from before control identities existed.
            diesel::sql_query("INSERT OR IGNORE INTO application_kv(key,value) SELECT 'node_revocation/' || peer_id, json_object('node_id', ?, 'revoked_at', ?) FROM node_control_identities WHERE node_id = ? UNION ALL SELECT 'node_revocation/' || substr(key,27), json_object('node_id', ?, 'revoked_at', ?) FROM application_kv WHERE substr(key,1,26)='control_enrollment_result/' AND json_extract(json_extract(value,'$.result'), '$.Enrolled.node_id') = ?")
                .bind::<Integer, _>(id).bind::<diesel::sql_types::Timestamp, _>(command.applied_at).bind::<Integer, _>(id)
                .bind::<Integer, _>(id).bind::<diesel::sql_types::Timestamp, _>(command.applied_at).bind::<Integer, _>(id)
                .execute(conn)?;
            let tunnels = wireguard_tunnels::table.filter(
                wireguard_tunnels::node_id_peer1
                    .eq(id)
                    .or(wireguard_tunnels::node_id_peer2.eq(id)),
            );
            diesel::delete(
                tunnel_intents::table.filter(
                    tunnel_intents::tunnel_id.eq_any(tunnels.select(wireguard_tunnels::id)),
                ),
            )
            .execute(conn)?;
            diesel::delete(tunnels).execute(conn)?;
            diesel::delete(
                mesh_group_memberships::table.filter(mesh_group_memberships::node_id.eq(id)),
            )
            .execute(conn)?;
            diesel::delete(application_kv::table.find(format!("wireguard_key/{id}"))).execute(conn)?;
            let prefix = format!("control_answer_result/{id}/");
            diesel::sql_query("DELETE FROM application_kv WHERE substr(key,1,length(?))=?")
                .bind::<Text, _>(&prefix).bind::<Text, _>(&prefix).execute(conn)?;
            diesel::delete(node_control_identities::table.find(id)).execute(conn)?;
            diesel::delete(nodes::table.find(id)).execute(conn)?;
        }
        Action::RemoveTunnelIntent { tunnel_id, kind } => {
            diesel::delete(
                tunnel_intents::table
                    .filter(tunnel_intents::tunnel_id.eq(tunnel_id))
                    .filter(tunnel_intents::kind.eq(match kind {
                        IntentKind::Manual => "manual",
                        IntentKind::Legacy => "legacy",
                    })),
            )
            .execute(conn)?;
        }
        _ => return Err("not a topology mutation".into()),
    }
    // No foreign-key cascade assumptions. Unknown ownership is preserved, never guessed away.
    diesel::delete(wireguard_tunnels::table.filter(not(exists(
        tunnel_intents::table.filter(tunnel_intents::tunnel_id.eq(wireguard_tunnels::id)),
    ))))
    .execute(conn)?;
    crate::tunnel::remove_orphaned(conn)?;
    let mut affected = Vec::new();
    for (id, old) in before {
        if crate::db::control_identity_for_node(conn, id)
            .optional()?
            .is_some()
            && serde_json::to_value(crate::db::topology_snapshot(conn, id, 0)?)? != old
        {
            crate::db::bump_control_revision_at(conn, id, command.applied_at)?;
            affected.push(id);
        }
    }
    Ok(Ok(Some(
        serde_json::json!({"committed":true,"affected_nodes":affected,"convergence":"polling"})
            .to_string(),
    )))
}

pub(crate) fn local_inventory(conn: &mut diesel::SqliteConnection, operation: Operation) -> Result<serde_json::Value, Error> {
    if !matches!(operation, Operation::Inventory | Operation::Status) { return Err("not a local inventory read".into()); }
    conn.transaction(|conn| read(conn, operation))
}

pub(crate) fn read(
    conn: &mut diesel::SqliteConnection,
    operation: Operation,
) -> Result<serde_json::Value, Error> {
    match operation {
        Operation::SessionRevoked(id) => {
            if !valid_session_id(&id) { return Err("invalid session ID".into()); }
            Ok(serde_json::json!(application_kv::table.find(format!("session_revocation/{id}"))
                .select(application_kv::key).first::<String>(conn).optional()?.is_some()))
        }
        Operation::Account => {
            #[derive(Deserialize, Serialize)]
            #[serde(deny_unknown_fields)]
            struct Account { username: String, password_hash: String }
            let value = application_kv::table.find("administrator/1")
                .select(application_kv::value).first::<String>(conn).optional()?;
            match value {
                Some(value) => Ok(serde_json::to_value(serde_json::from_str::<Account>(&value)?)?),
                None => Ok(serde_json::Value::Null),
            }
        }
        Operation::Inventory => {
            // Read timestamps as text to preserve SQLite's existing wire format, not Chrono's ISO format.
            let nodes = nodes::table.select((nodes::id, nodes::name,
                nodes::created_at, nodes::last_seen))
                .load::<(i32, String, TimestampText, Option<TimestampText>)>(conn)?
                .into_iter().map(|(id, name, created_at, last_seen)|
                    serde_json::json!({"id":id,"name":name,"created_at":created_at,"last_seen":last_seen})).collect::<Vec<_>>();
            let meshes = mesh_groups::table.select((mesh_groups::id, mesh_groups::name,
                mesh_groups::auto_wireguard, mesh_groups::auto_wireguard_mtu, mesh_groups::auto_wireguard_fec, mesh_groups::auto_wireguard_faketcp))
                .load::<(i32, String, bool, i32, bool, bool)>(conn)?.into_iter()
                .map(|(id, name, auto_wireguard, mtu, fec, faketcp)| serde_json::json!({"id":id,"name":name,"auto_wireguard":auto_wireguard,"mtu":mtu,"fec":fec,"faketcp":faketcp})).collect::<Vec<_>>();
            let memberships = mesh_group_memberships::table
                .select((mesh_group_memberships::mesh_group_id, mesh_group_memberships::node_id))
                .load::<(i32, i32)>(conn)?.into_iter()
                .map(|(mesh_id, node_id)| serde_json::json!({"mesh_id":mesh_id,"node_id":node_id})).collect::<Vec<_>>();
            let invites = invites::table.select((invites::id, invites::created_at,
                invites::expires_at, invites::used_count, invites::max_uses, invites::override_join_mesh))
                .load::<(i32, TimestampText, Option<TimestampText>, i32, Option<i32>, Option<i32>)>(conn)?.into_iter()
                .map(|(id, created_at, expires_at, used_count, max_uses, mesh_id)| serde_json::json!({"id":id,"created_at":created_at,"expires_at":expires_at,"used_count":used_count,"max_uses":max_uses,"mesh_id":mesh_id})).collect::<Vec<_>>();
            let mut intents = BTreeMap::<i32, Vec<serde_json::Value>>::new();
            for (tunnel_id, kind, mesh_id) in tunnel_intents::table
                .order((tunnel_intents::tunnel_id, tunnel_intents::kind, tunnel_intents::mesh_id))
                .load::<(i32, String, i32)>(conn)? {
                let mesh_id = (kind == "mesh").then_some(mesh_id);
                intents.entry(tunnel_id).or_default().push(serde_json::json!({"kind":kind,"mesh_id":mesh_id}));
            }
            let tunnels = wireguard_tunnels::table.select((wireguard_tunnels::id,
                wireguard_tunnels::node_id_peer1, wireguard_tunnels::node_id_peer2,
                wireguard_tunnels::endpoint_peer1, wireguard_tunnels::endpoint_peer2,
                wireguard_tunnels::endpoint_ipv6, wireguard_tunnels::mtu))
                .load::<(i32, i32, i32, Option<String>, Option<String>, bool, i32)>(conn)?.into_iter()
                .map(|(id, node_id_peer1, node_id_peer2, endpoint_peer1, endpoint_peer2, ipv6, mtu)|
                    serde_json::json!({"id":id,"node_id_peer1":node_id_peer1,"node_id_peer2":node_id_peer2,
                        "endpoint_peer1":endpoint_peer1,"endpoint_peer2":endpoint_peer2,"ipv6":ipv6,"mtu":mtu,
                        "intents":intents.remove(&id).unwrap_or_default()})).collect::<Vec<_>>();
            Ok(serde_json::json!({"nodes":nodes,"meshes":meshes,"memberships":memberships,"invites":invites,"tunnels":tunnels,"l2tp_tunnels":crate::db::l2tp_rows(conn)?,"l2tp_v2_tunnels":crate::db::l2tp_v2_rows(conn)?}))
        }
        Operation::Status => {
            Ok(serde_json::json!({
                "application_version": cat4igp_shared::compat::APPLICATION_VERSION,
                "observation": "local applied inventory"
            }))
        }
        Operation::RevokeSession(_) | Operation::Mutate(_) => Err("not a read".into()),
    }
}

pub(crate) fn valid_session_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
}

pub(crate) fn revoke_session(conn: &mut diesel::SqliteConnection, id: &str) -> Result<(), Error> {
    if !valid_session_id(id) { return Err("invalid session ID".into()); }
    // ponytail: tombstones do not expire; add GC only with a verified cluster clock bound.
    diesel::insert_or_ignore_into(application_kv::table).values((
        application_kv::key.eq(format!("session_revocation/{id}")),
        application_kv::value.eq("true"),
    )).execute(conn)?;
    Ok(())
}

pub(crate) fn serving_receipt(
    conn: &mut diesel::SqliteConnection,
    request_id: &str,
    fingerprint: &str,
) -> Result<Option<Result<Option<String>, String>>, Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt { fingerprint: String, result: String }
    let previous = application_kv::table.find(format!("administrator_result/{request_id}"))
        .select(application_kv::value).first::<String>(conn).optional()?
        .map(|value| serde_json::from_str::<Receipt>(&value)).transpose()?;
    previous
        .map(|receipt| {
            Ok(if receipt.fingerprint == fingerprint {
                serde_json::from_str(&receipt.result)?
            } else {
                Err("idempotency key conflict".into())
            })
        })
        .transpose()
}

pub(crate) fn save_receipt(conn: &mut diesel::SqliteConnection, request_id: &str, fingerprint: &str, result: &Result<Option<String>, String>) -> Result<(), Error> {
    diesel::insert_into(application_kv::table).values((
        application_kv::key.eq(format!("administrator_result/{request_id}")),
        application_kv::value.eq(serde_json::json!({"fingerprint":fingerprint,"result":serde_json::to_string(result)?}).to_string()),
    )).execute(conn)?;
    Ok(())
}

pub(crate) fn apply(
    conn: &mut diesel::SqliteConnection,
    command: &Mutation,
) -> Result<Result<Option<String>, String>, Error> {
    conn.transaction::<_, Error, _>(|conn| {
        if command.request_id.is_empty()
            || command.request_id.len() > 128
            || !command.request_id.is_ascii()
        {
            return Ok(Err("invalid idempotency key".into()));
        }
        let fingerprint = serde_json::to_string(&command.action)?;
        if let Some(previous) = serving_receipt(conn, &command.request_id, &fingerprint)? {
            return Ok(previous);
        }
        let valid_name = |name: &str| {
            !name.trim().is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
        };
        let result = match &command.action {
            Action::Bootstrap {
                username,
                password_hash,
            } => {
                if !valid_name(username) || PasswordHash::new(password_hash).is_err() {
                    Err("invalid administrator".into())
                } else if read(conn, Operation::Account)? != serde_json::Value::Null {
                    Err("administrator already exists".into())
                } else {
                    diesel::insert_into(application_kv::table)
                        .values((
                            application_kv::key.eq("administrator/1"),
                            application_kv::value.eq(serde_json::json!({"username":username,"password_hash":password_hash}).to_string()),
                        ))
                        .execute(conn)?;
                    Ok(Some("{\"committed\":true}".into()))
                }
            }
            Action::RenameNode { id, name } => {
                if *id <= 0 || !valid_name(name) {
                    Err("invalid node or name".into())
                } else if diesel::update(nodes::table.find(id))
                    .set(nodes::name.eq(name))
                    .execute(conn)?
                    != 1
                {
                    Err("node not found".into())
                } else {
                    Ok(Some("{\"committed\":true}".into()))
                }
            }
            Action::RenameMesh { id, name } => {
                if *id <= 0 || !valid_name(name) {
                    Err("invalid mesh or name".into())
                } else if diesel::update(mesh_groups::table.find(id))
                    .set(mesh_groups::name.eq(name))
                    .execute(conn)?
                    != 1
                {
                    Err("mesh not found".into())
                } else {
                    Ok(Some("{\"committed\":true}".into()))
                }
            }
            Action::InvalidateInvite { id } => {
                if *id <= 0
                    || !diesel::select(exists(invites::table.find(id))).get_result::<bool>(conn)?
                {
                    Err("invite not found".into())
                } else {
                    invalidate_invites(
                        conn,
                        invites::id.eq(*id).nullable(),
                        "invite invalidated by administrator",
                    )?;
                    Ok(Some("{\"committed\":true}".into()))
                }
            }
            Action::CreateMesh {
                name,
                auto_wireguard,
                mtu,
                fec,
                faketcp,
            } => {
                if !valid_name(name) || (!(1280..=9000).contains(mtu) && (*auto_wireguard || *mtu != 0))
                    || (!*auto_wireguard && (*fec || *faketcp))
                {
                    Err("invalid mesh name or MTU".into())
                } else {
                    let id = crate::db::next_management_id(conn, "mesh")?;
                    diesel::insert_into(mesh_groups::table)
                        .values((
                            mesh_groups::id.eq(id),
                            mesh_groups::name.eq(name),
                            mesh_groups::auto_wireguard.eq(auto_wireguard),
                            mesh_groups::auto_wireguard_fec.eq(fec),
                            mesh_groups::auto_wireguard_faketcp.eq(faketcp),
                            mesh_groups::auto_wireguard_mtu.eq(if *auto_wireguard {
                                *mtu
                            } else {
                                0
                            }),
                            mesh_groups::created_at.eq(command.applied_at),
                        ))
                        .execute(conn)?;
                    Ok(Some(
                        serde_json::json!({"committed":true,"mesh_id":id}).to_string(),
                    ))
                }
            }
            _ => topology_mutation(conn, command)?,
        };
        save_receipt(conn, &command.request_id, &fingerprint, &result)?;
        Ok(result)
    })
}

pub(crate) async fn send(
    jobs: &crate::DatabaseSender,
    operation: Operation,
) -> Result<serde_json::Value, String> {
    let (reply, result) = tokio::sync::oneshot::channel();
    jobs.try_send(crate::DatabaseJob::Admin { operation, reply })
        .map_err(|_| "unavailable; outcome may be unknown")?;
    tokio::time::timeout(std::time::Duration::from_secs(12), result)
        .await
        .map_err(|_| "unavailable; outcome may be unknown")?
        .map_err(|_| "unavailable; outcome may be unknown")?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Keys {
    origin: String,
    issuer: String,
    audience: String,
    active: String,
    keys: BTreeMap<String, String>,
}

pub(crate) fn load_keys() -> Result<Option<Arc<Keys>>, String> {
    let path = match std::env::var("ADMIN_JWT_CONFIG_FILE") {
        Ok(path) => path,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err("invalid admin configuration path".into()),
    };
    let keys: Keys = serde_json::from_slice(&protected_file(&path).map_err(|_| "invalid admin configuration")?)
        .map_err(|_| "invalid admin configuration")?;
    validate_keys(&keys).map_err(|_| "invalid admin configuration".to_owned())?;
    Ok(Some(Arc::new(keys)))
}

fn protected_file(path: &str) -> Result<Vec<u8>, Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // O_NOFOLLOW prevents accepting a substituted symlink; inspect the opened inode.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.len() > 16_384 {
        return Err("secret file must be a regular owner-only file <=16KiB".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 {
        return Err("secret file too large".into());
    }
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    jti: String,
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[cfg(test)]
pub(crate) fn test_credentials() -> (Arc<Keys>, String) {
    let keys = Keys {
        origin: "https://controller.example".into(), issuer: "test".into(), audience: "browser".into(),
        active: "a".into(), keys: BTreeMap::from([("a".into(), "01234567890123456789012345678901".into())]),
    };
    let now = chrono::Utc::now().timestamp() as u64;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("a".into());
    let claims = Claims { sub: "administrator:1".into(), jti: uuid::Uuid::new_v4().to_string(), iss: keys.issuer.clone(), aud: keys.audience.clone(), iat: now, exp: now + LIFE };
    let token = jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(keys.keys["a"].as_bytes())).unwrap();
    (Arc::new(keys), token)
}

#[derive(Clone)]
struct Web {
    jobs: crate::DatabaseSender,
    keys: Arc<Keys>,
    hashing: Arc<tokio::sync::Semaphore>,
    attempts: Arc<std::sync::Mutex<(i64, u32)>>,
}

fn cookie(headers: &HeaderMap) -> Option<&str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for pair in header.to_str().ok()?.split(';') {
            let (name, value) = pair.trim().split_once('=')?;
            if name == COOKIE {
                if found.is_some() || value.is_empty() || value.len() > 4096 {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

pub(crate) fn session_id(keys: &Keys, token: &str, now: u64) -> Option<String> {
    if token.is_empty() || token.len() > 4096 { return None; }
    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return None;
    };
    if header.alg != Algorithm::HS256 {
        return None;
    }
    let Some(secret) = header.kid.as_ref().and_then(|id| keys.keys.get(id)) else {
        return None;
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&keys.issuer]);
    validation.set_audience(&[&keys.audience]);
    validation.set_required_spec_claims(&["sub", "iss", "aud", "exp", "iat"]);
    validation.leeway = 0;
    validation.validate_nbf = true;
    let Ok(data) = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) else {
        return None;
    };
    (data.claims.sub == "administrator:1"
        && valid_session_id(&data.claims.jti)
        && data.claims.iat <= now
        && data.claims.exp > now
        && data.claims.exp.checked_sub(data.claims.iat) == Some(LIFE)).then_some(data.claims.jti)
}

pub(crate) fn verify(keys: &Keys, token: &str, now: u64) -> bool { session_id(keys, token, now).is_some() }

async fn guard(State(web): State<Web>, request: Request, next: Next) -> Response {
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        != Some(web.keys.origin.as_str())
    {
        return failure(StatusCode::FORBIDDEN, "untrusted origin");
    }
    if request.method() == axum::http::Method::POST
        && request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/json")
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json required",
        );
    }
    if request.uri().path() != "/login" {
        let Some(id) = cookie(request.headers()).and_then(|token| session_id(&web.keys, token, chrono::Utc::now().timestamp() as u64)) else {
            return failure(StatusCode::UNAUTHORIZED, "unauthorized");
        };
        match send(&web.jobs, Operation::SessionRevoked(id)).await {
            Ok(serde_json::Value::Bool(false)) => {},
            Ok(serde_json::Value::Bool(true)) => return failure(StatusCode::UNAUTHORIZED, "unauthorized"),
            _ => return failure(StatusCode::SERVICE_UNAVAILABLE, "authorization unavailable"),
        }
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn failure(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({"success":false,"message":message})),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

async fn login(State(web): State<Web>, Json(login): Json<Login>) -> Response {
    if login.username.is_empty()
        || login.username.len() > 256
        || login.password.is_empty()
        || login.password.len() > 1024
    {
        return failure(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    {
        let mut attempts = web.attempts.lock().unwrap();
        let minute = chrono::Utc::now().timestamp() / 60;
        if attempts.0 != minute {
            *attempts = (minute, 0);
        }
        if attempts.1 >= 10 {
            return failure(StatusCode::TOO_MANY_REQUESTS, "login rate limited");
        }
        attempts.1 += 1;
    }
    let Ok(permit) = web.hashing.clone().try_acquire_owned() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "login busy");
    };
    let account = match send(&web.jobs, Operation::Account).await {
        Ok(account) => account,
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "authoritative state unavailable",
            );
        }
    };
    let username = account["username"].as_str().unwrap_or("").to_owned();
    let hash = account["password_hash"].as_str().unwrap_or("").to_owned();
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(login.password.as_bytes(), &hash)
                .is_ok()
        }) && username == login.username
    })
    .await
    .unwrap_or(false);
    if !valid {
        return failure(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    let now = chrono::Utc::now().timestamp() as u64;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(web.keys.active.clone());
    let claims = Claims {
        sub: "administrator:1".into(),
        jti: uuid::Uuid::new_v4().to_string(),
        iss: web.keys.issuer.clone(),
        aud: web.keys.audience.clone(),
        iat: now,
        exp: now + LIFE,
    };
    let Ok(token) = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(web.keys.keys[&web.keys.active].as_bytes()),
    ) else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "session unavailable");
    };
    (
        [(
            header::SET_COOKIE,
            format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={LIFE}"),
        )],
        Json(serde_json::json!({"success":true,"subject":"administrator:1","expires_at":now+LIFE})),
    )
        .into_response()
}

async fn logout(State(web): State<Web>, headers: HeaderMap) -> Response {
    let Some(id) = cookie(&headers).and_then(|token| session_id(&web.keys, token, chrono::Utc::now().timestamp() as u64)) else {
        return failure(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    if send(&web.jobs, Operation::RevokeSession(id)).await.is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "logout outcome unknown");
    }
    ([(header::SET_COOKIE, format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"))], StatusCode::NO_CONTENT).into_response()
}

async fn inventory(State(web): State<Web>) -> Response {
    match send(&web.jobs, Operation::Inventory).await {
        Ok(value) => Json(value).into_response(),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authoritative state unavailable",
        ),
    }
}

async fn status(State(web): State<Web>) -> Response {
    match send(&web.jobs, Operation::Status).await {
        Ok(value) => Json(value).into_response(),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authoritative state unavailable",
        ),
    }
}

async fn invite(
    State(web): State<Web>,
    mut headers: HeaderMap,
    Json(payload): Json<cat4igp_shared::rest::operator::CreateInvitePayload>,
) -> Response {
    let Some(key) = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 100 && v.is_ascii())
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key required (1..100 ASCII bytes)",
        );
    };
    let scoped = format!("admin:1:invite:{key}");
    headers.insert("Idempotency-Key", scoped.parse().unwrap());
    crate::router::operator::create_invite(State(web.jobs), headers, Json(payload))
        .await
        .into_response()
}

async fn mutate(
    State(web): State<Web>,
    headers: HeaderMap,
    Json(action): Json<Action>,
) -> Response {
    if matches!(action, Action::Bootstrap { .. }) {
        return failure(StatusCode::FORBIDDEN, "bootstrap is local only");
    }
    let Some(key) = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 100 && v.is_ascii())
    else {
        return failure(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key required (1..100 ASCII bytes)",
        );
    };
    match send(
        &web.jobs,
        Operation::Mutate(Mutation {
            request_id: format!("admin:1:{key}"),
            action,
            applied_at: chrono::Utc::now().naive_utc(),
        }),
    )
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) if error.starts_with("unavailable") => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "outcome unknown; retry with same key and payload",
        ),
        Err(error) => failure(StatusCode::CONFLICT, &error),
    }
}

fn validate_keys(keys: &Keys) -> Result<(), Error> {
    let uri: axum::http::Uri = keys.origin.parse()?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        || keys.origin.ends_with('/')
        || keys.issuer.is_empty()
        || keys.audience.is_empty()
        || keys.keys.is_empty()
        || keys.keys.len() > 4
        || !keys.keys.contains_key(&keys.active)
        || keys
            .keys
            .iter()
            .any(|(id, key)| id.is_empty() || id.len() > 64 || key.len() < 32 || key.len() > 256)
    {
        return Err("invalid JWT configuration".into());
    }
    Ok(())
}

pub(crate) async fn router(jobs: crate::DatabaseSender) -> Result<Router, Error> {
    let Some(keys) = load_keys()? else { return Ok(Router::new()); };
    if let Ok(path) = std::env::var("ADMIN_BOOTSTRAP_FILE") {
        let login: Login = serde_json::from_slice(&protected_file(&path)?)?;
        if login.username.trim().is_empty()
            || login.username.len() > 256
            || login.username.chars().any(char::is_control)
            || login.password.len() < 12
            || login.password.len() > 1024
        {
            return Err("invalid bootstrap credentials".into());
        }
        if send(&jobs, Operation::Account).await? != serde_json::Value::Null {
            return Err("administrator already exists; remove ADMIN_BOOTSTRAP_FILE".into());
        }
        let hash = tokio::task::spawn_blocking(move || {
            Argon2::default()
                .hash_password(
                    login.password.as_bytes(),
                    &SaltString::generate(&mut rand08::rngs::OsRng),
                )
                .map(|hash| (login.username, hash.to_string()))
                .map_err(|_| "password hashing failed")
        })
        .await??;
        send(
            &jobs,
            Operation::Mutate(Mutation {
                request_id: "bootstrap-administrator".into(),
                applied_at: chrono::Utc::now().naive_utc(),
                action: Action::Bootstrap {
                    username: hash.0,
                    password_hash: hash.1,
                },
            }),
        )
        .await?;
    }
    Ok(web_router(jobs, keys))
}

fn web_router(jobs: crate::DatabaseSender, keys: impl Into<Arc<Keys>>) -> Router {
    let web = Web {
        jobs,
        keys: keys.into(),
        hashing: Arc::new(tokio::sync::Semaphore::new(2)),
        attempts: Arc::new(std::sync::Mutex::new((0, 0))),
    };
    Router::new()
        .route("/login", post(login))
        .route(
            "/me",
            get(|| async { Json(serde_json::json!({"subject":"administrator:1"})) }),
        )
        .route("/logout", post(logout))
        .route("/inventory", get(inventory))
        .route("/status", get(status))
        .route("/invites", post(invite))
        .route("/actions", post(mutate))
        .layer(axum::middleware::from_fn_with_state(web.clone(), guard))
        .layer(axum::extract::DefaultBodyLimit::max(4096))
        .with_state(web)
}

#[cfg(test)]
pub(crate) async fn test_gateway(
    jobs: crate::DatabaseSender,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().nest(
        "/admin",
        web_router(
            jobs,
            Keys {
                origin: "https://controller.example".into(),
                issuer: "test".into(),
                audience: "browser".into(),
                active: "test".into(),
                keys: BTreeMap::from([("test".into(), "a".repeat(32))]),
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (
        address,
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }),
    )
}

#[cfg(test)]
pub(crate) async fn test_request(
    address: std::net::SocketAddr,
    path: &str,
    cookie: &str,
    body: Option<&str>,
) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let method = if body.is_some() { "POST" } else { "GET" };
    let body = body.unwrap_or("");
    socket.write_all(format!("{method} /admin/{path} HTTP/1.1\r\nHost: controller.example\r\nConnection: close\r\nOrigin: https://controller.example\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        socket.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        head.into(),
        body.into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_contract_and_node_revocation() {
        use diesel::connection::SimpleConnection;
        let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        assert_eq!(
            read(&mut conn, Operation::Account).unwrap(),
            serde_json::Value::Null
        );
        assert_eq!(
            read(&mut conn, Operation::Inventory).unwrap(),
            serde_json::json!({
                "nodes":[],"meshes":[],"memberships":[],"invites":[],"tunnels":[],"l2tp_tunnels":[],"l2tp_v2_tunnels":[]
            })
        );
        conn.batch_execute(r#"
            INSERT INTO nodes(id,name,auth_key,created_at,last_seen) VALUES
                (1,'a','secret','2026-10-20 12:34:56.123456',NULL),
                (2,'b','secret','2026-10-20 12:34:56','2026-10-20 13:00:00');
            INSERT INTO mesh_groups(id,name,auto_wireguard,auto_wireguard_mtu,created_at) VALUES(1,'mesh',1,1420,'2026-10-20 12:34:56');
            INSERT INTO mesh_group_memberships(mesh_group_id,node_id,created_at) VALUES(1,1,'2026-10-20 12:34:56');
            INSERT INTO invites(code,created_at,expires_at,max_uses,override_join_mesh) VALUES
                ('secret','2026-10-20 12:34:56',NULL,NULL,NULL),
                ('other','2026-10-20 12:34:56','2026-10-21 12:34:56',3,1);
            INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,endpoint_ipv6,mtu) VALUES
                (1,1,2,NULL,'[2001:db8::2]:1234',1,1420),(2,2,2,'192.0.2.1:42',NULL,0,1280);
            INSERT INTO tunnel_intents VALUES(1,'mesh',1),(1,'manual',0),(1,'legacy',0);
            INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'current','signing','encryption');
            INSERT INTO application_kv VALUES('wireguard_key/2',json_object('public_key','peer-key','created_at','2026-01-01'));
            INSERT INTO application_kv VALUES
                ('control_enrollment_result/current',json_object('request_id','','fingerprint','f','result','{"Enrolled":{"node_id":1}}')),
                ('control_enrollment_result/legacy',json_object('request_id','','fingerprint','f','result','{"Enrolled":{"node_id":1}}')),
                ('control_enrollment_result/other',json_object('request_id','','fingerprint','f','result','{"Enrolled":{"node_id":2}}')),
                ('control_enrollment_result/rejected',json_object('request_id','','fingerprint','f','result','{"Rejected":"no"}'));
        "#).unwrap();
        let inventory = read(&mut conn, Operation::Inventory).unwrap();
        assert_eq!(
            inventory["nodes"],
            serde_json::json!([
                {"id":1,"name":"a","created_at":"2026-10-20 12:34:56.123456","last_seen":null},
                {"id":2,"name":"b","created_at":"2026-10-20 12:34:56","last_seen":"2026-10-20 13:00:00"}
            ])
        );
        assert_eq!(
            inventory["meshes"],
            serde_json::json!([{"id":1,"name":"mesh","auto_wireguard":true,"mtu":1420,"fec":false,"faketcp":false}])
        );
        assert_eq!(
            inventory["memberships"],
            serde_json::json!([{"mesh_id":1,"node_id":1}])
        );
        assert_eq!(
            inventory["invites"],
            serde_json::json!([
                {"id":1,"created_at":"2026-10-20 12:34:56","expires_at":null,"used_count":0,"max_uses":null,"mesh_id":null},
                {"id":2,"created_at":"2026-10-20 12:34:56","expires_at":"2026-10-21 12:34:56","used_count":0,"max_uses":3,"mesh_id":1}
            ])
        );
        assert_eq!(
            inventory["tunnels"],
            serde_json::json!([
                {"id":1,"node_id_peer1":1,"node_id_peer2":2,"endpoint_peer1":null,"endpoint_peer2":"[2001:db8::2]:1234","ipv6":true,"mtu":1420,
                    "intents":[{"kind":"legacy","mesh_id":null},{"kind":"manual","mesh_id":null},{"kind":"mesh","mesh_id":1}]},
                {"id":2,"node_id_peer1":2,"node_id_peer2":2,"endpoint_peer1":"192.0.2.1:42","endpoint_peer2":null,"ipv6":false,"mtu":1280,"intents":[]}
            ])
        );
        let command = Mutation {
            request_id: "delete".into(),
            action: Action::DeleteNode { id: 1 },
            applied_at: chrono::Utc::now().naive_utc(),
        };
        let result = apply(&mut conn, &command).unwrap();
        assert!(result.is_ok());
        assert_eq!(apply(&mut conn, &command).unwrap(), result);
        assert_eq!(
            [crate::db::identity_revoked(&mut conn, "current").unwrap(), crate::db::identity_revoked(&mut conn, "legacy").unwrap()],
            [true, true]
        );
        let remaining = read(&mut conn, Operation::Inventory).unwrap();
        assert_eq!(remaining["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(remaining["tunnels"].as_array().unwrap().len(), 1);
        assert_eq!(remaining["tunnels"][0]["id"], 2);
        assert_eq!(
            remaining["tunnels"][0]["intents"],
            serde_json::json!([{"kind":"legacy","mesh_id":null}])
        );
    }

    // Isolate environment configuration in a child process; no unsafe set_var in parallel tests.
    #[tokio::test]
    async fn nested_router_authentication_and_rotation() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        fn provision(path: &std::path::Path, active: &str, old: bool) {
            let mut keys = BTreeMap::from([("b", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")]);
            if old {
                keys.insert("a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            }
            std::fs::write(
                path,
                serde_json::to_vec(&serde_json::json!({
                    "origin":"https://controller.example", "issuer":"test", "audience":"browser",
                    "active":active, "keys":keys,
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        if std::env::var_os("CAT4IGP_ADMIN_ROUTER_TEST").is_none() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("keys.json");
            provision(&path, "a", true);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "admin::tests::nested_router_authentication_and_rotation",
                    "--nocapture",
                ])
                .env("CAT4IGP_ADMIN_ROUTER_TEST", "1")
                .env("ADMIN_JWT_CONFIG_FILE", &path)
                .env_remove("ADMIN_BOOTSTRAP_FILE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        async fn start(
            jobs: crate::DatabaseSender,
        ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
            let app = Router::new().nest("/admin", router(jobs).await.unwrap());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (address, server)
        }

        async fn request(
            address: std::net::SocketAddr,
            method: &str,
            path: &str,
            headers: &str,
            body: &str,
        ) -> (u16, String, String) {
            let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
            socket.write_all(format!("{method} /admin/{path} HTTP/1.1\r\nHost: controller.example\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()).as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.read_to_end(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            let text = String::from_utf8(bytes).unwrap();
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            (
                head.split_whitespace().nth(1).unwrap().parse().unwrap(),
                head.to_owned(),
                body.to_owned(),
            )
        }

        let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        let password = "a sufficiently long password";
        let hash = Argon2::default()
            .hash_password(
                password.as_bytes(),
                &SaltString::generate(&mut rand08::rngs::OsRng),
            )
            .unwrap()
            .to_string();
        assert!(
            apply(
                &mut conn,
                &Mutation {
                    request_id: "bootstrap".into(),
                    applied_at: chrono::Utc::now().naive_utc(),
                    action: Action::Bootstrap {
                        username: "admin".into(),
                        password_hash: hash
                    },
                }
            )
            .unwrap()
            .is_ok()
        );
        let (jobs, mut work) = tokio::sync::mpsc::channel(8);
        let worker = tokio::spawn(async move {
            let mut calls = (0, 0, 0);
            while let Some(job) = work.recv().await {
                let crate::DatabaseJob::Admin { operation, reply } = job else {
                    panic!("unexpected job")
                };
                let value = match operation {
                    Operation::Account => {
                        calls.0 += 1;
                        read(&mut conn, Operation::Account).unwrap()
                    }
                    Operation::Inventory => {
                        calls.1 += 1;
                        read(&mut conn, Operation::Inventory).unwrap()
                    }
                    Operation::Status => read(&mut conn, Operation::Status).unwrap(),
                    Operation::SessionRevoked(id) => read(&mut conn, Operation::SessionRevoked(id)).unwrap(),
                    Operation::RevokeSession(id) => { revoke_session(&mut conn, &id).unwrap(); serde_json::Value::Null },
                    Operation::Mutate(command) => {
                        calls.2 += 1;
                        let value = apply(&mut conn, &command).unwrap().unwrap().unwrap();
                        serde_json::from_str(&value).unwrap()
                    }
                };
                reply.send(Ok(value)).unwrap();
            }
            calls
        });
        let (first, server1) = start(jobs.clone()).await;
        let (second, server2) = start(jobs.clone()).await;
        let json = "Origin: https://controller.example\r\nContent-Type: application/json\r\n";
        let credentials = serde_json::json!({"username":"admin", "password":password}).to_string();
        assert_eq!(request(first, "GET", "inventory", "", "").await.0, 401);
        for headers in [
            "Content-Type: application/json\r\n",
            "Origin: https://evil.example\r\nContent-Type: application/json\r\n",
        ] {
            assert_eq!(
                request(first, "POST", "login", headers, &credentials)
                    .await
                    .0,
                403
            );
        }
        assert_eq!(
            request(
                first,
                "POST",
                "login",
                "Origin: https://controller.example\r\nContent-Type: text/plain\r\n",
                &credentials
            )
            .await
            .0,
            415
        );
        assert_eq!(request(first, "POST", "login", json, "{").await.0, 400);
        assert_eq!(
            request(first, "POST", "login", json, &" ".repeat(4097))
                .await
                .0,
            413
        );
        assert_eq!(
            request(
                first,
                "POST",
                "login",
                json,
                r#"{"username":"admin","password":"wrong"}"#
            )
            .await
            .0,
            401
        );
        let (status, headers, _) = request(first, "POST", "login", json, &credentials).await;
        // This must reach login without a cookie after Axum strips the /admin nesting prefix.
        assert_eq!(status, 200, "{headers}");
        assert!(headers.to_lowercase().contains("cache-control: no-store"));
        let set_cookie = headers
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .unwrap();
        for flag in [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=900",
        ] {
            assert!(set_cookie.contains(flag));
        }
        assert!(!set_cookie.contains("Domain="));
        let cookie = set_cookie.split(';').next().unwrap();
        let auth = format!("Cookie: {cookie}\r\n");
        assert_eq!(
            request(
                first,
                "GET",
                "me",
                &format!("Cookie: {cookie}; {cookie}\r\n"),
                ""
            )
            .await
            .0,
            401
        );
        for address in [first, second] {
            let (status, _, body) = request(address, "GET", "me", &auth, "").await;
            assert_eq!(status, 200);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["subject"],
                "administrator:1"
            );
        }
        let malicious = r#"{"action":"bootstrap","username":"attacker","password_hash":"invalid"}"#;
        let write = format!("{json}{auth}Idempotency-Key: mesh-test\r\n");
        assert_eq!(
            request(first, "POST", "actions", &write, malicious).await.0,
            403
        );
        let mesh =
            r#"{"action":"create_mesh","name":"test mesh","auto_wireguard":true,"mtu":1420}"#;
        let created = request(first, "POST", "actions", &write, mesh).await;
        assert_eq!(created.0, 200);
        assert_eq!(
            request(second, "POST", "actions", &write, mesh).await.2,
            created.2
        );
        let (status, _, body) = request(second, "GET", "inventory", &auth, "").await;
        assert_eq!(status, 200);
        let inventory: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(inventory["meshes"].as_array().unwrap().len(), 1);
        assert_eq!(inventory["meshes"][0]["name"], "test mesh");
        assert!(!body.contains("password_hash"));

        let path = std::env::var("ADMIN_JWT_CONFIG_FILE").unwrap();
        provision(std::path::Path::new(&path), "b", true);
        let (overlap, server3) = start(jobs.clone()).await;
        assert_eq!(request(overlap, "GET", "me", &auth, "").await.0, 200);
        let rotated = request(overlap, "POST", "login", json, &credentials).await;
        assert_eq!(rotated.0, 200);
        let new_cookie = rotated
            .1
            .lines()
            .find_map(|line| line.strip_prefix("set-cookie: "))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(new_cookie.split_once('=').unwrap().1)
                .unwrap()
                .kid
                .as_deref(),
            Some("b")
        );
        let new_auth = format!("Cookie: {new_cookie}\r\n");
        assert_eq!(request(second, "GET", "me", &new_auth, "").await.0, 200);
        provision(std::path::Path::new(&path), "b", false);
        let (retired, server4) = start(jobs.clone()).await;
        assert_eq!(request(retired, "GET", "me", &auth, "").await.0, 401);
        assert_eq!(request(retired, "GET", "me", &new_auth, "").await.0, 200);
        assert_eq!(
            request(retired, "POST", "logout", &new_auth, "{}").await.0,
            403
        );
        let logout = request(
            retired,
            "POST",
            "logout",
            &format!("{json}{new_auth}"),
            "{}",
        )
        .await;
        assert_eq!(logout.0, 204);
        assert_eq!(request(overlap, "GET", "me", &new_auth, "").await.0, 401);
        assert_eq!(request(overlap, "GET", "me", &auth, "").await.0, 200);
        assert!(logout.1.contains(&format!(
            "{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
        )));
        assert_eq!(request(retired, "GET", "me", "", "").await.0, 401);

        let (unavailable_jobs, unavailable_work) = tokio::sync::mpsc::channel(1);
        drop(unavailable_work);
        let (unavailable, server5) = start(unavailable_jobs).await;
        assert_eq!(
            request(unavailable, "POST", "login", json, &credentials)
                .await
                .0,
            503
        );
        assert_eq!(
            request(unavailable, "GET", "inventory", &new_auth, "")
                .await
                .0,
            503
        );
        let uncertain = request(
            unavailable,
            "POST",
            "actions",
            &format!("{json}{new_auth}Idempotency-Key: unknown\r\n"),
            mesh,
        )
        .await;
        assert_eq!(uncertain.0, 503);
        assert!(
            uncertain
                .2
                .contains("authorization unavailable")
        );

        for server in [server1, server2, server3, server4, server5] {
            server.abort();
            let _ = server.await;
        }
        drop(jobs);
        assert_eq!(
            worker.await.unwrap(),
            (3, 1, 2),
            "rejected requests must never reach the database"
        );
    }

    #[test]
    fn sessions_and_atomic_replay() {
        let now = chrono::Utc::now().timestamp() as u64;
        let keys = Keys {
            origin: "https://controller.example".into(),
            issuer: "test".into(),
            audience: "browser".into(),
            active: "a".into(),
            keys: BTreeMap::from([("a".into(), "01234567890123456789012345678901".into())]),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("a".into());
        let mut claims = Claims {
            sub: "administrator:1".into(),
            jti: uuid::Uuid::new_v4().to_string(),
            iss: "test".into(),
            aud: "browser".into(),
            iat: now,
            exp: now + LIFE,
        };
        let encode = |claims: &Claims| {
            jsonwebtoken::encode(
                &header,
                claims,
                &EncodingKey::from_secret(keys.keys["a"].as_bytes()),
            )
            .unwrap()
        };
        assert!(verify(&keys, &encode(&claims), now));
        assert!(!verify(&keys, "invalid", now));
        claims.iss = "other".into();
        assert!(!verify(&keys, &encode(&claims), now));
        claims.iss = "test".into();
        claims.aud = "other".into();
        assert!(!verify(&keys, &encode(&claims), now));
        claims.aud = "browser".into();
        claims.sub = "other".into();
        assert!(!verify(&keys, &encode(&claims), now));
        claims.sub = "administrator:1".into();
        assert!(!verify(&keys, &encode(&claims), now + LIFE));
        claims.iat = now + 1;
        assert!(!verify(&keys, &encode(&claims), now));
        claims.iat = now;
        claims.exp += 1;
        assert!(!verify(&keys, &encode(&claims), now));
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            "__Host-cat4igp=a; __Host-cat4igp=b".parse().unwrap(),
        );
        assert!(cookie(&headers).is_none());
        let mut conn = diesel::SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        let command = Mutation {
            request_id: "check".into(),
            applied_at: chrono::Utc::now().naive_utc(),
            action: Action::CreateMesh {
                name: "mesh".into(),
                auto_wireguard: true,
                mtu: 1420,
                fec: false,
                faketcp: false,
            },
        };
        let first = apply(&mut conn, &command).unwrap();
        assert!(first.is_ok());
        assert_eq!(first, apply(&mut conn, &command).unwrap());
        let changed = Mutation {
            action: Action::RenameNode {
                id: 1,
                name: "renamed".into(),
            },
            ..command
        };
        assert!(apply(&mut conn, &changed).unwrap().is_err());
        assert_eq!(
            read(&mut conn, Operation::Inventory).unwrap()["meshes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let hash = Argon2::default()
            .hash_password(
                b"a sufficiently long password",
                &SaltString::generate(&mut rand08::rngs::OsRng),
            )
            .unwrap()
            .to_string();
        let bootstrap = Mutation {
            request_id: "bootstrap".into(),
            action: Action::Bootstrap {
                username: "admin".into(),
                password_hash: hash,
            },
            applied_at: chrono::Utc::now().naive_utc(),
        };
        assert!(apply(&mut conn, &bootstrap).unwrap().is_ok());
        assert!(
            apply(
                &mut conn,
                &Mutation {
                    request_id: "duplicate".into(),
                    ..bootstrap
                }
            )
            .unwrap()
            .is_err()
        );
    }
}
