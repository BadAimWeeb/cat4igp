use std::{collections::BTreeMap, sync::Arc};

use crate::schema::{
    administrator, administrator_results, control_answer_results, control_enrollment_results,
    invites, mesh_group_memberships, mesh_groups, node_control_identities, node_revocations, nodes,
    operator_invite_results, tunnel_intents, wireguard_static_key, wireguard_tunnels,
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
    Inventory,
    Status,
    Replicas,
    CodeRead,
    Replica(ReplicaAction),
    Mutate(Mutation),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReplicaAction {
    EnrollmentCode,
    RotateEnrollmentCode {
        expected_generation: u64,
    },
    JoinBundle {
        bootstrap: libp2p::Multiaddr,
    },
    ActivateLearner {
        node_id: u64,
    },
    PromoteLearner {
        node_id: u64,
    },
    RevokeReplica {
        node_id: u64,
    },
    GrantServing {
        node_id: u64,
        expected_roster_revision: u64,
        public_address: libp2p::Multiaddr,
        control_address: libp2p::Multiaddr,
        request_id: String,
    },
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
    },
    SetMeshFec {
        id: i32,
        fec: bool,
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
        .filter(selection);
    diesel::update(
        operator_invite_results::table
            .filter(json_functions::text(operator_invite_results::result, "$.Ok").eq_any(codes)),
    )
    .set(operator_invite_results::result.eq(serde_json::to_string(
        &Result::<String, String>::Err(reason.into()),
    )?))
    .execute(conn)?;
    diesel::delete(invites::table.filter(deletion)).execute(conn)?;
    Ok(())
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
        Action::DeleteMesh { id } | Action::SetMeshFec { id, .. } | Action::SetMeshMtu { id, .. } => (!(*id > 0
            && diesel::select(exists(mesh_groups::table.find(id))).get_result::<bool>(conn)?))
        .then_some("mesh not found"),
        Action::DeleteNode { id } => (!(*id > 0
            && diesel::select(exists(nodes::table.find(id))).get_result::<bool>(conn)?))
        .then_some("node not found"),
        Action::RemoveTunnelIntent { tunnel_id, .. } => (!(*tunnel_id > 0
            && diesel::select(exists(wireguard_tunnels::table.find(tunnel_id)))
                .get_result::<bool>(conn)?))
        .then_some("tunnel not found"),
        _ => return Err("not a topology mutation".into()),
    };
    if let Some(message) = missing {
        return Ok(Err(message.into()));
    }
    if let Action::SetMeshFec { id, fec: true } = &command.action {
        if !mesh_groups::table.find(id).select(mesh_groups::auto_wireguard).first::<bool>(conn)? {
            return Ok(Err("FEC requires Auto WireGuard".into()));
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
        Action::SetMeshFec { id, fec } => {
            diesel::update(mesh_groups::table.find(id))
                .set(mesh_groups::auto_wireguard_fec.eq(fec))
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
            diesel::insert_or_ignore_into(node_revocations::table)
                .values(
                    node_control_identities::table
                        .filter(node_control_identities::node_id.eq(id))
                        .select((
                            node_control_identities::peer_id,
                            node_control_identities::node_id,
                            command
                                .applied_at
                                .into_sql::<diesel::sql_types::Timestamp>(),
                        )),
                )
                .into_columns((
                    node_revocations::peer_id,
                    node_revocations::node_id,
                    node_revocations::revoked_at,
                ))
                .execute(conn)?;
            // Enrollment results contain the original identity even for pre-control legacy records.
            diesel::insert_or_ignore_into(node_revocations::table)
                .values(
                    control_enrollment_results::table
                        .filter(
                            json_functions::integer(
                                control_enrollment_results::result,
                                "$.Enrolled.node_id",
                            )
                            .eq(id),
                        )
                        .select((
                            control_enrollment_results::peer_id,
                            id.into_sql::<Integer>(),
                            command
                                .applied_at
                                .into_sql::<diesel::sql_types::Timestamp>(),
                        )),
                )
                .into_columns((
                    node_revocations::peer_id,
                    node_revocations::node_id,
                    node_revocations::revoked_at,
                ))
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
            diesel::delete(wireguard_static_key::table.find(id)).execute(conn)?;
            diesel::delete(
                control_answer_results::table.filter(control_answer_results::node_id.eq(id)),
            )
            .execute(conn)?;
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

pub(crate) fn read(
    conn: &mut diesel::SqliteConnection,
    operation: Operation,
) -> Result<serde_json::Value, Error> {
    match operation {
        Operation::Account => Ok(administrator::table.find(1)
            .select((administrator::username, administrator::password_hash))
            .first::<(String, String)>(conn).optional()?
            .map(|(username, password_hash)| serde_json::json!({"username":username,"password_hash":password_hash}))
            .unwrap_or(serde_json::Value::Null)),
        Operation::Inventory => {
            // Read timestamps as text to preserve SQLite's existing wire format, not Chrono's ISO format.
            let nodes = nodes::table.select((nodes::id, nodes::name,
                nodes::created_at, nodes::last_seen))
                .load::<(i32, String, TimestampText, Option<TimestampText>)>(conn)?
                .into_iter().map(|(id, name, created_at, last_seen)|
                    serde_json::json!({"id":id,"name":name,"created_at":created_at,"last_seen":last_seen})).collect::<Vec<_>>();
            let meshes = mesh_groups::table.select((mesh_groups::id, mesh_groups::name,
                mesh_groups::auto_wireguard, mesh_groups::auto_wireguard_mtu, mesh_groups::auto_wireguard_fec))
                .load::<(i32, String, bool, i32, bool)>(conn)?.into_iter()
                .map(|(id, name, auto_wireguard, mtu, fec)| serde_json::json!({"id":id,"name":name,"auto_wireguard":auto_wireguard,"mtu":mtu,"fec":fec})).collect::<Vec<_>>();
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
            Ok(serde_json::json!({"nodes":nodes,"meshes":meshes,"memberships":memberships,"invites":invites,"tunnels":tunnels}))
        }
        Operation::Status => {
            use diesel::OptionalExtension;
            let admitted = crate::db::get_setting(conn, "controller_admitted")
                .optional()?
                .map(|v| serde_json::from_str::<serde_json::Value>(&v))
                .transpose()?
                .unwrap_or(serde_json::json!({}));
            let revoked = crate::db::get_setting(conn, "replica_revocations")
                .optional()?
                .map(|v| serde_json::from_str::<serde_json::Value>(&v))
                .transpose()?
                .unwrap_or(serde_json::json!({}));
            Ok(
                serde_json::json!({"application_version":cat4igp_shared::discovery::join::APPLICATION_VERSION,"replicas":admitted,"revocations":revoked,"observation":"committed inventory; not reachability"}),
            )
        }
        Operation::Replicas => {
            use diesel::OptionalExtension;
            let admitted: BTreeMap<u64, libp2p::PeerId> =
                crate::db::get_setting(conn, "controller_admitted")
                    .optional()?
                    .map(|s| serde_json::from_str(&s))
                    .transpose()?
                    .unwrap_or_default();
            let pending: Vec<crate::cluster::Admission> =
                crate::db::get_setting(conn, "replica_pending_admissions")
                    .optional()?
                    .map(|s| serde_json::from_str(&s))
                    .transpose()?
                    .unwrap_or_default();
            let roster: Option<
                cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerRoster>,
            > = crate::db::get_setting(conn, "controller_roster")
                .optional()?
                .map(|s| serde_json::from_str(&s))
                .transpose()?;
            Ok(serde_json::json!({
                "admitted": admitted,
                "pending": pending.iter().map(|a| serde_json::json!({"node_id":a.request.node_id,"peer_id":a.source,"address":a.request.address,"admitted_at_ms":a.at_ms})).collect::<Vec<_>>(),
                "roster": roster.map(|r| r.body),
                "revocations": crate::cluster::read_revocations(conn)?,
                "observation": "leader-linearized committed inventory; not reachability"
            }))
        }
        Operation::Replica(_) | Operation::CodeRead => {
            Err("cluster administration not available".into())
        }
        Operation::Mutate(_) => Err("not a read".into()),
    }
}

pub(crate) fn serving_receipt(
    conn: &mut diesel::SqliteConnection,
    request_id: &str,
    fingerprint: &str,
) -> Result<Option<Result<Option<String>, String>>, Error> {
    let previous = administrator_results::table
        .find(request_id)
        .select((
            administrator_results::fingerprint,
            administrator_results::result,
        ))
        .first::<(String, String)>(conn)
        .optional()?;
    previous
        .map(|(saved_fingerprint, result)| {
            Ok(if saved_fingerprint == fingerprint {
                serde_json::from_str(&result)?
            } else {
                Err("idempotency key conflict".into())
            })
        })
        .transpose()
}

pub(crate) fn apply_serving_grant(
    conn: &mut diesel::SqliteConnection,
    request_id: &str,
    fingerprint: &str,
    expected_revision: u64,
    roster: &cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerRoster>,
) -> Result<Result<Option<String>, String>, Error> {
    conn.transaction::<_, Error, _>(|conn| {
        if let Some(result) = serving_receipt(conn, request_id, fingerprint)? {
            return Ok(result);
        }
        let current = crate::cluster::read_authority(conn)?.roster;
        let result = if current.as_ref().map(|r| r.body.revision) != Some(expected_revision) {
            Err("roster revision conflict".into())
        } else {
            crate::cluster::apply_roster(conn, roster)?.map(|_| {
                Some(serde_json::json!({
                "committed":true, "roster_revision":roster.body.revision,
                "issued_at_ms":roster.body.issued_at_ms, "expires_at_ms":roster.body.expires_at_ms,
                "semantics":"durable request receipt; not lease renewal"
            }).to_string())
            })
        };
        diesel::insert_into(administrator_results::table)
            .values((
                administrator_results::request_id.eq(request_id),
                administrator_results::fingerprint.eq(fingerprint),
                administrator_results::result.eq(serde_json::to_string(&result)?),
            ))
            .execute(conn)?;
        Ok(result)
    })
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
                    diesel::insert_into(administrator::table)
                        .values((
                            administrator::id.eq(1),
                            administrator::username.eq(username),
                            administrator::password_hash.eq(password_hash),
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
            } => {
                if !valid_name(name) || (!(1280..=9000).contains(mtu) && (*auto_wireguard || *mtu != 0))
                    || (!*auto_wireguard && *fec)
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
        diesel::insert_into(administrator_results::table)
            .values((
                administrator_results::request_id.eq(&command.request_id),
                administrator_results::fingerprint.eq(fingerprint),
                administrator_results::result.eq(serde_json::to_string(&result)?),
            ))
            .execute(conn)?;
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
struct Keys {
    origin: String,
    issuer: String,
    audience: String,
    active: String,
    keys: BTreeMap<String, String>,
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
    iss: String,
    aud: String,
    iat: u64,
    exp: u64,
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

fn verify(keys: &Keys, token: &str, now: u64) -> bool {
    let Ok(header) = jsonwebtoken::decode_header(token) else {
        return false;
    };
    if header.alg != Algorithm::HS256 {
        return false;
    }
    let Some(secret) = header.kid.as_ref().and_then(|id| keys.keys.get(id)) else {
        return false;
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
        return false;
    };
    data.claims.sub == "administrator:1"
        && data.claims.iat <= now
        && data.claims.exp > now
        && data.claims.exp.checked_sub(data.claims.iat) == Some(LIFE)
}

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
    if request.uri().path() != "/login"
        && !cookie(request.headers())
            .is_some_and(|token| verify(&web.keys, token, chrono::Utc::now().timestamp() as u64))
    {
        return failure(StatusCode::UNAUTHORIZED, "unauthorized");
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

async fn replicas(State(web): State<Web>) -> Response {
    replica_response(send(&web.jobs, Operation::Replicas).await)
}

fn replica_response(result: Result<serde_json::Value, String>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) if error.starts_with("unavailable") => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "outcome unknown; inspect inventory before resuming the same desired state",
        ),
        Err(error) => failure(StatusCode::CONFLICT, &error),
    }
}

async fn replica_action(
    State(web): State<Web>,
    headers: HeaderMap,
    Json(action): Json<ReplicaAction>,
) -> Response {
    // Serving grants carry a durable, administrator-scoped body request ID.
    if headers.contains_key("Idempotency-Key") {
        return failure(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key unsupported; this is a desired-state reconciliation API",
        );
    }
    if matches!(
        action,
        ReplicaAction::ActivateLearner { node_id: 0 }
            | ReplicaAction::PromoteLearner { node_id: 0 }
            | ReplicaAction::RevokeReplica { node_id: 0 }
    ) {
        return failure(StatusCode::BAD_REQUEST, "node_id must be positive");
    }
    if let ReplicaAction::GrantServing {
        node_id,
        request_id,
        public_address,
        control_address,
        ..
    } = &action
    {
        if *node_id == 0
            || request_id.is_empty()
            || request_id.len() > 100
            || !request_id.is_ascii()
            || public_address == control_address
        {
            return failure(
                StatusCode::BAD_REQUEST,
                "invalid serving grant or request_id (1..100 ASCII bytes)",
            );
        }
    }
    replica_response(send(&web.jobs, Operation::Replica(action)).await)
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

pub(crate) async fn router(jobs: crate::DatabaseSender) -> Result<Router, Error> {
    let path = match std::env::var("ADMIN_JWT_CONFIG_FILE") {
        Ok(path) => path,
        Err(std::env::VarError::NotPresent) => return Ok(Router::new()),
        Err(error) => return Err(error.into()),
    };
    let keys: Keys = serde_json::from_slice(&protected_file(&path)?)?;
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

fn web_router(jobs: crate::DatabaseSender, keys: Keys) -> Router {
    let web = Web {
        jobs,
        keys: Arc::new(keys),
        hashing: Arc::new(tokio::sync::Semaphore::new(2)),
        attempts: Arc::new(std::sync::Mutex::new((0, 0))),
    };
    Router::new()
        .route("/login", post(login))
        .route(
            "/me",
            get(|| async { Json(serde_json::json!({"subject":"administrator:1"})) }),
        )
        .route(
            "/logout",
            post(|| async {
                (
                    [(
                        header::SET_COOKIE,
                        format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
                    )],
                    StatusCode::NO_CONTENT,
                )
            }),
        )
        .route("/inventory", get(inventory))
        .route("/status", get(status))
        .route("/replicas", get(replicas))
        .route("/replicas/reconcile", post(replica_action))
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
                "nodes":[],"meshes":[],"memberships":[],"invites":[],"tunnels":[]
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
            INSERT INTO wireguard_static_key(node_id,public_key) VALUES(2,'peer-key');
            INSERT INTO control_enrollment_results VALUES
                ('current','','f','{"Enrolled":{"node_id":1}}'),
                ('legacy','','f','{"Enrolled":{"node_id":1}}'),
                ('other','','f','{"Enrolled":{"node_id":2}}'),
                ('rejected','','f','{"Rejected":"no"}');
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
            serde_json::json!([{"id":1,"name":"mesh","auto_wireguard":true,"mtu":1420,"fec":false}])
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
            node_revocations::table
                .select(node_revocations::peer_id)
                .order(node_revocations::peer_id)
                .load::<String>(&mut conn)
                .unwrap(),
            ["current", "legacy"]
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
                    Operation::Replicas | Operation::Replica(_) | Operation::CodeRead => {
                        let _ = reply.send(Err("cluster administration not available".into()));
                        continue;
                    }
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
        assert_eq!(request(first, "GET", "replicas", &auth, "").await.0, 409);
        assert_eq!(
            request(
                second,
                "POST",
                "replicas/reconcile",
                &format!("{json}{auth}"),
                r#"{"action":"enrollment_code"}"#
            )
            .await
            .0,
            409
        );
        assert_eq!(
            request(
                second,
                "POST",
                "replicas/reconcile",
                &format!("{json}{auth}Idempotency-Key: unsupported\r\n"),
                r#"{"action":"enrollment_code"}"#
            )
            .await
            .0,
            400
        );
        assert_eq!(
            request(
                second,
                "POST",
                "replicas/reconcile",
                &auth,
                r#"{"action":"enrollment_code"}"#
            )
            .await
            .0,
            403
        );
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
                .contains("outcome unknown; retry with same key and payload")
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
