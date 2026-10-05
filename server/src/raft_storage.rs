//! Durable OpenRaft 0.9.25 storage-v2 adapter; not a running consensus service.
use std::{
    fmt::Debug,
    io::Cursor,
    ops::RangeBounds,
    pin::Pin,
    task::{Context, Poll},
};

use diesel::{
    Connection, ExpressionMethods, OptionalExtension, QueryDsl, QueryableByName, RunQueryDsl,
    SqliteConnection, sql_types::Text,
};
use openraft::{
    Entry, EntryPayload, LogId, RaftLogReader, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StorageError, StoredMembership, Vote,
    storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

openraft::declare_raft_types!(pub TypeConfig: D = Command, R = Result<Option<String>, String>, SnapshotData = SnapshotData);

// Authenticated principals are captured at ingress, never inferred from a forwarding replica.
// ponytail: trusted callers only; authenticated cluster forwarding must preserve these bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    Initialize(crate::db::InitializeCommand),
    LegacyImport(Vec<Vec<serde_json::Value>>),
    AuthorityInit(crate::cluster::AuthorityInit),
    ReplicaCode(crate::cluster::CodeRotation),
    Transport {
        active: crate::cluster::TransportCredential,
        next: crate::cluster::TransportCredential,
        complete: bool,
    },
    Admission(crate::cluster::Admission),
    RevokeReplica {
        id: u64,
        complete: bool,
    },
    Roster(cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerRoster>),
    Invite(crate::db::InviteCommand),
    // ponytail: internal committed mesh setup only; operator mesh CRUD needs authenticated ingress.
    Mesh {
        id: i32,
        name: String,
        mtu: i32,
        created_at: chrono::NaiveDateTime,
    },
    Enrollment {
        peer_id: String,
        command: crate::db::EnrollmentCommand,
    },
    Answer {
        peer_id: String,
        command: crate::db::AnswerCommand,
    },
}

const SNAPSHOT_LIMIT: usize = 16 * 1024 * 1024;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Job = Box<dyn FnOnce(&mut SqliteConnection) + Send>;

/// One bounded, serial blocking worker owns the connection. Accepted IO completes even if its
/// caller disconnects; a dead worker fails closed, never silently restarts.
#[derive(Clone)]
pub struct Store(
    tokio::sync::mpsc::Sender<Job>,
    tokio::sync::watch::Sender<()>,
);

fn storage_error(error: impl std::fmt::Display) -> StorageError<u64> {
    // Do not put secret-bearing SQL/JSON or command values in Raft diagnostics.
    let _ = error;
    StorageError::from_io_error(
        openraft::ErrorSubject::Store,
        openraft::ErrorVerb::Write,
        std::io::Error::other("SQLite Raft storage operation failed"),
    )
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type = Text)]
    value: String,
}

pub(crate) fn get<T: DeserializeOwned>(
    conn: &mut SqliteConnection,
    key: &str,
) -> Result<Option<T>, Error> {
    diesel::sql_query("SELECT value FROM raft_meta WHERE key = ?")
        .bind::<Text, _>(key)
        .get_result::<Row>(conn)
        .optional()?
        .map(|row| serde_json::from_str(&row.value).map_err(Into::into))
        .transpose()
}

fn put<T: Serialize>(conn: &mut SqliteConnection, key: &str, value: &T) -> Result<(), Error> {
    diesel::sql_query("INSERT INTO raft_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind::<Text, _>(key).bind::<Text, _>(serde_json::to_string(value)?).execute(conn)?;
    Ok(())
}

fn check_application_version(conn: &mut SqliteConnection) -> Result<(), Error> {
    let version = get::<u8>(conn, "application_version")?;
    if version == Some(cat4igp_shared::discovery::join::APPLICATION_VERSION) {
        return Ok(());
    }
    // Only standalone legacy application databases may acquire their first epoch.
    let occupied = diesel::sql_query(
        "SELECT value FROM raft_meta UNION ALL SELECT value FROM raft_logs LIMIT 1",
    )
    .load::<Row>(conn)?;
    if version.is_some() || !occupied.is_empty() {
        return Err(
            "incompatible application schema/protocol; coordinated upgrade required".into(),
        );
    }
    Ok(())
}

impl Store {
    pub(crate) fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.1.subscribe()
    }

    pub async fn open(path: String) -> Result<Self, StorageError<u64>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Job>(32);
        let (ready, opened) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let conn = (|| -> Result<SqliteConnection, Error> {
                let mut conn = SqliteConnection::establish(&path)?;
                use diesel::connection::SimpleConnection;
                conn.batch_execute("PRAGMA busy_timeout = 5000;")?;
                crate::db::migrate(&mut conn, false).map_err(std::io::Error::other)?;
                check_application_version(&mut conn)?;
                crate::db::configure_connection(&mut conn)?;
                if get::<u8>(&mut conn, "application_version")?.is_none() {
                    put(
                        &mut conn,
                        "application_version",
                        &cat4igp_shared::discovery::join::APPLICATION_VERSION,
                    )?;
                }
                Ok(conn)
            })();
            match conn {
                Ok(mut conn) => {
                    let _ = ready.send(Ok(()));
                    while let Some(job) = rx.blocking_recv() {
                        job(&mut conn);
                    }
                }
                Err(error) => {
                    let _ = ready.send(Err(storage_error(error)));
                }
            }
        });
        opened.await.map_err(storage_error)??;
        Ok(Self(tx, tokio::sync::watch::channel(()).0))
    }

    pub(crate) async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut SqliteConnection) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, StorageError<u64>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.0
            .send(Box::new(move |conn| {
                let _ = tx.send(job(conn).map_err(storage_error));
            }))
            .await
            .map_err(storage_error)?;
        rx.await.map_err(storage_error)?
    }
}

impl RaftLogReader<TypeConfig> for Store {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<u64>> {
        let start = range.start_bound().cloned();
        let end = range.end_bound().cloned();
        self.run(move |conn| {
            use std::ops::Bound::*;
            let lo = match start {
                Included(n) => Some(n),
                Excluded(n) => n.checked_add(1),
                Unbounded => Some(0),
            };
            let hi = match end {
                Included(n) => Some(n),
                Excluded(n) => n.checked_sub(1),
                Unbounded => Some(u64::MAX),
            };
            let (Some(lo), Some(hi)) = (lo, hi) else {
                return Ok(vec![]);
            };
            diesel::sql_query(
                "SELECT value FROM raft_logs WHERE idx >= ? AND idx <= ? ORDER BY idx",
            )
            .bind::<Text, _>(format!("{lo:016x}"))
            .bind::<Text, _>(format!("{hi:016x}"))
            .load::<Row>(conn)?
            .into_iter()
            .map(|r| serde_json::from_str(&r.value).map_err(Into::into))
            .collect()
        })
        .await
    }
}

impl RaftLogStorage<TypeConfig> for Store {
    type LogReader = Self;
    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<u64>> {
        self.run(|conn| {
            let purged = get(conn, "purged")?;
            let last = diesel::sql_query("SELECT value FROM raft_logs ORDER BY idx DESC LIMIT 1")
                .get_result::<Row>(conn)
                .optional()?
                .map(|r| serde_json::from_str::<Entry<TypeConfig>>(&r.value))
                .transpose()?;
            Ok(LogState {
                last_purged_log_id: purged,
                last_log_id: last.map(|e| e.log_id).or(purged),
            })
        })
        .await
    }
    async fn get_log_reader(&mut self) -> Self {
        self.clone()
    }
    async fn save_vote(&mut self, vote: &Vote<u64>) -> Result<(), StorageError<u64>> {
        let vote = *vote;
        self.run(move |conn| put(conn, "vote", &vote)).await
    }
    async fn read_vote(&mut self) -> Result<Option<Vote<u64>>, StorageError<u64>> {
        self.run(|conn| get(conn, "vote")).await
    }
    async fn save_committed(&mut self, id: Option<LogId<u64>>) -> Result<(), StorageError<u64>> {
        self.run(move |conn| put(conn, "committed", &id)).await
    }
    async fn read_committed(&mut self) -> Result<Option<LogId<u64>>, StorageError<u64>> {
        self.run(|conn| Ok(get(conn, "committed")?.flatten())).await
    }
    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let result = self.run(move |conn| conn.immediate_transaction::<_, Error, _>(|conn| {
            for entry in entries {
                diesel::sql_query("INSERT INTO raft_logs(idx, value) VALUES (?, ?) ON CONFLICT(idx) DO UPDATE SET value = excluded.value")
                    .bind::<Text, _>(format!("{:016x}", entry.log_id.index))
                    .bind::<Text, _>(serde_json::to_string(&entry)?).execute(conn)?;
            }
            Ok(())
        })).await;
        // FULL synchronous commit precedes both callback and return; no in-memory acknowledgement.
        callback.log_io_completed(if result.is_ok() {
            Ok(())
        } else {
            Err(std::io::Error::other("Raft log flush failed"))
        });
        result
    }
    async fn truncate(&mut self, id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.run(move |conn| {
            diesel::sql_query("DELETE FROM raft_logs WHERE idx >= ?")
                .bind::<Text, _>(format!("{:016x}", id.index))
                .execute(conn)?;
            Ok(())
        })
        .await
    }
    async fn purge(&mut self, id: LogId<u64>) -> Result<(), StorageError<u64>> {
        self.run(move |conn| {
            conn.immediate_transaction::<_, Error, _>(|conn| {
                diesel::sql_query("DELETE FROM raft_logs WHERE idx <= ?")
                    .bind::<Text, _>(format!("{:016x}", id.index))
                    .execute(conn)?;
                put(conn, "purged", &id)
            })
        })
        .await
    }
}

impl RaftStateMachine<TypeConfig> for Store {
    type SnapshotBuilder = Self;
    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<u64>>,
            StoredMembership<u64, openraft::BasicNode>,
        ),
        StorageError<u64>,
    > {
        self.run(|conn| {
            Ok((
                get(conn, "applied")?.flatten(),
                get(conn, "membership")?.unwrap_or_default(),
            ))
        })
        .await
    }
    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<Result<Option<String>, String>>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let result = self.run(move |conn| {
            conn.immediate_transaction::<_, Error, _>(|conn| {
                let mut responses = Vec::with_capacity(entries.len());
                for entry in entries {
                    let response = match entry.payload {
                        EntryPayload::Blank => Ok(None),
                        EntryPayload::Membership(membership) => {
                            put(
                                conn,
                                "membership",
                                &StoredMembership::new(Some(entry.log_id), membership),
                            )?;
                            Ok(None)
                        }
                        EntryPayload::Normal(Command::Initialize(command)) => {
                            crate::db::apply_initialization(conn, &command)?;
                            Ok(None)
                        }
                        EntryPayload::Normal(Command::LegacyImport(tables)) => {
                            if tables.len() != TABLES.len() || serde_json::to_vec(&tables)?.len() > 512 * 1024 {
                                return Err("invalid legacy import size".into());
                            }
                            let existing = application_tables(conn)?;
                            if existing == tables {
                                Ok(None)
                            } else if existing.iter().any(|rows| !rows.is_empty()) {
                                Err("legacy import requires empty application state".into())
                            } else {
                                insert_tables(conn, &tables)?;
                                Ok(None)
                            }
                        }
                        EntryPayload::Normal(Command::AuthorityInit(command)) => crate::cluster::apply_authority_init(conn, &command)?,
                        EntryPayload::Normal(Command::Roster(roster)) => crate::cluster::apply_roster(conn, &roster)?,
                        EntryPayload::Normal(Command::ReplicaCode(command)) => crate::cluster::apply_code_rotation(conn, &command)?,
                        EntryPayload::Normal(Command::Transport { active, next, complete }) => crate::cluster::apply_transport(conn, &active, &next, complete)?,
                        EntryPayload::Normal(Command::Admission(command)) => crate::cluster::apply_admission(conn, &command)?,
                        EntryPayload::Normal(Command::RevokeReplica { id, complete }) => {
                            let membership: StoredMembership<u64, openraft::BasicNode> = get(conn, "membership")?.unwrap_or_default();
                            if complete && membership.membership().nodes().any(|(node_id, _)| *node_id == id) {
                                Err("replica still in committed membership".into())
                            } else {
                                crate::cluster::apply_revocation(conn, id, complete)?
                            }
                        },
                        EntryPayload::Normal(Command::Invite(command)) => {
                            crate::db::apply_invite(conn, &command)?.map(Some)
                        }
                        EntryPayload::Normal(Command::Mesh { id, name, mtu, created_at }) => {
                            use crate::schema::mesh_groups::dsl;
                            if id <= 0 || name.is_empty() || name.len() > 128 || !(1280..=9000).contains(&mtu) {
                                Err("invalid mesh".into())
                            } else if let Some(existing) = dsl::mesh_groups.find(id).first::<crate::models::MeshGroup>(conn).optional()? {
                                if existing.name == name && existing.auto_wireguard && existing.auto_wireguard_mtu == mtu && existing.created_at == created_at {
                                    Ok(None)
                                } else {
                                    Err("mesh ID conflict".into())
                                }
                            } else {
                                diesel::insert_into(dsl::mesh_groups).values((dsl::id.eq(id), dsl::name.eq(name), dsl::auto_wireguard.eq(true), dsl::auto_wireguard_mtu.eq(mtu), dsl::created_at.eq(created_at))).execute(conn)?;
                                Ok(None)
                            }
                        }
                        EntryPayload::Normal(Command::Enrollment { peer_id, command }) => {
                            let key = crate::hex_decode(&command.request.client_signing_key).ok()
                                .and_then(|bytes| libp2p::identity::PublicKey::try_decode_protobuf(&bytes).ok());
                            if peer_id != command.request.client_peer_id
                                || key.is_none_or(|key| key.to_peer_id().to_string() != peer_id)
                                || !matches!(crate::hex_decode(&command.request.client_encryption_key), Ok(bytes) if bytes.len() == 32)
                            {
                                Err("invalid enrollment principal or keys".into())
                            } else {
                                let (response, _) = crate::db::apply_enrollment(conn, &command)?;
                                match response {
                                    cat4igp_shared::control::ControlResponse::Rejected(reason) => Err(reason),
                                    response => Ok(Some(serde_json::to_string(&response)?)),
                                }
                            }
                        }
                        EntryPayload::Normal(Command::Answer { peer_id, command }) => {
                            let identity = crate::db::control_identity_for_peer(conn, &peer_id).optional()?;
                            if identity.is_none_or(|identity| identity.node_id != command.node_id) {
                                Err("unknown control identity or unauthorized node".into())
                            } else {
                                let result = crate::db::apply_answer(conn, &command)?;
                                if result == "accepted" { Ok(Some(result)) } else { Err(result) }
                            }
                        }
                    };
                    put(conn, "applied", &Some(entry.log_id))?;
                    responses.push(response);
                }
                Ok(responses)
            })
        })
        .await;
        if result.is_ok() {
            self.1.send_replace(());
        }
        result
    }
    async fn get_snapshot_builder(&mut self) -> Self {
        self.clone()
    }
    async fn begin_receiving_snapshot(&mut self) -> Result<Box<SnapshotData>, StorageError<u64>> {
        Ok(Box::new(SnapshotData::default()))
    }
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, openraft::BasicNode>,
        snapshot: Box<SnapshotData>,
    ) -> Result<(), StorageError<u64>> {
        install(self, meta.clone(), snapshot.0.into_inner()).await?;
        self.1.send_replace(());
        Ok(())
    }
    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        self.run(|conn| get::<Image>(conn, "snapshot")?.map(snapshot).transpose())
            .await
    }
}

#[cfg(test)]
#[path = "raft_storage_test.rs"]
mod tests;
async fn install(
    store: &Store,
    meta: SnapshotMeta<u64, openraft::BasicNode>,
    bytes: Vec<u8>,
) -> Result<(), StorageError<u64>> {
    store.run(move |conn| {
            if bytes.len() > SNAPSHOT_LIMIT { return Err(std::io::Error::other("snapshot exceeds 16 MiB").into()); }
            let image: Image = serde_json::from_slice(&bytes)?;
            if image.version != 1 || image.application_version != cat4igp_shared::discovery::join::APPLICATION_VERSION || image.meta != meta || image.tables.len() != TABLES.len() {
                return Err(std::io::Error::other("invalid snapshot header").into());
            }
            conn.immediate_transaction::<_, Error, _>(|conn| {
                // Delete dependent rows first, and never touch Raft logs/vote/commit/purge or local settings.
                for (table, _) in TABLES.iter().rev() {
                    diesel::sql_query(format!("DELETE FROM {table}{}", filter(table))).execute(conn)?;
                }
                for ((table, columns), rows) in TABLES.iter().zip(&image.tables) {
                    let count = columns.split(',').count();
                    let values = (0..count).map(|i| format!("json_extract(value, '$[{i}]')")).collect::<Vec<_>>().join(",");
                    for row in rows {
                        if row.as_array().map(Vec::len) != Some(count) { return Err(std::io::Error::other("invalid snapshot row").into()); }
                        if *table == "settings" && !matches!(row[0].as_str(), Some("control_private_key" | "control_encryption_private_key" | "control_network_id" | "controller_admitted" | "controller_roster" | "replica_enrollment_code" | "replica_pending_admissions" | "replica_revocations" | "cluster_transport_rotation")) {
                            return Err(std::io::Error::other("replica-local setting in snapshot").into());
                        }
                        diesel::sql_query(format!("WITH row(value) AS (VALUES (?)) INSERT INTO {table} ({columns}) SELECT {values} FROM row"))
                            .bind::<Text, _>(serde_json::to_string(row)?).execute(conn)?;
                    }
                }
                put(conn, "applied", &meta.last_log_id)?;
                put(conn, "membership", &meta.last_membership)?;
                put(conn, "snapshot", &image)
            })
        }).await
}

// Explicit application allowlist: unknown settings (including future local transport keys) stay local.
const TABLES: &[(&str, &str)] = &[
    ("settings", "key,value,created_at,updated_at"),
    ("nodes", "id,name,auth_key,created_at,last_seen"),
    (
        "invites",
        "id,code,created_at,expires_at,used_count,max_uses,override_join_mesh",
    ),
    (
        "mesh_groups",
        "id,name,auto_wireguard,auto_wireguard_mtu,created_at",
    ),
    (
        "mesh_group_memberships",
        "id,mesh_group_id,node_id,created_at",
    ),
    (
        "node_control_identities",
        "node_id,peer_id,signing_key,encryption_key,topology_revision,created_at,updated_at",
    ),
    ("wireguard_static_key", "node_id,public_key,created_at"),
    (
        "wireguard_tunnels",
        "id,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,peer1_answered,peer2_answered,mtu,endpoint_ipv6,fec,faketcp,created_at,updated_at",
    ),
    (
        "control_answer_results",
        "node_id,request_id,fingerprint,result,expires_at",
    ),
    (
        "control_enrollment_results",
        "peer_id,request_id,fingerprint,result",
    ),
    ("operator_invite_results", "request_id,fingerprint,result"),
];

fn filter(table: &str) -> &'static str {
    if table == "settings" {
        " WHERE key IN ('control_private_key','control_encryption_private_key','control_network_id','controller_admitted','controller_roster','replica_enrollment_code','replica_pending_admissions','replica_revocations','cluster_transport_rotation')"
    } else {
        ""
    }
}

fn application_tables(conn: &mut SqliteConnection) -> Result<Vec<Vec<serde_json::Value>>, Error> {
    TABLES
        .iter()
        .map(|(table, columns)| {
            diesel::sql_query(format!(
                "SELECT json_array({columns}) AS value FROM {table}{} ORDER BY {}",
                filter(table),
                columns.split(',').next().unwrap()
            ))
            .load::<Row>(conn)?
            .into_iter()
            .map(|r| serde_json::from_str(&r.value).map_err(Into::into))
            .collect()
        })
        .collect()
}

fn insert_tables(
    conn: &mut SqliteConnection,
    tables: &[Vec<serde_json::Value>],
) -> Result<(), Error> {
    if tables.len() != TABLES.len() {
        return Err("invalid application tables".into());
    }
    for ((table, columns), rows) in TABLES.iter().zip(tables) {
        let count = columns.split(',').count();
        let values = (0..count)
            .map(|i| format!("json_extract(value, '$[{i}]')"))
            .collect::<Vec<_>>()
            .join(",");
        for row in rows {
            if row.as_array().map(Vec::len) != Some(count) {
                return Err("invalid application row".into());
            }
            if *table == "settings"
                && !matches!(
                    row[0].as_str(),
                    Some(
                        "control_private_key"
                            | "control_encryption_private_key"
                            | "control_network_id"
                            | "controller_admitted"
                            | "controller_roster"
                            | "replica_enrollment_code"
                            | "replica_pending_admissions"
                            | "replica_revocations"
                            | "cluster_transport_rotation"
                    )
                )
            {
                return Err("local setting in application import".into());
            }
            diesel::sql_query(format!("WITH row(value) AS (VALUES (?)) INSERT INTO {table} ({columns}) SELECT {values} FROM row"))
                .bind::<Text, _>(serde_json::to_string(row)?).execute(conn)?;
        }
    }
    Ok(())
}

// ponytail: offline current-schema check only, not quorum repair or a zero-loss restore.
// Restore learners through authenticated admission; never transplant local vote/binding/logs.
pub(crate) fn verify_recovery(
    path: &str,
    kind: &str,
    cluster: &str,
    signing: &str,
    encryption: &str,
) -> Result<String, Error> {
    use diesel::connection::SimpleConnection;
    let path = std::fs::canonicalize(path)?;
    if !path.is_file() || cluster.is_empty() {
        return Err("invalid recovery input".into());
    }
    let mut scratch = SqliteConnection::establish(":memory:")?;
    crate::db::migrate(&mut scratch, true).map_err(std::io::Error::other)?;
    let (tables, applied, membership, vote, snapshot_present) = match kind {
        "snapshot" => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&path)?
                .take((SNAPSHOT_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > SNAPSHOT_LIMIT {
                return Err("snapshot exceeds limit".into());
            }
            let image: Image = serde_json::from_slice(&bytes)?;
            if image.version != 1
                || image.application_version != cat4igp_shared::discovery::join::APPLICATION_VERSION
            {
                return Err("unsupported snapshot version".into());
            }
            (
                image.tables,
                image.meta.last_log_id,
                image.meta.last_membership,
                false,
                true,
            )
        }
        "database" => {
            // Percent-encode URI metacharacters; mode=ro must never create/migrate the source.
            let uri = path
                .to_str()
                .ok_or("invalid path")?
                .replace('%', "%25")
                .replace('?', "%3f")
                .replace('#', "%23");
            let mut conn = SqliteConnection::establish(&format!("file:{uri}?mode=ro"))?;
            conn.batch_execute("PRAGMA query_only=ON; BEGIN;")?;
            let integrity =
                diesel::sql_query("SELECT integrity_check AS value FROM pragma_integrity_check")
                    .load::<Row>(&mut conn)?;
            if integrity.len() != 1 || integrity[0].value != "ok" {
                return Err("SQLite integrity check failed".into());
            }
            crate::db::verify_schema(&mut conn).map_err(std::io::Error::other)?;
            check_application_version(&mut conn)?;
            let applied: Option<LogId<u64>> = get(&mut conn, "applied")?.flatten();
            let membership =
                get::<StoredMembership<u64, openraft::BasicNode>>(&mut conn, "membership")?
                    .unwrap_or_default();
            let vote = get::<Vote<u64>>(&mut conn, "vote")?;
            let binding = get::<(String, u64, String)>(&mut conn, "replica_binding")?;
            if applied.is_none() && binding.is_some() {
                return Err(
                    "local replica state is not a legacy backup or applied recovery point".into(),
                );
            }
            if let Some((network, id, peer)) = &binding {
                if network != cluster || *id == 0 || peer.parse::<libp2p::PeerId>().is_err() {
                    return Err("invalid local binding".into());
                }
            }
            if (applied.is_some() || vote.is_some()) && binding.is_none() {
                return Err("missing local binding".into());
            }
            let purged: Option<LogId<u64>> = get(&mut conn, "purged")?;
            let committed: Option<LogId<u64>> = get(&mut conn, "committed")?.flatten();
            if purged.is_some_and(|p| applied.is_none_or(|a| p.index > a.index)) {
                return Err("purged beyond applied".into());
            }
            let logs = diesel::sql_query(
                "SELECT json_array(idx,value) AS value FROM raft_logs ORDER BY idx",
            )
            .load::<Row>(&mut conn)?;
            let mut last = purged;
            for row in logs {
                let (idx, value): (String, String) = serde_json::from_str(&row.value)?;
                let entry: Entry<TypeConfig> = serde_json::from_str(&value)?;
                if idx != format!("{:016x}", entry.log_id.index)
                    || last.is_some_and(|p| p.index.checked_add(1) != Some(entry.log_id.index))
                {
                    return Err("invalid log sequence".into());
                }
                last = Some(entry.log_id);
            }
            if committed.is_some_and(|c| last.is_none_or(|l| c.index > l.index)) {
                return Err("commit beyond durable log".into());
            }
            let image = get::<Image>(&mut conn, "snapshot")?;
            if let Some(image) = &image {
                snapshot(Image {
                    version: image.version,
                    application_version: image.application_version,
                    meta: image.meta.clone(),
                    tables: image.tables.clone(),
                })?;
                if image.version != 1
                    || image.application_version
                        != cat4igp_shared::discovery::join::APPLICATION_VERSION
                    || image
                        .meta
                        .last_log_id
                        .is_some_and(|s| applied.is_none_or(|a| s.index > a.index))
                {
                    return Err("invalid stored snapshot".into());
                }
                let mut check = SqliteConnection::establish(":memory:")?;
                crate::db::migrate(&mut check, true).map_err(std::io::Error::other)?;
                insert_tables(&mut check, &image.tables)?;
                verify_application(&mut check, cluster, signing, encryption)?;
                verify_membership(image.meta.last_log_id, &image.meta.last_membership)?;
                if image.meta.last_log_id == applied
                    && (image.meta.last_membership != membership
                        || image.tables != application_tables(&mut conn)?)
                {
                    return Err("snapshot disagrees with application at same applied log".into());
                }
            }
            (
                application_tables(&mut conn)?,
                applied,
                membership,
                vote.is_some(),
                image.is_some(),
            )
        }
        _ => return Err("kind must be database or snapshot".into()),
    };
    insert_tables(&mut scratch, &tables)?;
    verify_application(&mut scratch, cluster, signing, encryption)?;
    verify_membership(applied, &membership)?;
    let class = if applied.is_some() {
        "raft-application"
    } else {
        "legacy-application"
    };
    if applied.is_none() && (vote || snapshot_present) {
        return Err("incomplete consensus state".into());
    }
    Ok(format!(
        "verified {class}; schema=current; identity=matches; applied_index={}; voters={}; joint={}; local_vote={vote}; snapshot={snapshot_present}; rows={:?}; OFFLINE CHECK ONLY: no quorum repair, no zero-loss guarantee",
        applied
            .map(|a| a.index.to_string())
            .unwrap_or_else(|| "none".into()),
        membership.membership().voter_ids().count(),
        membership.membership().get_joint_config().len() > 1,
        tables.iter().map(Vec::len).collect::<Vec<_>>()
    ))
}

fn verify_membership(
    applied: Option<LogId<u64>>,
    membership: &StoredMembership<u64, openraft::BasicNode>,
) -> Result<(), Error> {
    if membership
        .log_id()
        .is_some_and(|m| applied.is_none_or(|a| m.index > a.index))
        || (applied.is_some() && membership.membership().voter_ids().next().is_none())
    {
        return Err("invalid applied membership".into());
    }
    Ok(())
}

fn verify_application(
    conn: &mut SqliteConnection,
    cluster: &str,
    signing: &str,
    encryption: &str,
) -> Result<(), Error> {
    let authority = crate::cluster::read_authority(conn)?;
    if authority.network_id != cluster
        || authority.signing_key != signing
        || authority.encryption_key != encryption
    {
        return Err("backup identity mismatch".into());
    }
    if let Some(roster) = &authority.roster {
        let pin = libp2p::identity::PublicKey::try_decode_protobuf(&crate::hex_decode(signing)?)?;
        // Historical authenticity, not current lease readiness.
        roster.validate(&pin, cluster, 0, roster.body.issued_at_ms)?;
    }
    for row in diesel::sql_query("SELECT json_array(peer_id,request_id,fingerprint,result) AS value FROM control_enrollment_results").load::<Row>(conn)? {
        let (peer, id, fingerprint, result): (String, String, String, String) = serde_json::from_str(&row.value)?;
        let request: cat4igp_shared::control::EnrollmentRequest = serde_json::from_str(&fingerprint)?;
        let response: cat4igp_shared::control::ControlResponse = serde_json::from_str(&result)?;
        if request.client_peer_id != peer || request.request_id != id { return Err("invalid enrollment dedup".into()); }
        match response {
            cat4igp_shared::control::ControlResponse::Enrolled(response) => {
                let saved = crate::db::control_identity_for_peer(conn, &peer)?;
                if response.network_id != cluster || response.controller_signing_key != signing
                    || response.controller_encryption_key != encryption || saved.node_id != response.node_id
                    || saved.signing_key != request.client_signing_key || saved.encryption_key != request.client_encryption_key {
                    return Err("dedup identity mismatch".into());
                }
            }
            cat4igp_shared::control::ControlResponse::Rejected(_) => (),
            _ => return Err("invalid enrollment result variant".into()),
        }
    }
    for row in diesel::sql_query("SELECT result AS value FROM operator_invite_results")
        .load::<Row>(conn)?
    {
        let _: Result<String, String> = serde_json::from_str(&row.value)?;
    }
    for row in diesel::sql_query("SELECT fingerprint AS value FROM operator_invite_results")
        .load::<Row>(conn)?
    {
        let _: (Option<chrono::NaiveDateTime>, Option<i32>, Option<i32>) =
            serde_json::from_str(&row.value)?;
    }
    for row in
        diesel::sql_query("SELECT result AS value FROM control_answer_results").load::<Row>(conn)?
    {
        if !matches!(
            row.value.as_str(),
            "accepted"
                | "invalid decline type"
                | "invalid tunnel endpoint"
                | "unknown tunnel or unauthorized peer"
        ) {
            return Err("invalid answer result".into());
        }
    }
    for row in diesel::sql_query("SELECT fingerprint AS value FROM control_answer_results")
        .load::<Row>(conn)?
    {
        let _: cat4igp_shared::control::TunnelAnswer = serde_json::from_str(&row.value)?;
    }
    Ok(())
}

// ponytail: offline single-voter cutover, 512 KiB committed import; use staged snapshot
// seeding for larger databases, never import replica-local votes/logs or rotate logical pins.
pub(crate) fn legacy_backup(
    source: &str,
    backup: &str,
    cluster: &str,
) -> Result<Vec<Vec<serde_json::Value>>, Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let source_path = std::fs::canonicalize(source)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(backup)?;
    let mut original = SqliteConnection::establish(&format!(
        "file:{}?mode=ro",
        source_path.to_str().ok_or("invalid source path")?
    ))?;
    diesel::sql_query("VACUUM INTO ?")
        .bind::<Text, _>(backup)
        .execute(&mut original)?;
    file.sync_all()?;
    std::fs::File::open(
        std::path::Path::new(backup)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new(".")),
    )?
    .sync_all()?;
    let mut conn = SqliteConnection::establish(backup)?;
    crate::db::configure_connection(&mut conn)?;
    crate::db::migrate(&mut conn, true).map_err(std::io::Error::other)?;
    let used = diesel::sql_query(
        "SELECT value FROM raft_meta UNION ALL SELECT value FROM raft_logs LIMIT 1",
    )
    .load::<Row>(&mut conn)?;
    if !used.is_empty() {
        return Err("legacy source contains consensus state".into());
    }
    for name in [
        "controller_admitted",
        "controller_roster",
        "replica_pending_admissions",
        "replica_revocations",
        "replica_enrollment_code",
        "cluster_transport_rotation",
    ] {
        if crate::db::get_setting(&mut conn, name)
            .optional()?
            .is_some()
        {
            return Err("legacy source contains cluster authority".into());
        }
    }
    let authority = crate::cluster::read_authority(&mut conn)?;
    if authority.network_id != cluster {
        return Err("legacy network ID must equal cluster ID".into());
    }
    let tables = application_tables(&mut conn)?;
    if serde_json::to_vec(&tables)?.len() > 512 * 1024 {
        return Err("legacy import exceeds 512 KiB".into());
    }
    Ok(tables)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    version: u8,
    application_version: u8,
    meta: SnapshotMeta<u64, openraft::BasicNode>,
    tables: Vec<Vec<serde_json::Value>>,
}

fn snapshot(image: Image) -> Result<Snapshot<TypeConfig>, Error> {
    let bytes = serde_json::to_vec(&image)?;
    if bytes.len() > SNAPSHOT_LIMIT {
        return Err(std::io::Error::other("snapshot exceeds 16 MiB").into());
    }
    Ok(Snapshot {
        meta: image.meta,
        snapshot: Box::new(SnapshotData(Cursor::new(bytes))),
    })
}

impl RaftSnapshotBuilder<TypeConfig> for Store {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        self.run(|conn| {
            conn.immediate_transaction::<_, Error, _>(|conn| {
                let mut tables = Vec::with_capacity(TABLES.len());
                let mut size = 0;
                for (table, columns) in TABLES {
                    let rows = diesel::sql_query(format!(
                        "SELECT json_array({columns}) AS value FROM {table}{} ORDER BY {}",
                        filter(table),
                        columns.split(',').next().unwrap()
                    ))
                    .load::<Row>(conn)?;
                    let mut values = Vec::with_capacity(rows.len());
                    for row in rows {
                        size += row.value.len();
                        if size > SNAPSHOT_LIMIT {
                            return Err(std::io::Error::other("snapshot exceeds 16 MiB").into());
                        }
                        values.push(serde_json::from_str(&row.value)?);
                    }
                    tables.push(values);
                }
                let image = Image {
                    version: 1,
                    application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
                    meta: SnapshotMeta {
                        last_log_id: get(conn, "applied")?.flatten(),
                        last_membership: get(conn, "membership")?.unwrap_or_default(),
                        snapshot_id: uuid::Uuid::new_v4().to_string(),
                    },
                    tables,
                };
                let result = snapshot(Image {
                    version: image.version,
                    application_version: image.application_version,
                    meta: image.meta.clone(),
                    tables: image.tables.clone(),
                })?;
                put(conn, "snapshot", &image)?;
                Ok(result)
            })
        })
        .await
    }
}

// ponytail: logical JSON snapshots capped at 16 MiB, coordinated schema upgrades only.
// Replace with bounded streaming files when application state approaches this limit.
#[derive(Default, Debug)]
pub struct SnapshotData(Cursor<Vec<u8>>);
impl AsyncRead for SnapshotData {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncSeek for SnapshotData {
    fn start_seek(mut self: Pin<&mut Self>, position: std::io::SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.0).start_seek(position)
    }
    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.0).poll_complete(cx)
    }
}
impl AsyncWrite for SnapshotData {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self
            .0
            .position()
            .checked_add(buf.len() as u64)
            .is_none_or(|n| n > SNAPSHOT_LIMIT as u64)
        {
            return Poll::Ready(Err(std::io::Error::other("snapshot exceeds 16 MiB")));
        }
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
