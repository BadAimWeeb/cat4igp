//! Opt-in static cluster with committed any-replica ingress.
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use diesel::{Connection, ExpressionMethods, RunQueryDsl};
use openraft::{BasicNode, Raft};
use serde::{Deserialize, Serialize};

use crate::{
    raft_network::{Binding, Network},
    raft_storage::{Command, Store, TypeConfig},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    cluster_id: String,
    node_id: u64,
    mode: Mode,
    identity_file: String,
    listen: libp2p::Multiaddr,
    replicas: BTreeMap<u64, Replica>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    learner: Option<Replica>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster_psk: Option<String>,
    #[serde(default)]
    transport_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_import: Option<LegacyImport>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyImport {
    source: String,
    backup: String,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Initialize,
    Recover,
    Join,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replica {
    peer_id: libp2p::PeerId,
    address: libp2p::Multiaddr,
}

type Node = Raft<TypeConfig>;
const DEADLINE: Duration = Duration::from_secs(10);

use cat4igp_shared::discovery::{ControllerRoster, Signed};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityInit {
    pub identity: crate::db::InitializeCommand,
    pub admitted: BTreeMap<u64, libp2p::PeerId>,
}

pub(crate) fn new_authority(
    network_id: String,
    admitted: BTreeMap<u64, libp2p::PeerId>,
) -> AuthorityInit {
    AuthorityInit {
        identity: crate::db::InitializeCommand {
            signing_private_key: crate::hex_encode(
                &libp2p::identity::Keypair::generate_ed25519()
                    .to_protobuf_encoding()
                    .expect("ed25519 encoding"),
            ),
            encryption_private_key: crate::hex_encode(
                &x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng).to_bytes(),
            ),
            network_id,
            applied_at: chrono::Utc::now().naive_utc(),
        },
        admitted,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Authority {
    pub signing_key: String,
    pub encryption_key: String,
    pub network_id: String,
    pub roster: Option<Signed<ControllerRoster>>,
}

fn setting(
    conn: &mut diesel::SqliteConnection,
    name: &str,
    content: &str,
) -> Result<(), diesel::result::Error> {
    use crate::schema::settings::dsl::*;
    diesel::insert_into(settings)
        .values((
            key.eq(name),
            value.eq(content),
            created_at.eq(chrono::NaiveDateTime::default()),
            updated_at.eq(chrono::NaiveDateTime::default()),
        ))
        .on_conflict(key)
        .do_update()
        .set(value.eq(content))
        .execute(conn)?;
    Ok(())
}

const CODE_LIFETIME_MS: i64 = 15 * 60 * 1000;
const CODE_GRACE_MS: i64 = 2 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransportCredential {
    cluster_id: String,
    generation: u64,
    fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TransportRotation {
    active: TransportCredential,
    next: Option<TransportCredential>,
}

fn credential(
    cluster: &str,
    generation: u64,
    psk: libp2p::pnet::PreSharedKey,
) -> TransportCredential {
    TransportCredential {
        cluster_id: cluster.into(),
        generation,
        fingerprint: cat4igp_shared::discovery::join::transport_fingerprint(psk),
    }
}

fn read_transport(
    conn: &mut diesel::SqliteConnection,
) -> Result<Option<TransportRotation>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    crate::db::get_setting(conn, "cluster_transport_rotation")
        .optional()?
        .map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}

pub(crate) fn apply_transport(
    conn: &mut diesel::SqliteConnection,
    active: &TransportCredential,
    next: &TransportCredential,
    complete: bool,
) -> Result<Result<Option<String>, String>, Box<dyn std::error::Error + Send + Sync>> {
    let cluster = crate::db::get_setting(conn, "control_network_id")?;
    if active.cluster_id != cluster
        || next.cluster_id != cluster
        || active.generation.checked_add(1) != Some(next.generation)
        || active.fingerprint == next.fingerprint
        || [active, next].iter().any(|c| {
            c.fingerprint.len() != 64
                || !c
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Ok(Err("invalid transport credential transition".into()));
    }
    let mut state = read_transport(conn)?.unwrap_or(TransportRotation {
        active: active.clone(),
        next: None,
    });
    if complete && state.active == *next && state.next.is_none() {
        return Ok(Ok(None));
    }
    if state.active != *active
        || state.next.as_ref().is_some_and(|n| n != next)
        || (complete && state.next.as_ref() != Some(next))
    {
        return Ok(Err("conflicting transport credential transition".into()));
    }
    if complete {
        state.active = next.clone();
        state.next = None;
    } else {
        state.next = Some(next.clone());
    }
    setting(
        conn,
        "cluster_transport_rotation",
        &serde_json::to_string(&state)?,
    )?;
    Ok(Ok(None))
}

fn validate_transport(
    conn: &mut diesel::SqliteConnection,
    selected: &TransportCredential,
    fresh_learner: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(state) = read_transport(conn)? {
        if &state.active != selected && state.next.as_ref() != Some(selected) {
            return Err("transport credential does not match applied cluster rotation".into());
        }
    } else if selected.generation != 0 && !fresh_learner {
        return Err("transport generation not applied locally".into());
    }
    if let Some(previous) =
        crate::raft_storage::get::<TransportCredential>(conn, "transport_credential")?
    {
        if previous.cluster_id != selected.cluster_id
            || previous.generation > selected.generation
            || (previous.generation == selected.generation && previous != *selected)
        {
            return Err("stale or conflicting local transport credential".into());
        }
    }
    diesel::sql_query("INSERT INTO raft_meta(key,value) VALUES('transport_credential', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind::<diesel::sql_types::Text,_>(serde_json::to_string(selected)?).execute(conn)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admission {
    pub source: libp2p::PeerId,
    pub request: cat4igp_shared::discovery::join::Request,
    pub at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub peer: libp2p::PeerId,
    pub complete: bool,
}

pub(crate) fn read_revocations(
    conn: &mut diesel::SqliteConnection,
) -> Result<BTreeMap<u64, Revocation>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    Ok(crate::db::get_setting(conn, "replica_revocations")
        .optional()?
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default())
}

pub(crate) fn apply_revocation(
    conn: &mut diesel::SqliteConnection,
    id: u64,
    complete: bool,
) -> Result<Result<Option<String>, String>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    let mut revoked = read_revocations(conn)?;
    if let Some(saved) = revoked.get_mut(&id) {
        saved.complete |= complete;
    } else {
        if complete {
            return Ok(Err("revocation not started".into()));
        }
        let admitted: BTreeMap<u64, libp2p::PeerId> =
            serde_json::from_str(&crate::db::get_setting(conn, "controller_admitted")?)?;
        let pending: Vec<Admission> = crate::db::get_setting(conn, "replica_pending_admissions")
            .optional()?
            .map(|s| serde_json::from_str(&s))
            .transpose()?
            .unwrap_or_default();
        let Some(peer) = admitted.get(&id).copied().or_else(|| {
            pending
                .iter()
                .find(|a| a.request.node_id == id)
                .map(|a| a.source)
        }) else {
            return Ok(Err("unknown replica".into()));
        };
        // Permanent identity tombstones are bounded by the lifetime admission ceiling.
        if revoked.len() >= 64 {
            return Ok(Err("revocation capacity reached".into()));
        }
        let authority = read_authority(conn)?;
        if let Some(mut roster) = authority.roster.map(|r| r.body) {
            if roster.controllers.iter().any(|e| e.peer_id == peer) {
                roster.controllers.retain(|e| e.peer_id != peer);
                roster.discovery_endpoints.retain(|e| e.peer_id != peer);
                if roster.controllers.is_empty() {
                    return Ok(Err("cannot remove last serving replica".into()));
                }
                let Some(revision) = roster.revision.checked_add(1) else {
                    return Ok(Err("roster revision exhausted".into()));
                };
                roster.revision = revision;
                let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(
                    &crate::db::get_setting(conn, "control_private_key")?,
                )?)?;
                let signed = roster.sign(&key)?;
                setting(conn, "controller_roster", &serde_json::to_string(&signed)?)?;
            }
        }
        revoked.insert(
            id,
            Revocation {
                peer,
                complete: false,
            },
        );
    }
    setting(
        conn,
        "replica_revocations",
        &serde_json::to_string(&revoked)?,
    )?;
    Ok(Ok(None))
}

pub(crate) fn apply_admission(
    conn: &mut diesel::SqliteConnection,
    command: &Admission,
) -> Result<Result<Option<String>, String>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    let request = &command.request;
    let cluster = crate::db::get_setting(conn, "control_network_id")?;
    if request.validate(command.source, &cluster).is_err() || command.at_ms < 0 {
        return Ok(Err("invalid replica join".into()));
    }
    if read_revocations(conn)?
        .iter()
        .any(|(id, r)| *id == request.node_id || r.peer == command.source)
    {
        return Ok(Err("replica permanently revoked".into()));
    }
    let mut pending: Vec<Admission> = crate::db::get_setting(conn, "replica_pending_admissions")
        .optional()?
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default();
    for saved in &pending {
        if saved.request.request_id == request.request_id {
            return Ok(
                if saved.source == command.source && saved.request == *request {
                    Ok(None)
                } else {
                    Err("conflicting admission retry".into())
                },
            );
        }
        let mut saved_address = saved.request.address.clone();
        let mut proposed_address = request.address.clone();
        saved_address.pop();
        proposed_address.pop();
        if saved.source == command.source
            || saved.request.node_id == request.node_id
            || saved_address == proposed_address
        {
            return Ok(Err("admission binding collision".into()));
        }
    }
    let admitted: BTreeMap<u64, libp2p::PeerId> =
        serde_json::from_str(&crate::db::get_setting(conn, "controller_admitted")?)?;
    if admitted.contains_key(&request.node_id) || admitted.values().any(|p| *p == command.source) {
        return Ok(Err("admitted binding collision".into()));
    }
    if !read_code(conn)?.is_some_and(|state| valid_code(&state, &request.code, command.at_ms)) {
        return Ok(Err("invalid or expired replica code".into()));
    }
    // ponytail: 64 durable pending bindings, no membership/secrets; reconcile transport
    // authorization atomically with learner recovery before calling add_learner.
    if pending.len() + admitted.len() >= 64 {
        return Ok(Err("admission capacity reached".into()));
    }
    pending.push(command.clone());
    setting(
        conn,
        "replica_pending_admissions",
        &serde_json::to_string(&pending)?,
    )?;
    Ok(Ok(None))
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct ReplicaCode {
    generation: u64,
    code: String,
    activated_at_ms: i64,
    expires_at_ms: i64,
    previous: Option<(String, i64)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CodeRotation {
    expected_generation: u64,
    code: String,
    activated_at_ms: i64,
    expires_at_ms: i64,
}

impl std::fmt::Debug for CodeRotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodeRotation([redacted])")
    }
}

impl std::fmt::Debug for ReplicaCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplicaCode([redacted])")
    }
}

fn read_code(
    conn: &mut diesel::SqliteConnection,
) -> Result<Option<ReplicaCode>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    Ok(crate::db::get_setting(conn, "replica_enrollment_code")
        .optional()?
        .map(|s| serde_json::from_str(&s))
        .transpose()?)
}

pub(crate) fn apply_code_rotation(
    conn: &mut diesel::SqliteConnection,
    command: &CodeRotation,
) -> Result<Result<Option<String>, String>, Box<dyn std::error::Error + Send + Sync>> {
    let current = read_code(conn)?;
    let generation = current.as_ref().map_or(0, |c| c.generation);
    // Generation CAS is the retry identity: a lost reply must not rotate twice.
    if command.expected_generation.checked_add(1) == Some(generation) {
        return Ok(Ok(None));
    }
    if generation != command.expected_generation
        || generation == u64::MAX
        || command.code.len() != 64
        || !command
            .code
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || command.activated_at_ms < 0
        || command.activated_at_ms.checked_add(CODE_LIFETIME_MS) != Some(command.expires_at_ms)
        || current
            .as_ref()
            .is_some_and(|c| command.activated_at_ms < c.activated_at_ms || command.code == c.code)
    {
        return Ok(Err("invalid rotation or generation conflict".into()));
    }
    let previous = current.map(|c| {
        (
            c.code,
            c.expires_at_ms
                .min(command.activated_at_ms)
                .saturating_add(CODE_GRACE_MS),
        )
    });
    let next = ReplicaCode {
        generation: generation + 1,
        code: command.code.clone(),
        activated_at_ms: command.activated_at_ms,
        expires_at_ms: command.expires_at_ms,
        previous,
    };
    setting(
        conn,
        "replica_enrollment_code",
        &serde_json::to_string(&next)?,
    )?;
    Ok(Ok(None))
}

fn valid_code(state: &ReplicaCode, supplied: &str, now: i64) -> bool {
    use subtle::ConstantTimeEq;
    if supplied.len() != 64 || now < state.activated_at_ms {
        return false;
    }
    let current = state.code.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() == 1;
    let (previous, deadline) = state
        .previous
        .as_ref()
        .map(|(c, t)| (c.as_str(), *t))
        .unwrap_or((
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
        ));
    let previous = previous.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() == 1;
    (current && now < state.expires_at_ms) | (previous && now < deadline)
}

pub(crate) fn apply_authority_init(
    conn: &mut diesel::SqliteConnection,
    init: &AuthorityInit,
) -> Result<Result<Option<String>, String>, diesel::result::Error> {
    use diesel::OptionalExtension;
    if crate::db::get_setting(conn, "controller_admitted")
        .optional()?
        .is_some()
    {
        return Ok(Err("controller authority already initialized".into()));
    }
    if init.admitted.is_empty()
        || init.admitted.len() > 64
        || init.admitted.contains_key(&0)
        || init
            .admitted
            .values()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != init.admitted.len()
        || init.identity.network_id.len() > 64
    {
        return Ok(Err("invalid admitted bindings".into()));
    }
    crate::db::apply_initialization(conn, &init.identity)?;
    setting(
        conn,
        "controller_admitted",
        &serde_json::to_string(&init.admitted).unwrap(),
    )?;
    Ok(Ok(None))
}

pub(crate) fn read_authority(
    conn: &mut diesel::SqliteConnection,
) -> Result<Authority, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::OptionalExtension;
    let private = crate::hex_decode(&crate::db::get_setting(conn, "control_private_key")?)?;
    let key = libp2p::identity::Keypair::from_protobuf_encoding(&private)?;
    let secret: [u8; 32] = crate::hex_decode(&crate::db::get_setting(
        conn,
        "control_encryption_private_key",
    )?)?
    .try_into()
    .map_err(|_| "invalid encryption key")?;
    Ok(Authority {
        signing_key: crate::hex_encode(&key.public().encode_protobuf()),
        encryption_key: crate::hex_encode(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).as_bytes(),
        ),
        network_id: crate::db::get_setting(conn, "control_network_id")?,
        roster: crate::db::get_setting(conn, "controller_roster")
            .optional()?
            .map(|s| serde_json::from_str(&s))
            .transpose()?,
    })
}

fn check_bindings(
    conn: &mut diesel::SqliteConnection,
    expected: &BTreeMap<u64, libp2p::PeerId>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let saved: BTreeMap<u64, libp2p::PeerId> =
        serde_json::from_str(&crate::db::get_setting(conn, "controller_admitted")?)?;
    if &saved != expected {
        return Err("configured bindings differ from committed authority".into());
    }
    Ok(())
}

const ROSTER_RENEW_BEFORE_MS: i64 = 60_000;
const ROSTER_RENEW_LIFETIME_MS: i64 = 240_000;

fn renewed_roster(previous: &ControllerRoster, now: i64) -> Option<ControllerRoster> {
    // ponytail: trusted synchronized UTC, fixed four-minute lease/one-minute lead.
    // Backwards before issuance fails closed; add committed clock policy for skew handling.
    if now < previous.issued_at_ms
        || now
            < previous
                .expires_at_ms
                .saturating_sub(ROSTER_RENEW_BEFORE_MS)
    {
        return None;
    }
    let expires_at_ms = now.checked_add(ROSTER_RENEW_LIFETIME_MS)?;
    if expires_at_ms <= previous.expires_at_ms {
        return None;
    }
    Some(ControllerRoster {
        revision: previous.revision.checked_add(1)?,
        issued_at_ms: now,
        expires_at_ms,
        ..previous.clone()
    })
}

pub(crate) fn apply_roster(
    conn: &mut diesel::SqliteConnection,
    roster: &Signed<ControllerRoster>,
) -> Result<Result<Option<String>, String>, Box<dyn std::error::Error + Send + Sync>> {
    let authority = read_authority(conn)?;
    let mut admitted: BTreeMap<u64, libp2p::PeerId> =
        serde_json::from_str(&crate::db::get_setting(conn, "controller_admitted")?)?;
    use diesel::OptionalExtension;
    let pending: Vec<Admission> = crate::db::get_setting(conn, "replica_pending_admissions")
        .optional()?
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default();
    let membership: openraft::StoredMembership<u64, BasicNode> =
        crate::raft_storage::get(conn, "membership")?.unwrap_or_default();
    for admission in pending {
        if membership.membership().get_joint_config().len() == 1
            && membership
                .membership()
                .voter_ids()
                .any(|id| id == admission.request.node_id)
        {
            admitted.insert(admission.request.node_id, admission.source);
        }
    }
    let pin = libp2p::identity::PublicKey::try_decode_protobuf(&crate::hex_decode(
        &authority.signing_key,
    )?)?;
    // Replay uses the committed issue time, not replica clocks. Ingress checks freshness.
    if let Err(error) = roster.validate(&pin, &authority.network_id, 1, roster.body.issued_at_ms) {
        return Ok(Err(error.into()));
    }
    if roster
        .body
        .controllers
        .iter()
        .any(|e| !admitted.values().any(|p| *p == e.peer_id))
    {
        return Ok(Err("roster peer is not admitted".into()));
    }
    let revoked = read_revocations(conn)?;
    if roster
        .body
        .controllers
        .iter()
        .any(|e| revoked.values().any(|r| r.peer == e.peer_id))
    {
        return Ok(Err("roster peer revoked".into()));
    }
    let encoded = cat4igp_shared::discovery::encode(roster)?;
    if let Some(previous) = authority.roster {
        if cat4igp_shared::discovery::encode(&previous)? == encoded {
            return Ok(Ok(None));
        }
        if roster.body.revision <= previous.body.revision
            || roster.body.issued_at_ms < previous.body.issued_at_ms
            || roster.body.expires_at_ms <= previous.body.expires_at_ms
        {
            return Ok(Err("roster revision/time rollback or substitution".into()));
        }
    }
    setting(conn, "controller_roster", std::str::from_utf8(&encoded)?)?;
    Ok(Ok(None))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Operation {
    AffectedSnapshots {
        principal: libp2p::PeerId,
        serving: libp2p::PeerId,
        envelope: cat4igp_shared::control::EncryptedEnvelope,
    },
    Client {
        principal: libp2p::PeerId,
        serving: libp2p::PeerId,
        request: cat4igp_shared::control::ControlRequest,
    },
    Ready,
    Authority,
    Discovery {
        query: cat4igp_shared::discovery::FindControllers,
        source: libp2p::PeerId,
        serving: libp2p::PeerId,
    },
    InitializeAuthority,
    ReplicaCode {
        rotate_generation: Option<u64>,
    },
    // Admitted-only prerequisite, never an admission or membership grant.
    VerifyReplicaCode(String),
    ActivateLearner(u64),
    PromoteLearner(u64),
    RevokeReplica(u64),
    Join {
        source: libp2p::PeerId,
        request: cat4igp_shared::discovery::join::Request,
    },
    Roster(ControllerRoster),
    GrantServing(ServingGrant),
    RenewRoster,
    PrepareTransport(TransportCredential),
    CompleteTransport,
    Invite {
        request_id: String,
        expires_at: Option<chrono::NaiveDateTime>,
        max_uses: Option<i32>,
        join_mesh: Option<i32>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServingGrant {
    node_id: u64,
    // ponytail: operator-attested public/private listener binding to the admitted Noise
    // identity, not reachability proof; add authenticated probes before automatic relocation.
    public_address: libp2p::Multiaddr,
    control_address: libp2p::Multiaddr,
}

impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Operation([redacted])")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Outcome {
    AffectedSnapshots(Vec<cat4igp_shared::control::EncryptedEnvelope>),
    Client(cat4igp_shared::control::ControlResponse),
    Ready,
    Authority(Result<Authority, String>),
    Discovery(Result<Signed<cat4igp_shared::discovery::ControllerAvailable>, String>),
    Roster(Result<(), String>),
    ReplicaCode(Result<ReplicaCode, String>),
    VerifiedReplicaCode(bool),
    Learner(Result<(), String>),
    Promotion(Result<(), String>),
    Revocation(Result<(), String>),
    Join(cat4igp_shared::discovery::join::Response),
    Invite(Result<String, String>),
    Redirect(u64),
    Unavailable,
    Transport(Result<TransportRotation, String>),
}

#[derive(Clone)]
pub(crate) struct Service {
    _attachment: tokio::sync::watch::Sender<Option<Node>>,
    node: Node,
    store: Store,
    network: Option<Network>,
    admitted: BTreeMap<u64, libp2p::PeerId>,
    cluster_id: String,
    allocation: Arc<tokio::sync::Mutex<()>>,
    cluster_psk: libp2p::pnet::PreSharedKey,
    transport_credential: TransportCredential,
    #[cfg(test)]
    interrupt_revocation: Arc<std::sync::atomic::AtomicBool>,
}

impl Service {
    pub(crate) async fn local(&self, operation: Operation) -> Outcome {
        if let Operation::Invite { request_id, .. } = &operation {
            if request_id.is_empty() || request_id.len() > 128 || !request_id.is_ascii() {
                return Outcome::Invite(Err("invalid request ID".into()));
            }
        }
        let metrics = self.node.metrics().borrow().clone();
        if metrics.current_leader != Some(metrics.id) {
            return metrics
                .current_leader
                .map(Outcome::Redirect)
                .unwrap_or(Outcome::Unavailable);
        }
        let service = self.clone();
        let Ok(guard) = service.allocation.clone().try_lock_owned() else {
            return Outcome::Unavailable;
        };
        // Accepted writes outlive response cancellation and keep the allocation lock until
        // OpenRaft resolves them. Never reuse a locally selected ID while a write is pending.
        tokio::spawn(async move {
            let _guard = guard;
            let operation = if let Operation::GrantServing(grant) = operation {
                if service.node.ensure_linearizable().await.is_err() {
                    return Outcome::Unavailable;
                }
                let metrics = service.node.metrics().borrow().clone();
                let membership = metrics.membership_config.membership();
                if membership.get_joint_config().len() != 1
                    || !membership.voter_ids().any(|id| id == grant.node_id)
                {
                    return Outcome::Roster(Err("serving requires a committed voter".into()));
                }
                let matched = if grant.node_id == metrics.id {
                    metrics.last_applied
                } else {
                    metrics
                        .replication
                        .as_ref()
                        .and_then(|r| r.get(&grant.node_id))
                        .copied()
                        .flatten()
                };
                if matched.is_none() || matched < metrics.last_applied {
                    return Outcome::Roster(Err("serving voter has not caught up".into()));
                }
                match service
                    .store
                    .run(move |conn| {
                        use diesel::OptionalExtension;
                        if read_revocations(conn)?.contains_key(&grant.node_id) {
                            return Err("replica revoked".into());
                        }
                        let admitted: BTreeMap<u64, libp2p::PeerId> = serde_json::from_str(
                            &crate::db::get_setting(conn, "controller_admitted")?,
                        )?;
                        let pending: Vec<Admission> =
                            crate::db::get_setting(conn, "replica_pending_admissions")
                                .optional()?
                                .map(|s| serde_json::from_str(&s))
                                .transpose()?
                                .unwrap_or_default();
                        let peer = admitted
                            .get(&grant.node_id)
                            .copied()
                            .or_else(|| {
                                pending
                                    .iter()
                                    .find(|a| a.request.node_id == grant.node_id)
                                    .map(|a| a.source)
                            })
                            .ok_or("no committed admission")?;
                        let endpoint = cat4igp_shared::discovery::ControllerEndpoint {
                            peer_id: peer,
                            addresses: vec![
                                grant.public_address.clone(),
                                grant.control_address.clone(),
                            ],
                        };
                        endpoint.validate()?;
                        let public = cat4igp_shared::discovery::ControllerEndpoint {
                            peer_id: peer,
                            addresses: vec![grant.public_address.clone()],
                        };
                        public.validate()?;
                        if grant.public_address == grant.control_address {
                            return Err(
                                "public discovery and private control listeners must differ".into(),
                            );
                        }
                        let authority = read_authority(conn)?;
                        let mut roster = authority
                            .roster
                            .ok_or("initialize serving roster first")?
                            .body;
                        if let Some(existing) =
                            roster.controllers.iter().find(|e| e.peer_id == peer)
                        {
                            if existing != &endpoint
                                || !roster.discovery_endpoints.contains(&public)
                            {
                                return Err("serving endpoint conflict".into());
                            }
                            return Ok(roster);
                        }
                        let now = chrono::Utc::now()
                            .timestamp_millis()
                            .max(roster.issued_at_ms);
                        roster.revision =
                            roster.revision.checked_add(1).ok_or("revision exhausted")?;
                        roster.issued_at_ms = now;
                        roster.expires_at_ms = now
                            .checked_add(ROSTER_RENEW_LIFETIME_MS)
                            .ok_or("lease exhausted")?
                            .max(
                                roster
                                    .expires_at_ms
                                    .checked_add(1)
                                    .ok_or("lease exhausted")?,
                            );
                        roster.controllers.push(endpoint);
                        roster.discovery_endpoints.push(public);
                        Ok(roster)
                    })
                    .await
                {
                    Ok(body) => Operation::Roster(body),
                    Err(_) => return Outcome::Roster(Err("invalid serving grant".into())),
                }
            } else {
                operation
            };
            match operation {
                Operation::PrepareTransport(next) => {
                    let active = service.transport_credential.clone();
                    match service
                        .node
                        .client_write(Command::Transport {
                            active,
                            next,
                            complete: false,
                        })
                        .await
                    {
                        Ok(reply) if reply.data.is_ok() => (),
                        Ok(reply) => return Outcome::Transport(Err(reply.data.unwrap_err())),
                        Err(_) => return Outcome::Unavailable,
                    }
                    match service
                        .store
                        .run(|conn| read_transport(conn)?.ok_or("missing rotation".into()))
                        .await
                    {
                        Ok(state) => Outcome::Transport(Ok(state)),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::CompleteTransport => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let Ok(Some(state)) = service.store.run(read_transport).await else {
                        return Outcome::Unavailable;
                    };
                    let Some(next) = state.next.clone() else {
                        if state.active != service.transport_credential {
                            return Outcome::Transport(Err(
                                "runtime transport generation is stale".into(),
                            ));
                        }
                        return Outcome::Transport(Ok(state));
                    };
                    if next != service.transport_credential {
                        return Outcome::Transport(Err(
                            "restart with prepared generation before completion".into(),
                        ));
                    }
                    // ponytail: coordinated stop-all maintenance, not hot switching. A new-key
                    // quorum can complete; operators must restart ALL replicas before reopening.
                    match service
                        .node
                        .client_write(Command::Transport {
                            active: state.active,
                            next,
                            complete: true,
                        })
                        .await
                    {
                        Ok(reply) if reply.data.is_ok() => match service
                            .store
                            .run(|conn| read_transport(conn)?.ok_or("missing rotation".into()))
                            .await
                        {
                            Ok(state) => Outcome::Transport(Ok(state)),
                            Err(_) => Outcome::Unavailable,
                        },
                        Ok(reply) => Outcome::Transport(Err(reply.data.unwrap_err())),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::GrantServing(_) => unreachable!(),
                Operation::RevokeReplica(id) => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let metrics = service.node.metrics().borrow().clone();
                    let membership = metrics.membership_config.membership();
                    if id == metrics.id
                        || membership
                            .get_joint_config()
                            .iter()
                            .any(|v| v.contains(&id) && v.len() <= 1)
                    {
                        return Outcome::Revocation(Err(
                            "self or last-voter removal unsupported".into()
                        ));
                    }
                    match service
                        .store
                        .run(move |conn| {
                            Ok(read_revocations(conn)?.get(&id).is_some_and(|r| r.complete))
                        })
                        .await
                    {
                        Ok(true) => return Outcome::Revocation(Ok(())),
                        Ok(false) => (),
                        Err(_) => return Outcome::Unavailable,
                    }
                    // Stage one withdraws serving rights and blocks all join/credential retries,
                    // but keeps consensus transport alive until native safe removal commits.
                    match service
                        .node
                        .client_write(Command::RevokeReplica {
                            id,
                            complete: false,
                        })
                        .await
                    {
                        Ok(reply) if reply.data.is_ok() => (),
                        Ok(reply) => return Outcome::Revocation(reply.data.map(|_| ())),
                        Err(_) => return Outcome::Unavailable,
                    }
                    #[cfg(test)]
                    if service
                        .interrupt_revocation
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        return Outcome::Unavailable;
                    }
                    if membership.nodes().any(|(node_id, _)| *node_id == id) {
                        if service
                            .node
                            .change_membership(
                                openraft::ChangeMembers::RemoveVoters(
                                    std::collections::BTreeSet::from([id]),
                                ),
                                false,
                            )
                            .await
                            .is_err()
                        {
                            return Outcome::Unavailable;
                        }
                        // RemoveNodes also covers a pre-existing learner. Native APIs resume
                        // durable joint configurations; no local voter arithmetic or disconnect.
                        if service
                            .node
                            .change_membership(
                                openraft::ChangeMembers::RemoveNodes(
                                    std::collections::BTreeSet::from([id]),
                                ),
                                false,
                            )
                            .await
                            .is_err()
                        {
                            return Outcome::Unavailable;
                        }
                    }
                    match service
                        .node
                        .client_write(Command::RevokeReplica { id, complete: true })
                        .await
                    {
                        Ok(reply) if reply.data.is_ok() => {
                            if let Some(network) = &service.network {
                                if network.reconcile_store(&service.store).await.is_err() {
                                    return Outcome::Unavailable;
                                }
                            }
                            Outcome::Revocation(Ok(()))
                        }
                        Ok(reply) => Outcome::Revocation(reply.data.map(|_| ())),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::PromoteLearner(id) => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let admitted = service
                        .store
                        .run(move |conn| {
                            use diesel::OptionalExtension;
                            if read_revocations(conn)?.contains_key(&id) {
                                return Ok(false);
                            }
                            let pending: Vec<Admission> =
                                crate::db::get_setting(conn, "replica_pending_admissions")
                                    .optional()?
                                    .map(|s| serde_json::from_str(&s))
                                    .transpose()?
                                    .unwrap_or_default();
                            Ok(pending.iter().any(|a| a.request.node_id == id))
                        })
                        .await;
                    match admitted {
                        Ok(true) => (),
                        Ok(false) => {
                            return Outcome::Promotion(Err("no committed admission".into()));
                        }
                        Err(_) => return Outcome::Unavailable,
                    }
                    let metrics = service.node.metrics().borrow().clone();
                    let membership = metrics.membership_config.membership();
                    if !membership.nodes().any(|(node_id, _)| *node_id == id) {
                        return Outcome::Promotion(Err("activate learner before promotion".into()));
                    }
                    // A completed retry is read-only; a joint configuration must finish through
                    // the native API even when the target is already in one voter set.
                    if membership.get_joint_config().len() == 1
                        && membership.voter_ids().any(|v| v == id)
                    {
                        return Outcome::Promotion(Ok(()));
                    }
                    let matched = metrics
                        .replication
                        .as_ref()
                        .and_then(|r| r.get(&id))
                        .copied()
                        .flatten();
                    if matched.is_none() || matched < metrics.last_applied {
                        return Outcome::Promotion(Err("learner has not caught up".into()));
                    }
                    // ponytail: explicit promotion only; retry resumes durable joint membership
                    // after restart. No serving grant, automatic promotion or voter removal.
                    match service
                        .node
                        .change_membership(
                            openraft::ChangeMembers::AddVoterIds(std::collections::BTreeSet::from(
                                [id],
                            )),
                            true,
                        )
                        .await
                    {
                        Ok(_) => Outcome::Promotion(Ok(())),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::ActivateLearner(id) => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let admission = service
                        .store
                        .run(move |conn| {
                            use diesel::OptionalExtension;
                            if read_revocations(conn)?.contains_key(&id) {
                                return Ok(None);
                            }
                            let pending: Vec<Admission> =
                                crate::db::get_setting(conn, "replica_pending_admissions")
                                    .optional()?
                                    .map(|s| serde_json::from_str(&s))
                                    .transpose()?
                                    .unwrap_or_default();
                            Ok(pending.into_iter().find(|a| a.request.node_id == id))
                        })
                        .await;
                    let Ok(Some(admission)) = admission else {
                        return Outcome::Learner(Err("no committed pending admission".into()));
                    };
                    let Some(network) = &service.network else {
                        return Outcome::Unavailable;
                    };
                    if network.reconcile_store(&service.store).await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let membership = service.node.metrics().borrow().membership_config.clone();
                    if membership.membership().voter_ids().any(|v| v == id) {
                        return Outcome::Learner(Err("pending node is already a voter".into()));
                    }
                    // ponytail: explicit operator retry resumes learner replication; no PSK delivery,
                    // automatic activation, serving grant or voter promotion.
                    let result = service
                        .node
                        .add_learner(
                            id,
                            BasicNode::new(admission.request.address.to_string()),
                            false,
                        )
                        .await;
                    match result {
                        Ok(_) => Outcome::Learner(Ok(())),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::Join { source, request } => {
                    use cat4igp_shared::discovery::join::Response;
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let selected = service.transport_credential.clone();
                    if !matches!(
                        service
                            .store
                            .run(move |conn| Ok(read_transport(conn)?
                                .map_or(selected.generation == 0, |s| s.next.is_none()
                                    && s.active == selected)))
                            .await,
                        Ok(true)
                    ) {
                        return Outcome::Join(Response::Unavailable);
                    }
                    if request.validate(source, &service.cluster_id).is_err() {
                        return Outcome::Join(Response::Rejected);
                    }
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let pending = Response::Pending {
                        request_id: request.request_id.clone(),
                        node_id: request.node_id,
                        peer_id: source,
                    };
                    let command = Admission {
                        source,
                        request,
                        at_ms: chrono::Utc::now().timestamp_millis(),
                    };
                    match service.node.client_write(Command::Admission(command)).await {
                        Ok(reply) if reply.data.is_ok() => {
                            // Only the exact authenticated committed retry gets transport credentials.
                            // ponytail: explicit operator learner activation; no serving grant/promotion.
                            let Some(network) = &service.network else {
                                return Outcome::Unavailable;
                            };
                            let mut replicas = network.bootstrap_endpoints();
                            if let Response::Pending {
                                node_id,
                                peer_id,
                                request_id,
                            } = pending
                            {
                                let address = service
                                    .store
                                    .run(move |conn| {
                                        let admissions: Vec<Admission> =
                                            serde_json::from_str(&crate::db::get_setting(
                                                conn,
                                                "replica_pending_admissions",
                                            )?)?;
                                        Ok(admissions
                                            .into_iter()
                                            .find(|a| {
                                                a.source == peer_id
                                                    && a.request.node_id == node_id
                                                    && a.request.request_id == request_id
                                            })
                                            .map(|a| a.request))
                                    })
                                    .await;
                                let Ok(Some(request)) = address else {
                                    return Outcome::Unavailable;
                                };
                                replicas.insert(
                                    node_id,
                                    cat4igp_shared::discovery::ControllerEndpoint {
                                        peer_id,
                                        addresses: vec![request.address],
                                    },
                                );
                                Outcome::Join(Response::Bootstrap {
                                    request_id: request.request_id,
                                    node_id,
                                    peer_id,
                                    cluster_id: service.cluster_id.clone(),
                                    cluster_psk: service.cluster_psk.to_key_file(),
                                    transport_generation: service.transport_credential.generation,
                                    replicas,
                                })
                            } else {
                                Outcome::Unavailable
                            }
                        }
                        Ok(_) => Outcome::Join(Response::Rejected),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::ReplicaCode { rotate_generation } => {
                    service.replica_code(rotate_generation).await
                }
                Operation::VerifyReplicaCode(code) => {
                    if code.len() != 64 || service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    match service
                        .store
                        .run(move |conn| {
                            Ok(read_code(conn)?.is_some_and(|state| {
                                valid_code(&state, &code, chrono::Utc::now().timestamp_millis())
                            }))
                        })
                        .await
                    {
                        Ok(valid) => Outcome::VerifiedReplicaCode(valid),
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::AffectedSnapshots {
                    principal,
                    serving,
                    envelope,
                } => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    service
                        .affected_snapshots(principal, serving, envelope)
                        .await
                }
                Operation::Client {
                    principal,
                    serving,
                    request,
                } => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    service.client(principal, serving, request).await
                }
                Operation::Ready => match service.node.ensure_linearizable().await {
                    Ok(_) => Outcome::Ready,
                    Err(_) => Outcome::Unavailable,
                },
                Operation::Discovery {
                    query,
                    source,
                    serving,
                } => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let admitted = service.admitted.clone();
                    Outcome::Discovery(
                        service
                            .store
                            .run(move |conn| {
                                check_bindings(conn, &admitted)?;
                                let authority = read_authority(conn)?;
                                let roster =
                                    authority.roster.ok_or("no committed serving roster")?;
                                let key = libp2p::identity::Keypair::from_protobuf_encoding(
                                    &crate::hex_decode(&crate::db::get_setting(
                                        conn,
                                        "control_private_key",
                                    )?)?,
                                )?;
                                Ok(cat4igp_shared::discovery::transport::respond(
                                    &key,
                                    &roster,
                                    serving,
                                    &query,
                                    source,
                                    chrono::Utc::now().timestamp_millis(),
                                )?)
                            })
                            .await
                            .map_err(|e| e.to_string()),
                    )
                }
                Operation::Authority => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let admitted = service.admitted.clone();
                    Outcome::Authority(
                        service
                            .store
                            .run(move |conn| {
                                check_bindings(conn, &admitted)?;
                                read_authority(conn)
                            })
                            .await
                            .map_err(|e| e.to_string()),
                    )
                }
                Operation::InitializeAuthority => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let exists = service
                        .store
                        .run(|conn| {
                            use diesel::OptionalExtension;
                            Ok(crate::db::get_setting(conn, "controller_admitted")
                                .optional()?
                                .is_some())
                        })
                        .await;
                    match exists {
                        Ok(true) => Outcome::Roster(Ok(())),
                        Ok(false) => match service
                            .node
                            .client_write(Command::AuthorityInit(new_authority(
                                service.cluster_id,
                                service.admitted,
                            )))
                            .await
                        {
                            Ok(reply) => Outcome::Roster(reply.data.map(|_| ())),
                            Err(_) => Outcome::Unavailable,
                        },
                        Err(_) => Outcome::Unavailable,
                    }
                }
                Operation::RenewRoster => service.renew_roster().await,
                Operation::Roster(body) => {
                    if service.node.ensure_linearizable().await.is_err() {
                        return Outcome::Unavailable;
                    }
                    let previous = match service.store.run(read_authority).await {
                        Ok(authority) => authority.roster,
                        Err(_) => return Outcome::Unavailable,
                    };
                    let metrics = service.node.metrics().borrow().clone();
                    let membership = metrics.membership_config.membership();
                    let peers = match service
                        .store
                        .run(|conn| {
                            use diesel::OptionalExtension;
                            let mut peers: BTreeMap<u64, libp2p::PeerId> = serde_json::from_str(
                                &crate::db::get_setting(conn, "controller_admitted")?,
                            )?;
                            let pending: Vec<Admission> =
                                crate::db::get_setting(conn, "replica_pending_admissions")
                                    .optional()?
                                    .map(|s| serde_json::from_str(&s))
                                    .transpose()?
                                    .unwrap_or_default();
                            for admission in pending {
                                peers.insert(admission.request.node_id, admission.source);
                            }
                            Ok(peers)
                        })
                        .await
                    {
                        Ok(peers) => peers,
                        Err(_) => return Outcome::Unavailable,
                    };
                    for endpoint in &body.controllers {
                        if previous
                            .as_ref()
                            .is_some_and(|r| r.body.controllers.contains(endpoint))
                        {
                            continue;
                        }
                        let Some(id) = peers
                            .iter()
                            .find_map(|(id, peer)| (*peer == endpoint.peer_id).then_some(*id))
                        else {
                            return Outcome::Roster(Err("no committed admission".into()));
                        };
                        let matched = if id == metrics.id {
                            metrics.last_applied
                        } else {
                            metrics
                                .replication
                                .as_ref()
                                .and_then(|r| r.get(&id))
                                .copied()
                                .flatten()
                        };
                        if membership.get_joint_config().len() != 1
                            || !membership.voter_ids().any(|v| v == id)
                            || matched.is_none()
                            || matched < metrics.last_applied
                        {
                            return Outcome::Roster(Err(
                                "new serving endpoint requires caught-up voter".into(),
                            ));
                        }
                    }
                    let admitted = service.admitted.clone();
                    let signed = service
                        .store
                        .run(move |conn| {
                            check_bindings(conn, &admitted)?;
                            let network = crate::db::get_setting(conn, "control_network_id")?;
                            let key = libp2p::identity::Keypair::from_protobuf_encoding(
                                &crate::hex_decode(&crate::db::get_setting(
                                    conn,
                                    "control_private_key",
                                )?)?,
                            )?;
                            let signed = body.sign(&key)?;
                            signed.validate(
                                &key.public(),
                                &network,
                                1,
                                chrono::Utc::now().timestamp_millis(),
                            )?;
                            Ok(signed)
                        })
                        .await;
                    match signed {
                        Err(error) => Outcome::Roster(Err(error.to_string())),
                        Ok(roster) => {
                            match service.node.client_write(Command::Roster(roster)).await {
                                Ok(reply) => Outcome::Roster(reply.data.map(|_| ())),
                                Err(_) => Outcome::Unavailable,
                            }
                        }
                    }
                }
                Operation::Invite {
                    request_id,
                    expires_at,
                    max_uses,
                    join_mesh,
                } => {
                    match invite(
                        &service.node,
                        &service.store,
                        request_id,
                        expires_at,
                        max_uses,
                        join_mesh,
                    )
                    .await
                    {
                        Ok(result) => Outcome::Invite(result),
                        Err(_) => Outcome::Unavailable,
                    }
                }
            }
        })
        .await
        .unwrap_or(Outcome::Unavailable)
    }

    async fn replica_code(&self, rotate: Option<u64>) -> Outcome {
        if self.node.ensure_linearizable().await.is_err() {
            return Outcome::Unavailable;
        }
        let admitted = self.admitted.clone();
        let current = match self
            .store
            .run(move |conn| {
                check_bindings(conn, &admitted)?;
                read_code(conn)
            })
            .await
        {
            Ok(current) => current,
            Err(_) => return Outcome::Unavailable,
        };
        let now = chrono::Utc::now().timestamp_millis();
        // Trusted UTC: backwards before activation fails closed, forwards expires
        // immediately. No local extension or tolerated skew; operators synchronize clocks.
        if current.as_ref().is_some_and(|c| now < c.activated_at_ms) {
            return Outcome::Unavailable;
        }
        let generation = current.as_ref().map_or(0, |c| c.generation);
        if let Some(expected) = rotate {
            if expected.checked_add(1) == Some(generation) {
                return Outcome::ReplicaCode(Ok(current.unwrap()));
            }
            if expected != generation {
                return Outcome::ReplicaCode(Err("generation conflict".into()));
            }
        }
        if rotate.is_some() || current.as_ref().is_none_or(|c| now >= c.expires_at_ms) {
            use rand08::RngCore;
            let mut random = [0; 32];
            rand08::rngs::OsRng.fill_bytes(&mut random);
            let Some(expires_at_ms) = now.checked_add(CODE_LIFETIME_MS) else {
                return Outcome::Unavailable;
            };
            let command = CodeRotation {
                expected_generation: generation,
                code: crate::hex_encode(&random),
                activated_at_ms: now,
                expires_at_ms,
            };
            match self.node.client_write(Command::ReplicaCode(command)).await {
                Ok(reply) if reply.data.is_ok() => (),
                _ => return Outcome::Unavailable,
            }
            return match self.store.run(read_code).await {
                Ok(Some(code)) => Outcome::ReplicaCode(Ok(code)),
                _ => Outcome::Unavailable,
            };
        }
        Outcome::ReplicaCode(Ok(current.unwrap()))
    }

    async fn renew_roster(&self) -> Outcome {
        if self.node.ensure_linearizable().await.is_err() {
            return Outcome::Unavailable;
        }
        let admitted = self.admitted.clone();
        let signed = self
            .store
            .run(move |conn| {
                check_bindings(conn, &admitted)?;
                let authority = read_authority(conn)?;
                let Some(previous) = authority.roster else {
                    return Ok(None);
                };
                let Some(body) =
                    renewed_roster(&previous.body, chrono::Utc::now().timestamp_millis())
                else {
                    return Ok(None);
                };
                let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(
                    &crate::db::get_setting(conn, "control_private_key")?,
                )?)?;
                // Only the committed roster is copied. Ordered apply rechecks admitted peers
                // and every pending/complete revocation; no endpoint or serving grant is added.
                Ok(Some(body.sign(&key)?))
            })
            .await;
        match signed {
            Ok(None) => Outcome::Roster(Ok(())),
            Ok(Some(roster)) => match self.node.client_write(Command::Roster(roster)).await {
                Ok(reply) => Outcome::Roster(reply.data.map(|_| ())),
                Err(_) => Outcome::Unavailable,
            },
            Err(_) => Outcome::Unavailable,
        }
    }

    async fn schedule_codes(&self) {
        // ponytail: fixed 15m/2m policy, one-second reconciliation; add committed policy
        // management with admission. Restart/failover reads the committed deadline.
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        loop {
            timer.tick().await;
            let metrics = self.node.metrics().borrow().clone();
            if metrics.current_leader == Some(metrics.id) {
                // A valid committed code needs no reconciliation or allocation lock.
                // Recheck under the lock in replica_code before any rotation.
                let roster_due = self
                    .store
                    .run(|conn| {
                        Ok(read_authority(conn)?.roster.is_some_and(|roster| {
                            renewed_roster(&roster.body, chrono::Utc::now().timestamp_millis())
                                .is_some()
                        }))
                    })
                    .await;
                if matches!(roster_due, Ok(true)) {
                    let _ = self.local(Operation::RenewRoster).await;
                }
                if self.store.run(read_code).await.is_ok_and(|code| {
                    code.is_some_and(|code| {
                        chrono::Utc::now().timestamp_millis() < code.expires_at_ms
                    })
                }) {
                    continue;
                }
                let _ = self
                    .local(Operation::ReplicaCode {
                        rotate_generation: None,
                    })
                    .await;
            }
        }
    }

    async fn submit(&self, operation: Operation) -> Outcome {
        tokio::time::timeout(DEADLINE, async {
            let mut result = self.local(operation.clone()).await;
            // ponytail: two redirects, static admitted bindings; add discovery only with committed admission.
            for _ in 0..2 {
                let Outcome::Redirect(target) = result else {
                    break;
                };
                result = match &self.network {
                    Some(network) => network.forward(target, operation.clone()).await,
                    None => Outcome::Unavailable,
                };
            }
            result
        })
        .await
        .unwrap_or(Outcome::Unavailable)
    }

    async fn affected_snapshots(
        &self,
        principal: libp2p::PeerId,
        serving: libp2p::PeerId,
        envelope: cat4igp_shared::control::EncryptedEnvelope,
    ) -> Outcome {
        let admitted = self.admitted.clone();
        let result = self
            .store
            .run(move |conn| {
                check_bindings(conn, &admitted)?;
                let authority = read_authority(conn)?;
                let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(
                    &crate::db::get_setting(conn, "control_private_key")?,
                )?)?;
                let now = chrono::Utc::now().timestamp_millis();
                let roster = authority.roster.ok_or("no committed serving roster")?;
                roster.validate(&key.public(), &authority.network_id, 1, now)?;
                if !roster.body.controllers.iter().any(|e| e.peer_id == serving) {
                    return Err("unauthorized serving replica".into());
                }
                let identity = crate::db::control_identity_for_peer(conn, &principal.to_string())?;
                let answer = cat4igp_shared::control::open_tunnel_answer(
                    &identity.signing_key,
                    &crate::db::get_setting(conn, "control_encryption_private_key")?,
                    &authority.network_id,
                    identity.node_id,
                    now,
                    &envelope,
                )?;
                let recipients = crate::db::accepted_answer_recipients(
                    conn,
                    identity.node_id,
                    &envelope.meta.message_id,
                    &answer,
                )?;
                // Internal admitted-only read: recipients come from the authorized committed
                // result, never a forged public Snapshot principal or caller-supplied node list.
                recipients
                    .into_iter()
                    .map(|node| {
                        let identity = crate::db::control_identity_for_node(conn, node)?;
                        let snapshot =
                            crate::db::topology_snapshot(conn, node, identity.topology_revision)?;
                        Ok(cat4igp_shared::control::seal_topology_snapshot(
                            &key,
                            &identity.encryption_key,
                            cat4igp_shared::control::MessageMeta {
                                message_id: uuid::Uuid::new_v4().simple().to_string(),
                                network_id: authority.network_id.clone(),
                                recipient_node_id: node,
                                issued_at_ms: now,
                                expires_at_ms: now + 60_000,
                                topology_revision: identity.topology_revision,
                            },
                            &snapshot,
                        )?)
                    })
                    .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()
            })
            .await;
        match result {
            Ok(envelopes) => Outcome::AffectedSnapshots(envelopes),
            Err(_) => Outcome::Unavailable,
        }
    }

    async fn client(
        &self,
        principal: libp2p::PeerId,
        serving: libp2p::PeerId,
        request: cat4igp_shared::control::ControlRequest,
    ) -> Outcome {
        use cat4igp_shared::control::{
            ControlRequest, ControlResponse, EnrollmentResponse, MessageMeta,
        };
        // Only authenticated admitted replicas can call this over the cluster transport.
        // The private listener supplies the actual Noise peer, never a request-supplied principal.
        let admitted = self.admitted.clone();
        let prepared = self
            .store
            .run(move |conn| {
                use diesel::prelude::*;
                check_bindings(conn, &admitted)?;
                let authority = read_authority(conn)?;
                let key = libp2p::identity::Keypair::from_protobuf_encoding(&crate::hex_decode(
                    &crate::db::get_setting(conn, "control_private_key")?,
                )?)?;
                let roster = authority.roster.ok_or("no committed serving roster")?;
                let now = chrono::Utc::now().timestamp_millis();
                roster.validate(&key.public(), &authority.network_id, 1, now)?;
                if !roster
                    .body
                    .controllers
                    .iter()
                    .any(|endpoint| endpoint.peer_id == serving)
                {
                    return Err("ingress replica is not authorized to serve clients".into());
                }
                match request {
                    ControlRequest::Enroll(request) => {
                        if request.client_peer_id != principal.to_string()
                            || request.request_id.is_empty()
                            || request.request_id.len() > 256
                            || request.node_name.is_empty()
                            || request.node_name.len() > 256
                            || request.invitation_code.is_empty()
                            || request.invitation_code.len() > 256
                            || request.wireguard_public_key.is_empty()
                            || request.wireguard_public_key.len() > 256
                            || request.client_signing_key.len() > 1024
                            || request.client_encryption_key.len() != 64
                        {
                            return Err("invalid enrollment request".into());
                        }
                        let signing = libp2p::identity::PublicKey::try_decode_protobuf(
                            &crate::hex_decode(&request.client_signing_key)?,
                        )?;
                        if signing.to_peer_id() != principal
                            || crate::hex_decode(&request.client_encryption_key)?.len() != 32
                        {
                            return Err("enrollment principal/key mismatch".into());
                        }
                        let node_id = crate::schema::nodes::table
                            .select(diesel::dsl::max(crate::schema::nodes::id))
                            .first::<Option<i32>>(conn)?
                            .unwrap_or(0)
                            .checked_add(1)
                            .ok_or("node IDs exhausted")?;
                        Ok(Ok(Command::Enrollment {
                            peer_id: principal.to_string(),
                            command: crate::db::EnrollmentCommand {
                                allocation: crate::db::prepare_enrollment_allocation(
                                    conn,
                                    &request.invitation_code,
                                )?,
                                request,
                                node_id,
                                auth_key: uuid::Uuid::new_v4().to_string(),
                                applied_at: chrono::Utc::now().naive_utc(),
                                response: EnrollmentResponse {
                                    node_id,
                                    topology_revision: 0,
                                    network_id: authority.network_id,
                                    controller_signing_key: authority.signing_key,
                                    controller_encryption_key: authority.encryption_key,
                                },
                            },
                        }))
                    }
                    ControlRequest::Snapshot => {
                        let identity =
                            crate::db::control_identity_for_peer(conn, &principal.to_string())?;
                        let snapshot = crate::db::topology_snapshot(
                            conn,
                            identity.node_id,
                            identity.topology_revision,
                        )?;
                        let envelope = cat4igp_shared::control::seal_topology_snapshot(
                            &key,
                            &identity.encryption_key,
                            MessageMeta {
                                message_id: uuid::Uuid::new_v4().simple().to_string(),
                                network_id: authority.network_id,
                                recipient_node_id: identity.node_id,
                                issued_at_ms: now,
                                expires_at_ms: now + 60_000,
                                topology_revision: identity.topology_revision,
                            },
                            &snapshot,
                        )?;
                        Ok(Err(ControlResponse::SnapshotEnvelope(envelope)))
                    }
                    ControlRequest::TunnelAnswerEnvelope(envelope) => {
                        let identity =
                            crate::db::control_identity_for_peer(conn, &principal.to_string())?;
                        let private =
                            crate::db::get_setting(conn, "control_encryption_private_key")?;
                        let answer = cat4igp_shared::control::open_tunnel_answer(
                            &identity.signing_key,
                            &private,
                            &authority.network_id,
                            identity.node_id,
                            now,
                            &envelope,
                        )?;
                        Ok(Ok(Command::Answer {
                            peer_id: principal.to_string(),
                            command: crate::db::AnswerCommand {
                                node_id: identity.node_id,
                                request_id: envelope.meta.message_id,
                                answer,
                                applied_at: chrono::Utc::now().naive_utc(),
                            },
                        }))
                    }
                }
            })
            .await;
        match prepared {
            Err(error) => Outcome::Client(ControlResponse::Rejected(error.to_string())),
            Ok(Err(response)) => Outcome::Client(response),
            Ok(Ok(command)) => {
                let enrollment = matches!(&command, Command::Enrollment { .. });
                match self.node.client_write(command).await {
                    Err(_) => Outcome::Unavailable,
                    Ok(reply) => match reply.data {
                        Err(reason) => Outcome::Client(ControlResponse::Rejected(reason)),
                        Ok(Some(result)) if enrollment => match serde_json::from_str(&result) {
                            Ok(response) => Outcome::Client(response),
                            Err(_) => Outcome::Unavailable,
                        },
                        Ok(Some(result)) if result == "accepted" => {
                            Outcome::Client(ControlResponse::Accepted)
                        }
                        _ => Outcome::Unavailable,
                    },
                }
            }
        }
    }
}

// ponytail: static admitted voters, one explicit initializer; add rolling-code learner admission
// for dynamic membership (client ingress uses only the committed static serving roster).
async fn start(
    config: Config,
    database: String,
    psk: libp2p::pnet::PreSharedKey,
) -> Result<(Node, Store, tokio::task::JoinHandle<()>, Service), String> {
    start_inner(
        config,
        database,
        psk,
        #[cfg(test)]
        None,
    )
    .await
}

async fn start_inner(
    config: Config,
    database: String,
    psk: libp2p::pnet::PreSharedKey,
    #[cfg(test)] reservation: Option<std::net::TcpListener>,
) -> Result<(Node, Store, tokio::task::JoinHandle<()>, Service), String> {
    cat4igp_shared::discovery::topic(&config.cluster_id, cat4igp_shared::discovery::Role::Client)
        .map_err(str::to_owned)?;
    if config.cluster_id.is_empty()
        || config.cluster_id.len() > 128
        || config.node_id == 0
        || config.replicas.is_empty()
        || config.replicas.len() > 64
        || config.replicas.keys().any(|id| *id == 0)
        || config
            .replicas
            .values()
            .map(|r| r.peer_id)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != config.replicas.len()
    {
        return Err("invalid cluster ID, node ID or replicas".into());
    }
    if (config.mode == Mode::Recover || config.learner.is_some())
        && !std::path::Path::new(&config.identity_file).is_file()
    {
        return Err("recovery requires the existing replica identity file".into());
    }
    let key = crate::raft_network::replica_identity(std::path::Path::new(&config.identity_file))
        .map_err(|e| e.to_string())?;
    let peer = key.public().to_peer_id();
    let legacy = if let Some(import) = &config.legacy_import {
        if config.mode != Mode::Initialize
            || config.learner.is_some()
            || config.replicas.len() != 1
            || !config.replicas.contains_key(&config.node_id)
        {
            return Err("legacy import requires explicit single-voter initialize".into());
        }
        if std::path::Path::new(&database).exists() {
            return Err(
                "legacy import destination must not exist; recover an interrupted destination"
                    .into(),
            );
        }
        let tables = crate::raft_storage::legacy_backup(
            &import.source,
            &import.backup,
            &config.cluster_id,
        )
        .map_err(|_| {
            "legacy backup/import validation failed; source unchanged, inspect retained backup"
                .to_owned()
        })?;
        if tables[0].iter().any(|row| {
            row[0] == "control_private_key"
                && row[1]
                    .as_str()
                    .and_then(|s| crate::hex_decode(s).ok())
                    .and_then(|b| libp2p::identity::Keypair::from_protobuf_encoding(&b).ok())
                    .is_some_and(|k| k.public().to_peer_id() == peer)
        }) {
            return Err(
                "legacy logical identity must differ from replica transport identity".into(),
            );
        }
        Some(tables)
    } else {
        None
    };
    if config
        .learner
        .as_ref()
        .or_else(|| config.replicas.get(&config.node_id))
        .map(|r| r.peer_id)
        != Some(peer)
    {
        return Err("replica identity does not match configured node binding".into());
    }
    if config.learner.is_some()
        && (config.mode == Mode::Initialize || config.replicas.contains_key(&config.node_id))
    {
        return Err("learner cannot initialize or replace a bootstrap replica".into());
    }
    if legacy.is_some() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)
            .map_err(|e| e.to_string())?;
        let mut conn = diesel::SqliteConnection::establish(&database).map_err(|e| e.to_string())?;
        crate::db::configure_connection(&mut conn).map_err(|e| e.to_string())?;
        crate::db::migrate(&mut conn, true)?;
    }
    let store = Store::open(database).await.map_err(|e| e.to_string())?;
    let transport_credential = credential(&config.cluster_id, config.transport_generation, psk);
    let selected = transport_credential.clone();
    let binding =
        serde_json::to_string(&(config.cluster_id.clone(), config.node_id, peer.to_string()))
            .map_err(|e| e.to_string())?;
    let mode = config.mode;
    let learner = config.learner.is_some();
    let admitted: BTreeMap<_, _> = config
        .replicas
        .iter()
        .map(|(id, r)| (*id, r.peer_id))
        .collect();
    let expected_admitted = admitted.clone();
    let transport_bootstrap = serde_json::to_string(
        &config
            .replicas
            .iter()
            .map(|(id, r)| (*id, (r.peer_id, r.address.to_string())))
            .collect::<BTreeMap<_, _>>(),
    )
    .map_err(|e| e.to_string())?;
    store.run(move |conn| {
        use diesel::{OptionalExtension, QueryableByName, sql_types::Text};
        #[derive(QueryableByName)]
        struct Value { #[diesel(sql_type = Text)] value: String }
        conn.immediate_transaction::<_, Box<dyn std::error::Error + Send + Sync>, _>(|conn| {
            let previous = diesel::sql_query("SELECT value FROM raft_meta WHERE key = 'replica_binding'")
                .get_result::<Value>(conn).optional()?;
            let persisted = previous.is_some();
            let previous_transport = diesel::sql_query("SELECT value FROM raft_meta WHERE key = 'transport_bootstrap'")
                .get_result::<Value>(conn).optional()?;
            if previous_transport.is_some_and(|p| p.value != transport_bootstrap) {
                return Err("configured bootstrap endpoints differ from durable transport binding".into());
            }
            if previous.is_some_and(|p| p.value != binding) {
                return Err(std::io::Error::other("persisted cluster/node/peer binding mismatch").into());
            }
            let used = diesel::sql_query("SELECT 'used' AS value FROM raft_meta WHERE key NOT IN ('replica_binding', 'application_version') UNION ALL SELECT 'used' AS value FROM raft_logs LIMIT 1")
                .get_result::<Value>(conn).optional()?.is_some();
            if (mode == Mode::Recover && !persisted) || (mode != Mode::Recover && (persisted || used) && !(learner && persisted)) {
                return Err(std::io::Error::other("initialize/join require pristine consensus state; existing replicas must recover").into());
            }
            if let Some(saved) = crate::db::get_setting(conn, "controller_admitted").optional()? {
                let saved: BTreeMap<u64, libp2p::PeerId> = serde_json::from_str(&saved)?;
                if saved != expected_admitted { return Err("configured bindings differ from committed authority".into()); }
            }
            // ponytail: no legacy import yet; add an explicit snapshot-seeded cutover before migration.
            if mode != Mode::Recover && !persisted {
                let application = diesel::sql_query("SELECT 'used' AS value FROM settings UNION ALL SELECT 'used' AS value FROM nodes UNION ALL SELECT 'used' AS value FROM invites UNION ALL SELECT 'used' AS value FROM mesh_groups UNION ALL SELECT 'used' AS value FROM control_enrollment_results UNION ALL SELECT 'used' AS value FROM operator_invite_results LIMIT 1")
                    .get_result::<Value>(conn).optional()?.is_some();
                if application { return Err(std::io::Error::other("initialize/join require an empty application database; legacy import unsupported").into()); }
            }
            diesel::sql_query("INSERT INTO raft_meta(key,value) VALUES ('replica_binding', ?) ON CONFLICT(key) DO NOTHING")
                .bind::<Text,_>(&binding).execute(conn)?;
            // ponytail: older replicas pin endpoints on first upgraded recovery; coordinated upgrades only.
            diesel::sql_query("INSERT INTO raft_meta(key,value) VALUES ('transport_bootstrap', ?) ON CONFLICT(key) DO NOTHING")
                .bind::<Text,_>(&transport_bootstrap).execute(conn)?;
            // A protected join config supplies the current generation before catchup.
            // Before catchup, recovery must use the exact previously pinned credential.
            let unapplied_learner = learner && ((!persisted && !used)
                || (persisted && crate::raft_storage::get::<TransportCredential>(conn, "transport_credential")?.as_ref() == Some(&selected)));
            validate_transport(conn, &selected, unapplied_learner)?;
            Ok(())
        })
    }).await.map_err(|e| e.to_string())?;
    let mut bindings: BTreeMap<_, _> = config
        .replicas
        .iter()
        .map(|(id, r)| {
            (
                *id,
                Binding {
                    peer: r.peer_id,
                    address: r.address.clone(),
                },
            )
        })
        .collect();
    if let Some(learner) = config.learner {
        bindings.insert(
            config.node_id,
            Binding {
                peer: learner.peer_id,
                address: learner.address,
            },
        );
    }
    #[cfg(test)]
    drop(reservation);
    let (network, _, attach, task) = Network::start(
        config.node_id,
        config.cluster_id.clone(),
        key,
        psk,
        bindings,
        config.listen,
    )
    .await
    .map_err(|e| format!("cluster transport startup node {}: {e:?}", config.node_id))?;
    // Reconstruct before consensus can send RPCs; subscribe before apply/snapshot can advance.
    network
        .reconcile_store(&store)
        .await
        .map_err(|e| format!("initial transport authorization: {e:?}"))?;
    let mut changes = store.changes();
    let reconciliation_network = network.clone();
    let reconciliation_store = store.clone();
    let task = tokio::spawn(async move {
        struct AbortTransport(tokio::task::AbortHandle);
        impl Drop for AbortTransport {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _abort = AbortTransport(task.abort_handle());
        let mut transport = task;
        loop {
            tokio::select! {
                result = &mut transport => { result.expect("cluster transport failed"); break; }
                changed = changes.changed() => {
                    if changed.is_err() { transport.abort(); break; }
                    if reconciliation_network.reconcile_store(&reconciliation_store).await.is_err() {
                        transport.abort();
                        panic!("committed transport authorization invalid");
                    }
                }
            }
        }
    });
    let settings = Arc::new(
        openraft::Config {
            cluster_name: config.cluster_id.clone(),
            snapshot_max_chunk_size: 64 * 1024,
            max_payload_entries: 16,
            ..Default::default()
        }
        .validate()
        .map_err(|e| e.to_string())?,
    );
    let node = Node::new(
        config.node_id,
        settings,
        network.consensus(),
        store.clone(),
        store.clone(),
    )
    .await
    .map_err(|e| format!("Raft core startup node {}: {e:?}", config.node_id))?;
    attach.send(Some(node.clone())).map_err(|e| e.to_string())?;
    let service = Service {
        _attachment: attach,
        node: node.clone(),
        store: store.clone(),
        network: Some(network.clone()),
        admitted: admitted.clone(),
        cluster_id: config.cluster_id.clone(),
        allocation: Arc::new(tokio::sync::Mutex::new(())),
        cluster_psk: psk,
        transport_credential,
        #[cfg(test)]
        interrupt_revocation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let mut local_service = service.clone();
    local_service.network = Some(network.consensus());
    network.attach_service(local_service);
    if mode == Mode::Initialize {
        node.initialize(
            config
                .replicas
                .keys()
                .map(|id| (*id, BasicNode::default()))
                .collect::<BTreeMap<_, _>>(),
        )
        .await
        .map_err(|e| format!("Raft initialize node {}: {e:?}", config.node_id))?;
        node.wait(Some(DEADLINE))
            .current_leader(config.node_id, "initializer elected")
            .await
            .map_err(|e| {
                format!(
                    "initializer election: {e:?}; metrics={:?}",
                    *node.metrics().borrow()
                )
            })?;
        // Only the explicit initializer generates logical keys; followers only replay committed settings.
        if let Some(tables) = legacy {
            node.client_write(Command::LegacyImport(tables))
                .await
                .map_err(|e| e.to_string())?
                .data?;
        }
        let init = new_authority(config.cluster_id, admitted);
        node.client_write(Command::AuthorityInit(init))
            .await
            .map_err(|e| {
                format!(
                    "authority initialization Raft outcome: {e:?}; metrics={:?}",
                    *node.metrics().borrow()
                )
            })?
            .data
            .map_err(|e| format!("authority initialization rejected: {e}"))?;
    }
    Ok((node, store, task, service))
}

async fn invite(
    node: &Node,
    store: &Store,
    request_id: String,
    expires_at: Option<chrono::NaiveDateTime>,
    max_uses: Option<i32>,
    join_mesh: Option<i32>,
) -> Result<Result<String, String>, diesel::result::Error> {
    let operation = async {
        node.ensure_linearizable().await.map_err(|_| ())?;
        let command = match store
            .run(move |conn| {
                use diesel::prelude::*;
                let last = crate::schema::invites::table
                    .select(diesel::dsl::max(crate::schema::invites::id))
                    .first::<Option<i32>>(conn)?
                    .unwrap_or(0);
                Ok(crate::db::InviteCommand {
                    request_id,
                    id: last.checked_add(1).ok_or("invite IDs exhausted")?,
                    code: uuid::Uuid::new_v4().to_string(),
                    expires_at,
                    max_uses,
                    join_mesh,
                    applied_at: chrono::Utc::now().naive_utc(),
                })
            })
            .await
        {
            Ok(command) => command,
            Err(_) => {
                // A failed database read is not quorum loss; fail stop rather than
                // continue selecting IDs from potentially damaged storage.
                let _ = node.shutdown().await;
                return Err(());
            }
        };
        let response = node
            .client_write(Command::Invite(command))
            .await
            .map_err(|_| ())?;
        Ok::<_, ()>(
            response
                .data
                .and_then(|code| code.ok_or_else(|| "missing committed invite result".into())),
        )
    };
    operation
        .await
        .map_err(|_| diesel::result::Error::RollbackTransaction)
}

async fn private_control(service: Service, key: libp2p::identity::Keypair) -> Result<(), String> {
    let listen = match std::env::var("CONTROL_BIND_MULTIADDR") {
        Err(std::env::VarError::NotPresent) => return std::future::pending().await,
        Err(error) => return Err(error.to_string()),
        Ok(listen) => listen,
    };
    let psk: libp2p::pnet::PreSharedKey = std::env::var("CONTROL_PRIVATE_NETWORK_KEY")
        .map_err(|_| "CONTROL_PRIVATE_NETWORK_KEY required")?
        .parse()
        .map_err(|_| "invalid client network PSK")?;
    private_control_at(service, key, &listen, psk).await
}

async fn private_control_at(
    service: Service,
    key: libp2p::identity::Keypair,
    listen: &str,
    psk: libp2p::pnet::PreSharedKey,
) -> Result<(), String> {
    private_control_inner(
        service,
        key,
        listen,
        psk,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
type EnrollmentDrop = Arc<std::sync::Mutex<Option<(libp2p::PeerId, std::path::PathBuf, bool)>>>;

async fn private_control_inner(
    service: Service,
    key: libp2p::identity::Keypair,
    listen: &str,
    psk: libp2p::pnet::PreSharedKey,
    #[cfg(test)] drop_enrollment: Option<EnrollmentDrop>,
) -> Result<(), String> {
    use futures_util::StreamExt;
    use libp2p::{
        core::{Transport, upgrade::Version},
        noise,
        pnet::PnetConfig,
        request_response,
        swarm::Swarm,
        tcp, yamux,
    };
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(psk).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&key).map_err(|e| e.to_string())?)
        .multiplex(yamux::Config::default())
        .boxed();
    let mut swarm = Swarm::new(
        transport,
        crate::ControlBehaviour {
            request_response: request_response::json::Behaviour::new(
                [(
                    libp2p::StreamProtocol::new(crate::CONTROL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            gossipsub: crate::gossipsub(&key)?,
        },
        key.public().to_peer_id(),
        libp2p::swarm::Config::with_tokio_executor(),
    );
    swarm
        .listen_on(
            listen
                .parse()
                .map_err(|_| "invalid control listen address")?,
        )
        .map_err(|e| e.to_string())?;
    let serving = key.public().to_peer_id();
    let mut authority = service
        .network
        .as_ref()
        .ok_or("missing cluster transport")?
        .authority();
    let mut relays = service
        .network
        .as_ref()
        .map(|network| network.listen_topology());
    let mut pending = tokio::task::JoinSet::new();
    let mut pushes = tokio::task::JoinSet::new();
    let mut published = BTreeMap::new();
    // ponytail: 32 postcommit reads of at most two recipients, 256 revision watermarks,
    // 64 KiB envelopes; add byte-budget scheduling for larger topologies. Polling repairs loss.
    loop {
        tokio::select! {
            changed = authority.changed() => {
                if changed.is_err() { return Err("authority reconciliation stopped".into()); }
                if !authority.borrow().permits(serving, chrono::Utc::now().timestamp_millis()) {
                    pending.abort_all();
                    pushes.abort_all();
                }
            }
            payload = async {
                match &mut relays {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                // Lag/overflow is intentionally repaired by existing client snapshot polling.
                let Ok(payload) = payload else { continue; };
                if !authority.borrow().verify(serving, &payload) { continue; }
                let Ok(envelope) = serde_json::from_slice::<cat4igp_shared::control::EncryptedEnvelope>(&payload) else { continue; };
                let node = envelope.meta.recipient_node_id;
                let revision = envelope.meta.topology_revision;
                if published.get(&node).is_some_and(|previous| *previous >= revision) { continue; }
                if published.len() >= 256 { published.clear(); }
                published.insert(node, revision);
                let topic = libp2p::gossipsub::Sha256Topic::new(cat4igp_shared::control::topology_topic(&envelope.meta.network_id, node));
                let _ = swarm.behaviour_mut().gossipsub.publish(topic, payload);
            }
            Some(result) = pending.join_next(), if !pending.is_empty() => {
                let Ok((channel, response, principal, answer, _request)) = result else { continue; };
                #[cfg(test)]
                if matches!(&response, cat4igp_shared::control::ControlResponse::Enrolled(_)) {
                    let receipt = drop_enrollment.as_ref().and_then(|armed| {
                        let mut armed = armed.lock().unwrap();
                        if armed.as_ref().is_some_and(|(peer, _, _)| *peer == principal) {
                            armed.take().map(|(_, path, drop_reply)| (path, drop_reply))
                        } else { None }
                    });
                    if let Some((path, drop_reply)) = receipt {
                        use std::{io::Write, os::unix::fs::OpenOptionsExt};
                        // ponytail: one selected committed enrollment wire loss, not arbitrary crash points.
                        let snapshot = service.submit(Operation::Client {
                            principal, serving, request: cat4igp_shared::control::ControlRequest::Snapshot,
                        }).await;
                        let Outcome::Client(snapshot @ cat4igp_shared::control::ControlResponse::SnapshotEnvelope(_)) = snapshot else {
                            panic!("committed enrollment snapshot unavailable");
                        };
                        let mut request_file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path.with_extension("request.json")).unwrap();
                        serde_json::to_writer(&mut request_file, &(principal, &_request)).unwrap();
                        request_file.sync_all().unwrap();
                        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                        serde_json::to_writer(&mut file, &(response, snapshot)).unwrap();
                        file.sync_all().unwrap();
                        std::fs::File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
                        if drop_reply {
                        drop(channel);
                        let _ = swarm.disconnect_peer_id(principal);
                        println!("CAT4IGP_DROPPED");
                        std::io::stdout().flush().unwrap();
                        continue;
                        }
                        let (recorded, _): (cat4igp_shared::control::ControlResponse, serde_json::Value) = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, recorded);
                        continue;
                    }
                }
                if !authority.borrow().permits(serving, chrono::Utc::now().timestamp_millis()) { continue; }
                if matches!(response, cat4igp_shared::control::ControlResponse::Accepted) && pushes.len() < 32 && let Some(envelope) = answer {
                    let service = service.clone();
                    pushes.spawn(async move {
                        // Fresh quorum barrier after committed application: an isolated ingress
                        // must not seal local state, even when it previously acknowledged a write.
                        service.submit(Operation::AffectedSnapshots {
                            principal, serving, envelope,
                        }).await
                    });
                }
                let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
            }
            Some(result) = pushes.join_next(), if !pushes.is_empty() => {
                let Ok(Outcome::AffectedSnapshots(envelopes)) = result else { continue; };
                for envelope in envelopes {
                let Ok(payload) = serde_json::to_vec(&envelope) else { continue; };
                if !authority.borrow().verify(serving, &payload) { continue; }
                let node = envelope.meta.recipient_node_id;
                let revision = envelope.meta.topology_revision;
                if published.get(&node).is_some_and(|previous| *previous >= revision) { continue; }
                // Cache is only best-effort duplicate suppression, never authoritative state.
                if published.len() >= 256 { published.clear(); }
                published.insert(node, revision);
                if let Some(network) = &service.network { network.publish_topology(payload.clone()); }
                let topic = libp2p::gossipsub::Sha256Topic::new(cat4igp_shared::control::topology_topic(&envelope.meta.network_id, node));
                let _ = swarm.behaviour_mut().gossipsub.publish(topic, payload);
                }
            }
            event = swarm.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::Behaviour(crate::ControlBehaviourEvent::RequestResponse(
                    request_response::Event::Message { peer, message: request_response::Message::Request { request, channel, .. }, .. }
                )) = event {
                    if !authority.borrow().permits(serving, chrono::Utc::now().timestamp_millis()) || pending.len() >= 32 || serde_json::to_vec(&request).map_or(true, |bytes| bytes.len() > 64 * 1024) {
                        let _ = swarm.behaviour_mut().request_response.send_response(channel,
                            cat4igp_shared::control::ControlResponse::Rejected("control busy or oversized request".into()));
                        continue;
                    }
                    let service = service.clone();
                    pending.spawn(async move {
                        let answer = match &request {
                            cat4igp_shared::control::ControlRequest::TunnelAnswerEnvelope(envelope) => Some(envelope.clone()),
                            _ => None,
                        };
                        let _request = request.clone();
                        let response = match service.submit(Operation::Client { principal: peer, serving, request }).await {
                            Outcome::Client(response) => response,
                            _ => cat4igp_shared::control::ControlResponse::Rejected("quorum unavailable; retry same request".into()),
                        };
                        (channel, response, peer, answer, _request)
                    });
                }
            }
        }
    }
}

pub(crate) fn save_join(
    path: &str,
    identity_file: String,
    listen: libp2p::Multiaddr,
    request: &cat4igp_shared::discovery::join::Request,
    response: &cat4igp_shared::discovery::join::Response,
) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let key_path = std::path::Path::new(&identity_file);
    if !key_path.is_file() {
        return Err("join requires existing replica identity".into());
    }
    let key = crate::raft_network::replica_identity(key_path)
        .map_err(|_| "invalid existing replica identity")?;
    response.validate(request, key.public().to_peer_id())?;
    let cat4igp_shared::discovery::join::Response::Bootstrap {
        node_id,
        cluster_id,
        cluster_psk,
        transport_generation,
        replicas,
        ..
    } = response
    else {
        return Err("no committed transport bootstrap".into());
    };
    let mut replicas: BTreeMap<_, _> = replicas
        .iter()
        .map(|(id, r)| {
            (
                *id,
                Replica {
                    peer_id: r.peer_id,
                    address: r.addresses[0].clone(),
                },
            )
        })
        .collect();
    let learner = replicas.remove(node_id).ok_or("missing learner binding")?;
    let mut advertised = learner.address.clone();
    advertised.pop();
    if listen != advertised {
        return Err("learner listen must match committed advertised endpoint".into());
    }
    let config = Config {
        cluster_id: cluster_id.clone(),
        node_id: *node_id,
        mode: Mode::Join,
        identity_file,
        listen,
        replicas,
        learner: Some(learner),
        cluster_psk: Some(cluster_psk.clone()),
        transport_generation: *transport_generation,
        legacy_import: None,
    };
    let bytes = serde_json::to_vec(&config).map_err(|_| "cannot encode join config")?;
    if bytes.len() > 65536 {
        return Err("join config exceeds 64 KiB".into());
    }
    let path = std::path::Path::new(path);
    if path.exists() {
        // ponytail: exact retry only; endpoint/PSK refresh requires explicit future administration.
        use std::io::Read;
        let mut saved = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| "cannot read existing join config")?
            .take(65537)
            .read_to_end(&mut saved)
            .map_err(|_| "cannot read existing join config")?;
        if saved == bytes {
            return Ok(());
        }
        return Err("refusing to overwrite different join config".into());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let temporary = parent.join(format!(".join-{}", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        // Atomic no-clobber publication, unlike rename which can replace a concurrent config.
        std::fs::hard_link(&temporary, path)?;
        std::fs::remove_file(&temporary)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    let _ = std::fs::remove_file(temporary);
    result.map_err(|_| "cannot durably publish join config".into())
}

fn protected_read(path: &str) -> Result<Vec<u8>, String> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "cannot inspect secret file")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("secret file must be a regular owner-only file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "cannot open secret file")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read secret file")?;
    if bytes.len() > 65536 {
        return Err("secret file exceeds 64 KiB".into());
    }
    Ok(bytes)
}

fn publish_transport_config(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let path = std::path::Path::new(path);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let temporary = parent.join(format!(".transport-{}", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, path)?;
        std::fs::remove_file(&temporary)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    let _ = std::fs::remove_file(temporary);
    result.map_err(|_| "cannot publish protected config (output must not exist)".into())
}

// ponytail: operator-attested stop-all, never online recovery or pnet hot switching.
// TODO: process-kill maintenance rehearsal before claiming crash recovery automation.
pub(crate) fn offline_transport() -> Result<(), String> {
    let env = |name| std::env::var(name).map_err(|_| format!("{name} required"));
    apply_offline_transport(
        &env("CLUSTER_CONFIG_FILE")?,
        &env("CLUSTER_NEXT_PSK_FILE")?,
        &env("DATABASE_URL")?,
        &env("CLUSTER_ROTATED_CONFIG_FILE")?,
        env("CLUSTER_MAINTENANCE_STOPPED")? == "true",
    )
}

fn apply_offline_transport(
    config_path: &str,
    key_path: &str,
    database: &str,
    output: &str,
    stopped: bool,
) -> Result<(), String> {
    if !stopped {
        return Err("stop every replica before applying transport config".into());
    }
    let mut config: Config = serde_json::from_slice(&protected_read(config_path)?)
        .map_err(|_| "invalid protected cluster config")?;
    if config.mode != Mode::Recover || config.legacy_import.is_some() {
        return Err("maintenance requires recover config without legacy import".into());
    }
    let bytes = protected_read(key_path)?;
    let psk = std::str::from_utf8(&bytes)
        .ok()
        .filter(|s| s.len() <= 128 && s.is_ascii())
        .and_then(|s| s.parse::<libp2p::pnet::PreSharedKey>().ok())
        .ok_or("invalid next PSK file")?;
    let database = std::fs::canonicalize(database).map_err(|_| "existing database required")?;
    let mut conn = diesel::SqliteConnection::establish(&format!(
        "file:{}?mode=ro",
        database.to_str().ok_or("invalid database path")?
    ))
    .map_err(|_| "cannot open applied database")?;
    let binding = crate::raft_storage::get::<(String, u64, String)>(&mut conn, "replica_binding")
        .map_err(|_| "cannot read replica binding")?
        .ok_or("replica binding required")?;
    if binding.0 != config.cluster_id || binding.1 != config.node_id {
        return Err("maintenance config cluster/node mismatch".into());
    }
    if !std::path::Path::new(&config.identity_file).is_file() {
        return Err("existing maintenance replica identity required".into());
    }
    let key = crate::raft_network::replica_identity(std::path::Path::new(&config.identity_file))
        .map_err(|_| "invalid maintenance replica identity")?;
    if key.public().to_peer_id().to_string() != binding.2 {
        return Err("maintenance replica identity mismatch".into());
    }
    let state = read_transport(&mut conn)
        .map_err(|_| "cannot read applied rotation")?
        .ok_or("no applied rotation")?;
    let next = state.next.as_ref().ok_or("no prepared rotation")?;
    if next.cluster_id != config.cluster_id
        || next.generation
            != config
                .transport_generation
                .checked_add(1)
                .ok_or("generation exhausted")?
        || *next != credential(&config.cluster_id, next.generation, psk)
    {
        return Err("next key/cluster/generation mismatch".into());
    }
    let previous =
        crate::raft_storage::get::<TransportCredential>(&mut conn, "transport_credential")
            .map_err(|_| "cannot read local transport binding")?
            .ok_or("local transport binding required")?;
    if previous != state.active || previous.generation != config.transport_generation {
        return Err("stale local active credential".into());
    }
    config.transport_generation = next.generation;
    config.cluster_psk = Some(psk.to_key_file());
    publish_transport_config(
        output,
        &serde_json::to_vec(&config).map_err(|_| "cannot encode protected config")?,
    )
}

pub(crate) async fn serve(path: &str, database: String, apply: bool) -> Result<(), String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("cluster config exceeds 64 KiB".into());
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| "invalid cluster config")?;
    if config.transport_generation > 0 {
        protected_read(path)?;
    }
    if config.legacy_import.is_none() {
        let mut conn = diesel::SqliteConnection::establish(&database).map_err(|e| e.to_string())?;
        crate::db::configure_connection(&mut conn).map_err(|e| e.to_string())?;
        crate::db::migrate(&mut conn, apply)?;
    } else if !apply {
        return Err("legacy initialize requires AUTO_MIGRATE=true".into());
    }
    let learner_only = config.learner.is_some();
    let psk_text = config
        .cluster_psk
        .clone()
        .or_else(|| std::env::var("CLUSTER_PRIVATE_NETWORK_KEY").ok())
        .ok_or("CLUSTER_PRIVATE_NETWORK_KEY required")?;
    if psk_text.len() > 128 || !psk_text.is_ascii() {
        return Err("invalid cluster PSK".into());
    }
    let psk = psk_text.parse().map_err(|_| "invalid cluster PSK")?;
    let identity_file = config.identity_file.clone();
    let discovery_cluster = config.cluster_id.clone();
    let (node, _store, mut network, service) = start(config, database, psk).await?;
    if learner_only {
        // ponytail: transport/catch-up only; serving requires an explicit future authorization workflow.
        tokio::select! {
            result = &mut network => return Err(format!("learner transport stopped: {result:?}")),
            _ = async {
                let mut metrics = node.metrics();
                loop {
                    if metrics.borrow().running_state.is_err() { break; }
                    if metrics.changed().await.is_err() { break; }
                }
            } => return Err("learner consensus stopped".into()),
        }
    }
    let discovery_key = crate::raft_network::replica_identity(std::path::Path::new(&identity_file))
        .map_err(|e| e.to_string())?;
    let control = private_control(service.clone(), discovery_key.clone());
    let discovery_service = service.clone();
    let discovery = async move {
        let Ok(listen) = std::env::var("DISCOVERY_LISTEN_ADDRESS") else {
            return std::future::pending::<Result<(), String>>().await;
        };
        let mut swarm = cat4igp_shared::discovery::transport::swarm(&discovery_key)?;
        swarm
            .listen_on(
                listen
                    .parse()
                    .map_err(|_| "invalid discovery listen address")?,
            )
            .map_err(|e| e.to_string())?;
        let serving = discovery_key.public().to_peer_id();
        // ponytail: one bounded quorum lookup at a time; add concurrent dispatch for higher traffic.
        let join_service = discovery_service.clone();
        cat4igp_shared::discovery::transport::serve_with_join(
            swarm,
            &discovery_cluster,
            move |query, source| {
                let service = discovery_service.clone();
                async move {
                    match service
                        .submit(Operation::Discovery {
                            query,
                            source,
                            serving,
                        })
                        .await
                    {
                        Outcome::Discovery(result) => result,
                        _ => Err("discovery authority unavailable".into()),
                    }
                }
            },
            move |request, source| {
                let service = join_service.clone();
                async move {
                    match service.submit(Operation::Join { source, request }).await {
                        Outcome::Join(response) => response,
                        _ => cat4igp_shared::discovery::join::Response::Unavailable,
                    }
                }
            },
        )
        .await
    };
    let (jobs, mut work) = tokio::sync::mpsc::channel(crate::DATABASE_QUEUE_CAPACITY);
    let worker_service = service.clone();
    let mut worker = tokio::spawn(async move {
        while let Some(job) = work.recv().await {
            match job {
                crate::DatabaseJob::Invite {
                    request_id,
                    expires_at,
                    max_uses,
                    join_mesh,
                    reply,
                } => {
                    // Serial allocation and committed application; no local SQL fallback on any error.
                    let result = match worker_service
                        .submit(Operation::Invite {
                            request_id,
                            expires_at,
                            max_uses,
                            join_mesh,
                        })
                        .await
                    {
                        Outcome::Invite(result) => Ok(result),
                        _ => Err(diesel::result::Error::RollbackTransaction),
                    };
                    let _ = reply.send(result);
                }
                crate::DatabaseJob::Control(..) => unreachable!("cluster control is not enabled"),
            }
        }
    });
    // Explicit endpoint grants never follow admission/promotion automatically.
    let authority_read = service.clone();
    let authority_write = service.clone();
    let authority_init = service.clone();
    let code_read = service.clone();
    let code_rotate = service.clone();
    let learner = service.clone();
    let promotion = service.clone();
    let revocation = service.clone();
    let serving_grant = service.clone();
    let prepare_transport = service.clone();
    let complete_transport = service.clone();
    let authority_routes = axum::Router::new()
        .route(
            "/operator/transport_rotation",
            axum::routing::post(move |axum::Json(next): axum::Json<TransportCredential>| {
                let service = prepare_transport.clone();
                async move {
                    match service.submit(Operation::PrepareTransport(next)).await {
                        Outcome::Transport(Ok(state)) => Ok(axum::Json(state)),
                        Outcome::Transport(Err(_)) => Err(axum::http::StatusCode::CONFLICT),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            }),
        )
        .route(
            "/operator/transport_rotation/complete",
            axum::routing::post(move || {
                let service = complete_transport.clone();
                async move {
                    match service.submit(Operation::CompleteTransport).await {
                        Outcome::Transport(Ok(state)) => Ok(axum::Json(state)),
                        Outcome::Transport(Err(_)) => Err(axum::http::StatusCode::CONFLICT),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            }),
        )
        .route(
            "/operator/grant_serving",
            axum::routing::post(move |axum::Json(grant): axum::Json<ServingGrant>| {
                let service = serving_grant.clone();
                async move {
                    match service.submit(Operation::GrantServing(grant)).await {
                        Outcome::Roster(Ok(())) => axum::http::StatusCode::NO_CONTENT,
                        Outcome::Roster(Err(_)) => axum::http::StatusCode::CONFLICT,
                        _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    }
                }
            }),
        )
        .route(
            "/operator/revoke_replica",
            axum::routing::post(move |axum::Json(id): axum::Json<u64>| {
                let service = revocation.clone();
                async move {
                    match service.submit(Operation::RevokeReplica(id)).await {
                        Outcome::Revocation(Ok(())) => axum::http::StatusCode::NO_CONTENT,
                        Outcome::Revocation(Err(_)) => axum::http::StatusCode::CONFLICT,
                        _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    }
                }
            }),
        )
        .route(
            "/operator/promote_learner",
            axum::routing::post(move |axum::Json(id): axum::Json<u64>| {
                let service = promotion.clone();
                async move {
                    match service.submit(Operation::PromoteLearner(id)).await {
                        Outcome::Promotion(Ok(())) => axum::http::StatusCode::NO_CONTENT,
                        Outcome::Promotion(Err(_)) => axum::http::StatusCode::CONFLICT,
                        _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    }
                }
            }),
        )
        .route(
            "/operator/activate_learner",
            axum::routing::post(move |axum::Json(id): axum::Json<u64>| {
                let service = learner.clone();
                async move {
                    match service.submit(Operation::ActivateLearner(id)).await {
                        Outcome::Learner(Ok(())) => axum::http::StatusCode::NO_CONTENT,
                        Outcome::Learner(Err(_)) => axum::http::StatusCode::CONFLICT,
                        _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    }
                }
            }),
        )
        .route(
            "/operator/replica_enrollment_code",
            axum::routing::get(move || {
                let service = code_read.clone();
                async move {
                    match service
                        .submit(Operation::ReplicaCode {
                            rotate_generation: None,
                        })
                        .await
                    {
                        Outcome::ReplicaCode(Ok(code)) => Ok((
                            [(axum::http::header::CACHE_CONTROL, "no-store")],
                            axum::Json(code),
                        )),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            })
            .put(move |axum::Json(expected_generation): axum::Json<u64>| {
                let service = code_rotate.clone();
                async move {
                    match service
                        .submit(Operation::ReplicaCode {
                            rotate_generation: Some(expected_generation),
                        })
                        .await
                    {
                        Outcome::ReplicaCode(Ok(code)) => Ok((
                            [(axum::http::header::CACHE_CONTROL, "no-store")],
                            axum::Json(code),
                        )),
                        Outcome::ReplicaCode(Err(_)) => Err(axum::http::StatusCode::CONFLICT),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            }),
        )
        .route(
            "/operator/controller_authority",
            axum::routing::get(move || {
                let service = authority_read.clone();
                async move {
                    match service.submit(Operation::Authority).await {
                        Outcome::Authority(Ok(authority)) => Ok(axum::Json(authority)),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            })
            .post(move || {
                let service = authority_init.clone();
                async move {
                    match service.submit(Operation::InitializeAuthority).await {
                        Outcome::Roster(Ok(())) => Ok(axum::http::StatusCode::NO_CONTENT),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            })
            .put(move |axum::Json(roster): axum::Json<ControllerRoster>| {
                let service = authority_write.clone();
                async move {
                    match service.submit(Operation::Roster(roster)).await {
                        Outcome::Roster(Ok(())) => Ok(axum::http::StatusCode::NO_CONTENT),
                        Outcome::Roster(Err(_)) => Err(axum::http::StatusCode::CONFLICT),
                        _ => Err(axum::http::StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(
            cat4igp_shared::discovery::MAX_MESSAGE_BYTES,
        ))
        .layer(axum::middleware::from_fn(
            crate::router::auth_middleware_operator,
        ));
    let scheduler = service.clone();
    let readiness = service;
    let app = crate::router::make_router(jobs)
        .await
        .map_err(|e| e.to_string())?
        .merge(authority_routes)
        .route(
            "/cluster/ready",
            axum::routing::get(move || {
                let node = readiness.clone();
                async move {
                    match node.submit(Operation::Ready).await {
                        Outcome::Ready => axum::http::StatusCode::NO_CONTENT,
                        _ => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    }
                }
            }),
        );
    let listener =
        tokio::net::TcpListener::bind(std::env::var("BIND_HOST_PORT").map_err(|e| e.to_string())?)
            .await
            .map_err(|e| e.to_string())?;
    eprintln!("[cluster] committed ingress and opt-in discovery/private control");
    tokio::select! {
        _ = scheduler.schedule_codes() => Err("code scheduler stopped".into()),
        result = control => Err(format!("private control stopped: {result:?}")),
        result = discovery => Err(format!("public discovery stopped: {result:?}")),
        _ = async {
            let mut metrics = node.metrics();
            loop {
                if metrics.borrow().running_state.is_err() { break; }
                if metrics.changed().await.is_err() { break; }
            }
        } => Err("Raft stopped (fatal storage/runtime error)".into()),
        result = axum::serve(listener, app) => result.map_err(|e| e.to_string()),
        result = &mut network => Err(format!("cluster transport stopped: {result:?}")),
        result = &mut worker => Err(format!("cluster submission stopped: {result:?}")),
    }
}

#[cfg(test)]
#[path = "cluster_test.rs"]
mod tests;
