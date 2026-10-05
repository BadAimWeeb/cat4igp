//! Admitted private replica RPCs and best-effort immutable topology ciphertext relay.
use std::{collections::BTreeMap, io, path::Path, sync::Arc, time::Duration};

use futures_util::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    core::{Transport, upgrade::Version},
    gossipsub, identity, noise,
    pnet::{PnetConfig, PreSharedKey},
    request_response::{self as rr, json},
    swarm::{Config as SwarmConfig, SwarmEvent},
    tcp, yamux,
};
use openraft::{
    BasicNode, Raft, RaftNetwork, RaftNetworkFactory,
    error::{
        InstallSnapshotError, PayloadTooLarge, RPCError, RaftError, RemoteError, Timeout,
        Unreachable,
    },
    network::{RPCOption, RPCTypes},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};

use crate::raft_storage::TypeConfig;
type Node = Raft<TypeConfig>;
type Error = Box<dyn std::error::Error + Send + Sync>;
const LIMIT: usize = 1024 * 1024;
const CAPACITY: usize = 32;
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    rpc: json::Behaviour<Request, Response>,
    gossip: gossipsub::Behaviour,
}

/// Separate from logical controller keys and the client-network PSK. Never regenerate on error.
pub fn replica_identity(path: &Path) -> Result<identity::Keypair, Error> {
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    match fs::File::open(path) {
        Ok(file) => {
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.len() > 4096
            {
                return Err(io::Error::other("replica key must be private and bounded").into());
            }
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(io::Error::other("replica key exceeds limit").into());
            }
            Ok(identity::Keypair::from_protobuf_encoding(&bytes)?)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = identity::Keypair::generate_ed25519();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&key.to_protobuf_encoding()?)?;
            file.sync_all()?;
            fs::File::open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Clone, PartialEq)]
pub struct Binding {
    pub peer: PeerId,
    pub address: Multiaddr,
}

#[derive(Debug, Serialize, Deserialize)]
enum Rpc {
    Operator(crate::cluster::Operation),
    Vote(VoteRequest<u64>),
    Append(AppendEntriesRequest<TypeConfig>),
    Snapshot(InstallSnapshotRequest<TypeConfig>),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    application_version: u8,
    cluster: String,
    source: u64,
    target: u64,
    rpc: Rpc,
}
#[derive(Debug, Serialize, Deserialize)]
enum Response {
    Operator(crate::cluster::Outcome),
    Vote(Result<VoteResponse<u64>, RaftError<u64>>),
    Append(Result<AppendEntriesResponse<u64>, RaftError<u64>>),
    Snapshot(Result<InstallSnapshotResponse<u64>, RaftError<u64, InstallSnapshotError>>),
    Rejected,
}
struct Call {
    cluster: String,
    target: u64,
    rpc: Rpc,
    expires: Instant,
    reply: oneshot::Sender<Result<Response, &'static str>>,
}

#[derive(Clone)]
pub struct Network {
    id: u64,
    cluster: String,
    bindings: watch::Sender<BTreeMap<u64, Binding>>,
    bootstrap: Arc<BTreeMap<u64, Binding>>,
    updates: mpsc::Sender<(BTreeMap<u64, Binding>, oneshot::Sender<()>)>,
    tx: mpsc::Sender<Call>,
    service: watch::Sender<Option<crate::cluster::Service>>,
    relay: mpsc::Sender<Vec<u8>>,
    notifications: tokio::sync::broadcast::Sender<Vec<u8>>,
    relay_authority: watch::Sender<RelayAuthority>,
}
#[derive(Clone, Default)]
// ponytail: applied-store watch is eventually reconciled; explicit key rotation needs a committed continuity protocol.
pub(crate) struct RelayAuthority {
    pin: Option<(identity::PublicKey, String)>,
    roster: Option<cat4igp_shared::discovery::Signed<cat4igp_shared::discovery::ControllerRoster>>,
    active: bool,
}

impl RelayAuthority {
    fn refresh(&mut self, authority: Option<crate::cluster::Authority>) {
        self.active = false;
        let Some(authority) = authority else {
            return;
        };
        let Ok(bytes) = crate::hex_decode(&authority.signing_key) else {
            return;
        };
        let Ok(key) = identity::PublicKey::try_decode_protobuf(&bytes) else {
            return;
        };
        let pin = (key, authority.network_id);
        if self.pin.as_ref().is_some_and(|previous| previous != &pin) {
            return;
        }
        // Pin continuity survives invalid/expired/missing proofs. Rotation needs an explicit protocol.
        self.pin = Some(pin.clone());
        let Some(roster) = authority.roster else {
            return;
        };
        if roster
            .validate(&pin.0, &pin.1, 1, roster.body.issued_at_ms)
            .is_err()
        {
            return;
        }
        if self.roster.as_ref().is_some_and(|previous| {
            roster.body.revision < previous.body.revision
                || (roster.body.revision == previous.body.revision
                    && cat4igp_shared::discovery::encode(&roster).ok()
                        != cat4igp_shared::discovery::encode(previous).ok())
                || roster.body.issued_at_ms < previous.body.issued_at_ms
                || roster.body.expires_at_ms < previous.body.expires_at_ms
        }) {
            return;
        }
        self.roster = Some(roster);
        self.active = true;
    }

    pub(crate) fn permits(&self, peer: PeerId, now: i64) -> bool {
        self.active
            && self.pin.as_ref().zip(self.roster.as_ref()).is_some_and(
                |((key, network), roster)| {
                    roster.validate(key, network, 1, now).is_ok()
                        && roster
                            .body
                            .controllers
                            .iter()
                            .any(|endpoint| endpoint.peer_id == peer)
                },
            )
    }

    pub(crate) fn verify(&self, peer: PeerId, payload: &[u8]) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        self.permits(peer, now)
            && self.pin.as_ref().is_some_and(|(key, network)| {
                cat4igp_shared::control::verify_topology_relay(key, network, now, payload).is_ok()
            })
    }
}
pub struct Client {
    target: u64,
    network: Network,
}

fn unavailable<E: std::error::Error>(reason: &'static str) -> RPCError<u64, BasicNode, E> {
    RPCError::Unreachable(Unreachable::new(&io::Error::other(reason)))
}

impl Network {
    pub(crate) fn bootstrap_endpoints(
        &self,
    ) -> BTreeMap<u64, cat4igp_shared::discovery::ControllerEndpoint> {
        self.bootstrap
            .iter()
            .filter(|(id, binding)| self.bindings.borrow().get(id) == Some(*binding))
            .map(|(id, b)| {
                let mut address = b.address.clone();
                if !matches!(
                    address.iter().last(),
                    Some(libp2p::multiaddr::Protocol::P2p(_))
                ) {
                    address.push(libp2p::multiaddr::Protocol::P2p(b.peer));
                }
                (
                    *id,
                    cat4igp_shared::discovery::ControllerEndpoint {
                        peer_id: b.peer,
                        addresses: vec![address],
                    },
                )
            })
            .collect()
    }
    pub(crate) async fn reconcile_store(
        &self,
        store: &crate::raft_storage::Store,
    ) -> Result<(), Error> {
        let bootstrap = self.bootstrap.clone();
        let cluster = self.cluster.clone();
        let (bindings, authority) = store
            .run(move |conn| {
                let bindings = committed_bindings(conn, &cluster, &bootstrap)?;
                let authority = crate::cluster::read_authority(conn)
                    .ok()
                    .map(|mut authority| {
                        let permitted = authority.roster.as_ref().is_some_and(|roster| {
                            crate::cluster::read_revocations(conn).is_ok_and(|revoked| {
                                roster.body.controllers.iter().all(|endpoint| {
                                    bindings
                                        .values()
                                        .any(|binding| binding.peer == endpoint.peer_id)
                                        && !revoked.values().any(|r| r.peer == endpoint.peer_id)
                                })
                            })
                        });
                        if !permitted {
                            authority.roster = None;
                        }
                        authority
                    });
                Ok((bindings, authority))
            })
            .await?;
        self.relay_authority
            .send_modify(|current| current.refresh(authority));
        self.reconcile(bindings).await
    }
    pub(crate) async fn reconcile(&self, bindings: BTreeMap<u64, Binding>) -> Result<(), Error> {
        validate_bindings(
            self.id,
            &bindings,
            self.bindings.borrow().get(&self.id).map(|b| b.peer),
        )?;
        let (reply, rx) = oneshot::channel();
        self.updates
            .send((bindings, reply))
            .await
            .map_err(|_| io::Error::other("transport stopped"))?;
        rx.await
            .map_err(|_| io::Error::other("transport stopped"))?;
        Ok(())
    }
    pub(crate) fn listen_topology(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.notifications.subscribe()
    }

    pub(crate) fn authority(&self) -> watch::Receiver<RelayAuthority> {
        self.relay_authority.subscribe()
    }

    pub(crate) fn publish_topology(&self, payload: Vec<u8>) {
        // ponytail: best-effort 32 x 64 KiB queue; linearizable client polling repairs loss.
        if payload.len() <= 64 * 1024 {
            let _ = self.relay.try_send(payload);
        }
    }

    pub(crate) fn consensus(&self) -> Self {
        let mut network = self.clone();
        network.service = watch::channel(None).0;
        network
    }

    pub(crate) fn attach_service(&self, service: crate::cluster::Service) {
        self.service.send_replace(Some(service));
    }

    pub(crate) async fn forward(
        &self,
        target: u64,
        operation: crate::cluster::Operation,
    ) -> crate::cluster::Outcome {
        match self
            .call::<RaftError<u64>>(target, Rpc::Operator(operation), RPCOption::new(DEADLINE))
            .await
        {
            Ok(Response::Operator(result)) => result,
            _ => crate::cluster::Outcome::Unavailable,
        }
    }

    async fn call<E: std::error::Error>(
        &self,
        target: u64,
        rpc: Rpc,
        option: RPCOption,
    ) -> Result<Response, RPCError<u64, BasicNode, E>> {
        if !self.bindings.borrow().contains_key(&target) || target == self.id {
            return Err(unavailable("unauthorized target"));
        }
        let request = Request {
            application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION,
            cluster: self.cluster.clone(),
            source: self.id,
            target,
            rpc,
        };
        let action = match &request.rpc {
            Rpc::Operator(_) => RPCTypes::AppendEntries,
            Rpc::Vote(_) => RPCTypes::Vote,
            Rpc::Append(_) => RPCTypes::AppendEntries,
            Rpc::Snapshot(_) => RPCTypes::InstallSnapshot,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| unavailable::<E>("encode failed"))?
            .len()
            >= LIMIT
        {
            if let Rpc::Append(r) = &request.rpc {
                if r.entries.len() > 1 {
                    return Err(
                        PayloadTooLarge::new_entries_hint((r.entries.len() / 2) as u64).into(),
                    );
                }
            }
            // ponytail: a single oversized application entry cannot split; bound ingress before production writes.
            return Err(unavailable(
                "RPC exceeds wire limit; reduce batch/chunk size",
            ));
        }
        let ttl = option.hard_ttl().min(DEADLINE);
        let expires = Instant::now() + ttl;
        let (reply, rx) = oneshot::channel();
        self.tx
            .try_send(Call {
                cluster: request.cluster,
                target,
                rpc: request.rpc,
                expires,
                reply,
            })
            .map_err(|_| unavailable::<E>("transport overloaded or stopped"))?;
        tokio::time::timeout_at(expires, rx)
            .await
            .map_err(|_| {
                RPCError::Timeout(Timeout {
                    action,
                    id: self.id,
                    target,
                    timeout: ttl,
                })
            })?
            .map_err(|_| unavailable::<E>("transport stopped"))?
            .map_err(unavailable)
    }

    /// Caller supplies a replica-only PSK and explicit admitted bindings, never client credentials.
    /// ponytail: 64 authorized bindings and 1 MiB RPC/32 work slots; no credential delivery or promotion.
    pub async fn start(
        id: u64,
        cluster: String,
        key: identity::Keypair,
        cluster_psk: PreSharedKey,
        bindings: BTreeMap<u64, Binding>,
        listen: Multiaddr,
    ) -> Result<
        (
            Self,
            Multiaddr,
            watch::Sender<Option<Node>>,
            tokio::task::JoinHandle<()>,
        ),
        Error,
    > {
        if cluster.is_empty()
            || cluster.len() > 128
            || bindings.len() > 64
            || bindings.get(&id).map(|b| b.peer) != Some(key.public().to_peer_id())
        {
            return Err(io::Error::other("invalid cluster/local binding").into());
        }
        validate_bindings(id, &bindings, Some(key.public().to_peer_id()))?;
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .and_then(move |socket, _| PnetConfig::new(cluster_psk).handshake(socket))
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&key)?)
            .multiplex(yamux::Config::default())
            .timeout(DEADLINE)
            .boxed();
        let codec = json::codec::Codec::default()
            .set_request_size_maximum(LIMIT as u64)
            .set_response_size_maximum(LIMIT as u64);
        let rpc = rr::Behaviour::with_codec(
            codec,
            [(
                StreamProtocol::new("/cat4igp/raft/1"),
                rr::ProtocolSupport::Full,
            )],
            rr::Config::default()
                .with_request_timeout(DEADLINE)
                .with_max_concurrent_streams(CAPACITY),
        );
        let mut gossip = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Strict)
                .validate_messages()
                .max_transmit_size(70 * 1024)
                .heartbeat_interval(Duration::from_millis(200))
                .build()?,
        )
        .map_err(io::Error::other)?;
        gossip.subscribe(&gossipsub::Sha256Topic::new(format!(
            "/cat4igp/cluster/topology/1/{cluster}"
        )))?;
        for binding in bindings.values() {
            if binding.peer != key.public().to_peer_id() {
                gossip.add_explicit_peer(&binding.peer);
            }
        }
        let mut swarm = Swarm::new(
            transport,
            Behaviour { rpc, gossip },
            key.public().to_peer_id(),
            SwarmConfig::with_tokio_executor(),
        );
        swarm.listen_on(listen)?;
        let address = tokio::time::timeout(DEADLINE, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => break Ok(address),
                    SwarmEvent::ListenerError { error, .. } => break Err(error),
                    _ => {}
                }
            }
        })
        .await??;
        let (tx, rx) = mpsc::channel(CAPACITY);
        let (relay, relay_rx) = mpsc::channel(CAPACITY);
        let (updates, update_rx) = mpsc::channel(1);
        let network = Self {
            id,
            cluster,
            bootstrap: Arc::new(bindings.clone()),
            bindings: watch::channel(bindings).0,
            updates,
            tx,
            service: watch::channel(None).0,
            relay,
            notifications: tokio::sync::broadcast::channel(CAPACITY).0,
            relay_authority: watch::channel(RelayAuthority::default()).0,
        };
        let (attach, node) = watch::channel(None);
        let task = tokio::spawn(run(swarm, network.clone(), rx, node, relay_rx, update_rx));
        Ok((network, address, attach, task))
    }
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Client;
    async fn new_client(&mut self, target: u64, _node: &BasicNode) -> Client {
        Client {
            target,
            network: self.clone(),
        }
    }
}
impl RaftNetwork<TypeConfig> for Client {
    async fn vote(
        &mut self,
        rpc: VoteRequest<u64>,
        option: RPCOption,
    ) -> Result<VoteResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self
            .network
            .call(self.target, Rpc::Vote(rpc), option)
            .await?
        {
            Response::Vote(result) => {
                result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            _ => Err(unavailable("unexpected vote response")),
        }
    }
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<u64>, RPCError<u64, BasicNode, RaftError<u64>>> {
        match self
            .network
            .call(self.target, Rpc::Append(rpc), option)
            .await?
        {
            Response::Append(result) => {
                result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            _ => Err(unavailable("unexpected append response")),
        }
    }
    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<u64>,
        RPCError<u64, BasicNode, RaftError<u64, InstallSnapshotError>>,
    > {
        match self
            .network
            .call(self.target, Rpc::Snapshot(rpc), option)
            .await?
        {
            Response::Snapshot(result) => {
                result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
            }
            _ => Err(unavailable("unexpected snapshot response")),
        }
    }
}

fn authorized(network: &Network, peer: PeerId, request: &Request) -> bool {
    let leader = match &request.rpc {
        Rpc::Operator(_) => request.source,
        Rpc::Vote(r) => r.vote.leader_id.node_id,
        Rpc::Append(r) => r.vote.leader_id.node_id,
        Rpc::Snapshot(r) => r.vote.leader_id.node_id,
    };
    request.application_version == cat4igp_shared::discovery::join::APPLICATION_VERSION
        && request.cluster == network.cluster
        && (!matches!(request.rpc, Rpc::Operator(_))
            || network.bootstrap.get(&request.source).map(|b| b.peer) == Some(peer)
            || (matches!(
                request.rpc,
                Rpc::Operator(
                    crate::cluster::Operation::Discovery { .. }
                        | crate::cluster::Operation::Client { .. }
                        | crate::cluster::Operation::AffectedSnapshots { .. }
                )
            ) && network
                .relay_authority
                .borrow()
                .permits(peer, chrono::Utc::now().timestamp_millis())))
        && request.target == network.id
        && request.source == leader
        && request.source != network.id
        && network
            .bindings
            .borrow()
            .get(&request.source)
            .map(|b| b.peer)
            == Some(peer)
}

fn validate_bindings(
    id: u64,
    bindings: &BTreeMap<u64, Binding>,
    local: Option<PeerId>,
) -> Result<(), Error> {
    if bindings.len() > 64
        || bindings.contains_key(&0)
        || local.is_none()
        || bindings.get(&id).map(|b| b.peer) != local
    {
        return Err(io::Error::other("invalid local transport authorization").into());
    }
    let mut peers = std::collections::HashSet::new();
    let mut addresses = std::collections::HashSet::new();
    for binding in bindings.values() {
        let mut address = binding.address.clone();
        if matches!(
            address.iter().last(),
            Some(libp2p::multiaddr::Protocol::P2p(_))
        ) {
            address.pop();
        }
        if !peers.insert(binding.peer)
            || !addresses.insert(address)
            || binding.address.iter().any(
                |p| matches!(p, libp2p::multiaddr::Protocol::P2p(peer) if peer != binding.peer),
            )
        {
            return Err(io::Error::other("duplicate or conflicting transport binding").into());
        }
    }
    Ok(())
}

fn committed_bindings(
    conn: &mut diesel::SqliteConnection,
    cluster: &str,
    bootstrap: &BTreeMap<u64, Binding>,
) -> Result<BTreeMap<u64, Binding>, Error> {
    use diesel::OptionalExtension;
    let Some(saved) = crate::db::get_setting(conn, "controller_admitted").optional()? else {
        // ponytail: explicit static bootstrap before first authority commit; never infer voters from discovery.
        // Tombstones without committed authority cannot override explicit bootstrap trust.
        return Ok(bootstrap.clone());
    };
    let revoked = crate::cluster::read_revocations(conn)?;
    let admitted: BTreeMap<u64, PeerId> = serde_json::from_str(&saved)?;
    if admitted
        != bootstrap
            .iter()
            .filter(|(id, _)| admitted.contains_key(id))
            .map(|(id, b)| (*id, b.peer))
            .collect()
    {
        return Err(io::Error::other("bootstrap differs from committed authority").into());
    }
    let pending: Vec<crate::cluster::Admission> =
        crate::db::get_setting(conn, "replica_pending_admissions")
            .optional()?
            .map(|s| serde_json::from_str(&s))
            .transpose()?
            .unwrap_or_default();
    let mut bindings: BTreeMap<_, _> = bootstrap
        .iter()
        .filter(|(id, _)| admitted.contains_key(id))
        .map(|(id, b)| (*id, b.clone()))
        .collect();
    for admission in pending {
        admission
            .request
            .validate(admission.source, cluster)
            .map_err(io::Error::other)?;
        if bindings
            .insert(
                admission.request.node_id,
                Binding {
                    peer: admission.source,
                    address: admission.request.address,
                },
            )
            .is_some()
        {
            return Err(io::Error::other("committed node collision").into());
        }
    }
    if bootstrap.iter().any(|(id, b)| {
        !admitted.contains_key(id)
            && !revoked
                .get(id)
                .is_some_and(|r| r.complete && r.peer == b.peer)
            && !bindings
                .get(id)
                .is_some_and(|saved| saved.peer == b.peer && saved.address == b.address)
    }) {
        return Err(io::Error::other("learner bootstrap differs from committed admission").into());
    }
    // Validate collisions before any transport update, including bootstrap address collisions.
    bindings.retain(|id, b| {
        !revoked
            .iter()
            .any(|(r_id, r)| r.complete && (*id == *r_id || b.peer == r.peer))
    });
    let (&id, binding) = bindings
        .iter()
        .next()
        .ok_or_else(|| io::Error::other("empty bootstrap"))?;
    validate_bindings(id, &bindings, Some(binding.peer))?;
    Ok(bindings)
}

#[cfg(test)]
#[path = "raft_network_test.rs"]
mod tests;

async fn run(
    mut swarm: Swarm<Behaviour>,
    network: Network,
    mut calls: mpsc::Receiver<Call>,
    mut node: watch::Receiver<Option<Node>>,
    mut relays: mpsc::Receiver<Vec<u8>>,
    mut updates: mpsc::Receiver<(BTreeMap<u64, Binding>, oneshot::Sender<()>)>,
) {
    let topic =
        gossipsub::Sha256Topic::new(format!("/cat4igp/cluster/topology/1/{}", network.cluster));
    let mut revisions = BTreeMap::new();
    let mut pending = BTreeMap::<
        rr::OutboundRequestId,
        (
            PeerId,
            Instant,
            oneshot::Sender<Result<Response, &'static str>>,
        ),
    >::new();
    let mut work = JoinSet::new();
    let mut sources =
        std::collections::HashMap::<tokio::task::Id, (PeerId, tokio::task::AbortHandle)>::new();
    let snapshots = Arc::new(tokio::sync::Semaphore::new(1));
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    loop {
        tokio::select! {
            Some((bindings, reply)) = updates.recv() => {
                let old = network.bindings.borrow().clone();
                for (id, binding) in &old {
                    if bindings.get(id) != Some(binding) {
                        // Cancel only this identity's work, not unrelated forwarding/consensus.
                        for (peer, task) in sources.values() {
                            if *peer == binding.peer { task.abort(); }
                        }
                        swarm.behaviour_mut().gossip.remove_explicit_peer(&binding.peer);
                        let _ = swarm.disconnect_peer_id(binding.peer);
                        pending.retain(|_, (peer, _, _)| *peer != binding.peer);
                    }
                }
                for binding in bindings.values() {
                    if binding.peer != *swarm.local_peer_id() && network.bootstrap.values().any(|b| b.peer == binding.peer) {
                        swarm.behaviour_mut().gossip.add_explicit_peer(&binding.peer);
                    }
                }
                network.bindings.send_replace(bindings);
                let _ = reply.send(());
            }
            Some(payload) = relays.recv() => {
                if accept_relay(&network, &mut revisions, &payload) {
                    if let Err(error) = swarm.behaviour_mut().gossip.publish(topic.clone(), payload) {
                        eprintln!("[cluster topology] best-effort publish dropped: {error}");
                    }
                }
            }
            changed = node.changed() => { if changed.is_err() { break; } }
            _ = tick.tick() => {
                pending.retain(|_, (_, expires, _)| {
                    // Keep the slot until the native stream deadline, even when the caller cancels.
                    *expires > Instant::now()
                });
            }
            Some(call) = calls.recv() => {
                if call.reply.is_closed() || call.expires <= Instant::now() { continue; }
                if pending.len() >= CAPACITY { let _ = call.reply.send(Err("pending RPC limit")); continue; }
                let Some(binding) = network.bindings.borrow().get(&call.target).cloned() else {
                    let _ = call.reply.send(Err("authorization removed")); continue;
                };
                let request = Request { application_version: cat4igp_shared::discovery::join::APPLICATION_VERSION, cluster: call.cluster, source: network.id, target: call.target, rpc: call.rpc };
                let request_id = swarm.behaviour_mut().rpc.send_request_with_addresses(&binding.peer, request, vec![binding.address]);
                pending.insert(request_id, (binding.peer, Instant::now() + DEADLINE, call.reply));
            }
            Some(result) = work.join_next_with_id(), if !work.is_empty() => {
                match result {
                    Ok((id, (channel, response))) => {
                        sources.remove(&id);
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, response);
                    }
                    Err(error) => { sources.remove(&error.id()); }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if !network.bindings.borrow().values().any(|b| b.peer == peer_id) => { let _ = swarm.disconnect_peer_id(peer_id); }
                SwarmEvent::Behaviour(BehaviourEvent::Gossip(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                    let admitted = |peer| network.bootstrap.values().any(|b| b.peer == peer)
                        && network.bindings.borrow().values().any(|b| b.peer == peer);
                    let valid = admitted(propagation_source) && message.source.is_some_and(|peer| admitted(peer)
                        && network.relay_authority.borrow().permits(peer, chrono::Utc::now().timestamp_millis()))
                        && message.topic == topic.hash() && valid_relay(&network, &message.data);
                    let _ = swarm.behaviour_mut().gossip.report_message_validation_result(
                        &message_id, &propagation_source,
                        if valid { gossipsub::MessageAcceptance::Accept } else { gossipsub::MessageAcceptance::Reject });
                    if valid && accept_relay(&network, &mut revisions, &message.data) {
                        let _ = network.notifications.send(message.data);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(rr::Event::Message { peer, message, .. })) => match message {
                    rr::Message::Request { request, channel, .. } => {
                        let raft = node.borrow().clone();
                        if !authorized(&network, peer, &request) || work.len() >= CAPACITY || raft.is_none() {
                            let _ = swarm.behaviour_mut().rpc.send_response(channel, Response::Rejected);
                            continue;
                        }
                        if matches!(&request.rpc, Rpc::Operator(crate::cluster::Operation::Client { serving, .. } | crate::cluster::Operation::AffectedSnapshots { serving, .. }) if *serving != peer)
                            || (network.bootstrap.get(&request.source).map(|b| b.peer) != Some(peer)
                                && matches!(&request.rpc, Rpc::Operator(crate::cluster::Operation::Discovery { serving, .. }) if *serving != peer)) {
                            let _ = swarm.behaviour_mut().rpc.send_response(channel, Response::Rejected);
                            continue;
                        }
                        let snapshot_slot = if matches!(request.rpc, Rpc::Snapshot(_)) {
                            match snapshots.clone().try_acquire_owned() {
                                Ok(slot) => Some(slot),
                                Err(_) => { let _ = swarm.behaviour_mut().rpc.send_response(channel, Response::Rejected); continue; }
                            }
                        } else { None };
                        let raft = raft.unwrap();
                        let service = network.service.borrow().clone();
                        let task = work.spawn(async move {
                            let _snapshot_slot = snapshot_slot;
                            let response = tokio::time::timeout(DEADLINE, async {
                                match request.rpc {
                                    Rpc::Operator(operation) => Response::Operator(match service {
                                        Some(service) => service.local(operation).await,
                                        None => crate::cluster::Outcome::Unavailable,
                                    }),
                                    Rpc::Vote(r) => Response::Vote(raft.vote(r).await),
                                    Rpc::Append(r) => Response::Append(raft.append_entries(r).await),
                                    Rpc::Snapshot(r) => Response::Snapshot(raft.install_snapshot(r).await),
                                }
                            }).await.unwrap_or(Response::Rejected);
                            (channel, response)
                        });
                        sources.insert(task.id(), (peer, task));
                    }
                    rr::Message::Response { request_id, response } => {
                        if let Some((expected, _, reply)) = pending.remove(&request_id) {
                            let _ = reply.send(if peer == expected { Ok(response) } else { Err("wrong response peer") });
                        }
                    }
                },
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(rr::Event::OutboundFailure { request_id, .. })) => {
                    if let Some((_, _, reply)) = pending.remove(&request_id) { let _ = reply.send(Err("RPC connection failed")); }
                }
                _ => {}
            }
        }
    }
}

fn valid_relay(network: &Network, payload: &[u8]) -> bool {
    network
        .bindings
        .borrow()
        .get(&network.id)
        .is_some_and(|binding| {
            network
                .relay_authority
                .borrow()
                .verify(binding.peer, payload)
        })
}

fn accept_relay(network: &Network, revisions: &mut BTreeMap<i32, i64>, payload: &[u8]) -> bool {
    if !valid_relay(network, payload) {
        return false;
    }
    let envelope: cat4igp_shared::control::EncryptedEnvelope =
        serde_json::from_slice(payload).unwrap();
    let meta = envelope.meta;
    if revisions
        .get(&meta.recipient_node_id)
        .is_some_and(|r| *r >= meta.topology_revision)
    {
        return false;
    }
    // ponytail: bounded best-effort watermarks, not a second state authority; polling repairs eviction/drop.
    if revisions.len() >= 256 {
        revisions.clear();
    }
    revisions.insert(meta.recipient_node_id, meta.topology_revision);
    true
}
