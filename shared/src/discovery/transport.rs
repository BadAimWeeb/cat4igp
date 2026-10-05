//! Public metadata plus a separate bounded direct replica join protocol; no cluster PSK.
use super::*;
use futures_util::StreamExt;
use libp2p::{
    StreamProtocol,
    core::{Transport, upgrade::Version},
    gossipsub, noise, request_response,
    swarm::NetworkBehaviour,
    swarm::{Config, Swarm, SwarmEvent},
    tcp, yamux,
};
use std::{collections::VecDeque, time::Duration};

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub struct Behaviour {
    pub gossip: gossipsub::Behaviour,
    pub join: request_response::json::Behaviour<super::join::Request, super::join::Response>,
}

#[derive(Debug)]
pub enum Event {
    Gossip(gossipsub::Event),
    Join(request_response::Event<super::join::Request, super::join::Response>),
}
impl From<gossipsub::Event> for Event {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossip(e)
    }
}
impl From<request_response::Event<super::join::Request, super::join::Response>> for Event {
    fn from(e: request_response::Event<super::join::Request, super::join::Response>) -> Self {
        Self::Join(e)
    }
}

pub fn swarm(key: &identity::Keypair) -> Result<Swarm<Behaviour>, String> {
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key).map_err(|e| e.to_string())?)
        .multiplex(yamux::Config::default())
        .boxed();
    let config = gossipsub::ConfigBuilder::default()
        .protocol_id_prefix("/cat4igp/discovery/1")
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(MAX_MESSAGE_BYTES)
        .heartbeat_interval(Duration::from_millis(500))
        .build()
        .map_err(|e| e.to_string())?;
    let behaviour =
        gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)
            .map_err(|e| e.to_string())?;
    Ok(Swarm::new(
        transport,
        Behaviour {
            gossip: behaviour,
            join: request_response::json::Behaviour::with_codec(
                request_response::json::codec::Codec::default()
                    .set_request_size_maximum(4096)
                    .set_response_size_maximum(65536),
                [(
                    StreamProtocol::new("/cat4igp/replica-join/1"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(10))
                    .with_max_concurrent_streams(16),
            ),
        },
        key.public().to_peer_id(),
        Config::with_tokio_executor().with_idle_connection_timeout(Duration::from_secs(60)),
    ))
}

fn subscribe(
    swarm: &mut Swarm<Behaviour>,
    cluster: &str,
    role: Role,
) -> Result<gossipsub::Sha256Topic, String> {
    let topic = gossipsub::Sha256Topic::new(topic(cluster, role)?);
    swarm
        .behaviour_mut()
        .gossip
        .subscribe(&topic)
        .map_err(|e| e.to_string())?;
    Ok(topic)
}

/// Queries only out-of-band or previously signature-verified PUBLIC bootstrap PeerIds.
/// Returned proof must be persisted by callers before using a higher roster revision.
pub async fn discover(
    key: &identity::Keypair,
    pin: &identity::PublicKey,
    cluster: &str,
    role: Role,
    bootstraps: &[Multiaddr],
    minimum_revision: u64,
) -> Result<Signed<ControllerAvailable>, String> {
    if bootstraps.is_empty() || bootstraps.len() > 16 {
        return Err("discovery needs 1..16 trusted bootstrap addresses".into());
    }
    for address in bootstraps {
        let Some(Protocol::P2p(peer_id)) = address.iter().last() else {
            return Err("bootstrap must end in a trusted PeerId".into());
        };
        ControllerEndpoint {
            peer_id,
            addresses: vec![address.clone()],
        }
        .validate()?;
    }
    let mut swarm = swarm(key)?;
    let topic = subscribe(&mut swarm, cluster, role)?;
    let mut dialing = false;
    for address in bootstraps {
        dialing |= swarm.dial(address.clone()).is_ok();
    }
    if !dialing {
        return Err("discovery unavailable: no trusted bootstrap dial started".into());
    }
    let pending = FindControllers::new(cluster.into(), role, key.public().to_peer_id(), now())?;
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    // New signed messages on retries bypass Gossipsub's message-id deduplication,
    // while the application nonce remains stable for response correlation.
    let mut retry = tokio::time::interval(Duration::from_millis(
        600 + u64::from(rand08::random::<u8>()),
    ));
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("discovery unavailable: trusted bootstrap/mesh deadline exceeded".into()),
            _ = retry.tick() => {
                if swarm.connected_peers().next().is_some() {
                    match swarm.behaviour_mut().gossip.publish(topic.clone(), encode(&pending)?) {
                        Ok(_) | Err(gossipsub::PublishError::NoPeersSubscribedToTopic | gossipsub::PublishError::AllQueuesFull(_)) => {},
                        Err(error) => return Err(error.to_string()),
                    }
                }
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(Event::Gossip(gossipsub::Event::Message { message, .. })) = event {
                    if message.topic != topic.hash() { continue; }
                    let Some(source) = message.source else { continue; };
                    let Ok(response) = decode::<Signed<ControllerAvailable>>(&message.data) else { continue; };
                    if response.validate(pin, &pending, source, minimum_revision, now()).is_ok() {
                        return Ok(response);
                    }
                }
            }
        }
    }
}

/// Serve an externally authorized, short-lived roster; never invent membership.
pub async fn serve(
    swarm: Swarm<Behaviour>,
    signing_key: identity::Keypair,
    roster: Signed<ControllerRoster>,
) -> Result<(), String> {
    roster.validate(&signing_key.public(), &roster.body.cluster_id, 0, now())?;
    let peer = *swarm.local_peer_id();
    let cluster = roster.body.cluster_id.clone();
    serve_with(swarm, &cluster, move |query, source| {
        let result = respond(&signing_key, &roster, peer, &query, source, now());
        std::future::ready(result)
    })
    .await
}

/// Bind public metadata to a verified query, logical authority and serving transport identity.
pub fn respond(
    key: &identity::Keypair,
    roster: &Signed<ControllerRoster>,
    peer: PeerId,
    query: &FindControllers,
    source: PeerId,
    time: i64,
) -> Result<Signed<ControllerAvailable>, String> {
    roster.validate(&key.public(), &roster.body.cluster_id, 0, time)?;
    query.validate(source, &roster.body.cluster_id, query.role, time)?;
    let endpoint = roster
        .body
        .controllers
        .iter()
        .find(|e| e.peer_id == peer)
        .ok_or("discovery identity not authorized by roster")?
        .clone();
    ControllerAvailable {
        version: VERSION,
        cluster_id: query.cluster_id.clone(),
        role: query.role,
        recipient: source,
        nonce: query.nonce,
        issued_at_ms: time,
        expires_at_ms: query.expires_at_ms.min(roster.body.expires_at_ms),
        endpoint,
        roster: roster.clone(),
    }
    .sign(key)
    .map_err(str::to_owned)
}

/// Resolve authority for each accepted query; unavailable authority emits nothing.
pub async fn serve_with<F, Fut>(
    swarm: Swarm<Behaviour>,
    cluster: &str,
    responder: F,
) -> Result<(), String>
where
    F: FnMut(FindControllers, PeerId) -> Fut,
    Fut: std::future::Future<Output = Result<Signed<ControllerAvailable>, String>>,
{
    serve_with_join(swarm, cluster, responder, |_, _| {
        std::future::ready(super::join::Response::Unavailable)
    })
    .await
}

/// Native stream bounds, global/source quotas and serial dispatch bound pre-admission work.
pub async fn serve_with_join<F, Fut, J, JFut>(
    mut swarm: Swarm<Behaviour>,
    cluster: &str,
    mut responder: F,
    mut join: J,
) -> Result<(), String>
where
    F: FnMut(FindControllers, PeerId) -> Fut,
    Fut: std::future::Future<Output = Result<Signed<ControllerAvailable>, String>>,
    J: FnMut(super::join::Request, PeerId) -> JFut,
    JFut: std::future::Future<Output = super::join::Response>,
{
    let client = subscribe(&mut swarm, cluster, Role::Client)?;
    let replica = subscribe(&mut swarm, cluster, Role::Replica)?;
    let mut seen = VecDeque::new();
    let mut sources = VecDeque::new();
    let mut window = now();
    let mut count = 0;
    let mut join_sources = VecDeque::new();
    let mut join_window = now();
    let mut join_count = 0;
    loop {
        let event = swarm.select_next_some().await;
        if let SwarmEvent::Behaviour(Event::Join(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) = event
        {
            let time = now();
            if time - join_window >= 1000 {
                join_window = time;
                join_count = 0;
            }
            join_sources.retain(|(_, until)| *until > time);
            let response = if join_count >= 8 || join_sources.iter().any(|(p, _)| *p == peer) {
                super::join::Response::Unavailable
            } else {
                join_count += 1;
                if join_sources.len() == 256 {
                    join_sources.pop_front();
                }
                join_sources.push_back((peer, time + 1000));
                if request.validate(peer, cluster).is_err() {
                    super::join::Response::Rejected
                } else {
                    // ponytail: serial bounded join dispatch; add a completion queue for higher load.
                    tokio::time::timeout(Duration::from_secs(10), join(request, peer))
                        .await
                        .unwrap_or(super::join::Response::Unavailable)
                }
            };
            let _ = swarm.behaviour_mut().join.send_response(channel, response);
            continue;
        }
        if let SwarmEvent::Behaviour(Event::Gossip(gossipsub::Event::Message { message, .. })) =
            event
        {
            let time = now();
            let role = if message.topic == client.hash() {
                Role::Client
            } else if message.topic == replica.hash() {
                Role::Replica
            } else {
                continue;
            };
            let Some(source) = message.source else {
                continue;
            };
            if time - window >= 1000 {
                window = time;
                count = 0;
            }
            // ponytail: global 32-message/s, one/source/s and 256-entry caches;
            // add byte-budget/concurrent resolution for higher discovery traffic.
            if count >= 32 {
                continue;
            }
            count += 1;
            sources.retain(|(_, until)| *until > time);
            if sources.iter().any(|(peer, _)| *peer == source) {
                continue;
            }
            if sources.len() == 256 {
                sources.pop_front();
            }
            sources.push_back((source, time + 1000));
            let Ok(query) = decode::<FindControllers>(&message.data) else {
                continue;
            };
            if query.validate(source, cluster, role, time).is_err() {
                continue;
            }
            seen.retain(|(_, _, expires)| *expires > time);
            if seen
                .iter()
                .any(|(peer, nonce, _)| *peer == source && *nonce == query.nonce)
            {
                continue;
            }
            let nonce = query.nonce;
            let Ok(response) = responder(query, source).await else {
                continue;
            };
            if now() >= response.body.expires_at_ms {
                continue;
            }
            let topic = if role == Role::Client {
                &client
            } else {
                &replica
            };
            match swarm
                .behaviour_mut()
                .gossip
                .publish(topic.clone(), encode(&response)?)
            {
                Ok(_) => {
                    if seen.len() == 256 {
                        seen.pop_front();
                    }
                    // Retry the same nonce after one second if a response was lost.
                    seen.push_back((source, nonce, time + 1000));
                }
                Err(
                    gossipsub::PublishError::NoPeersSubscribedToTopic
                    | gossipsub::PublishError::AllQueuesFull(_),
                ) => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}
