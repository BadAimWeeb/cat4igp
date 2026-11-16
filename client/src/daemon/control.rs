use cat4igp_shared::control::{
    ControlRequest, ControlResponse, EncryptedEnvelope, TopologySnapshot, open_topology_snapshot,
    topology_topic,
};
use futures_util::StreamExt;
use libp2p::{
    StreamProtocol,
    core::{Transport, upgrade::Version},
    gossipsub, noise,
    pnet::{PnetConfig, PreSharedKey},
    request_response::{self, json},
    swarm::{Config as SwarmConfig, NetworkBehaviour, Swarm},
    tcp, yamux,
};
use std::collections::{HashSet, VecDeque};
use tokio::sync::{mpsc, oneshot};

const CONTROL_PROTOCOL: &str = "/cat4igp/control/1";

#[derive(NetworkBehaviour)]
struct ControlBehaviour {
    request_response: json::Behaviour<ControlRequest, ControlResponse>,
    gossipsub: gossipsub::Behaviour,
}

fn gossipsub(keypair: &libp2p::identity::Keypair) -> Result<gossipsub::Behaviour, String> {
    gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossipsub::ConfigBuilder::default()
            .protocol_id_prefix("/cat4igp/topology/1")
            .max_transmit_size(64 * 1024)
            .build()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn remember_message_id(
    seen: &mut HashSet<String>,
    order: &mut VecDeque<String>,
    message_id: String,
) -> bool {
    if !seen.insert(message_id.clone()) {
        return false;
    }
    order.push_back(message_id);
    // ponytail: remembers 256 messages per subscription; use expiry-based storage for higher traffic.
    if order.len() > 256 {
        if let Some(oldest) = order.pop_front() {
            seen.remove(&oldest);
        }
    }
    true
}

#[derive(Clone)]
pub struct ControlPlane(mpsc::Sender<Command>, std::sync::Arc<Worker>);

struct Worker(tokio::task::JoinHandle<()>);

impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Command {
    Request(
        ControlRequest,
        oneshot::Sender<Result<ControlResponse, String>>,
    ),
}

impl ControlPlane {
    pub fn stop(&self) {
        self.1.0.abort();
    }

    pub async fn request(&self, request: ControlRequest) -> Result<ControlResponse, String> {
        let (reply, response) = oneshot::channel();
        self.0
            .send(Command::Request(request, reply))
            .await
            .map_err(|_| "control plane stopped".to_string())?;
        response
            .await
            .map_err(|_| "control plane stopped".to_string())?
    }
}

/// Starts one post-enrollment swarm for both request-response and topology pushes.
pub fn start(
    mut config: crate::config::ServerConfig,
    updates: mpsc::Sender<TopologySnapshot>,
    current: std::sync::Arc<tokio::sync::Mutex<Option<crate::config::ServerConfig>>>,
) -> Result<ControlPlane, String> {
    let controller: libp2p::PeerId = config
        .controller_peer_id
        .as_deref()
        .ok_or_else(|| "controller peer id is not enrolled".to_string())?
        .parse()
        .map_err(|_| "invalid controller peer id".to_string())?;
    let node_id = config
        .control_node_id
        .ok_or_else(|| "control node id is not enrolled".to_string())?;
    let controller_signing_key = config
        .controller_signing_key
        .clone()
        .ok_or_else(|| "controller signing key is not enrolled".to_string())?;
    let pin = libp2p::identity::PublicKey::try_decode_protobuf(
        &hex_decode(&controller_signing_key).map_err(|e| e.to_string())?,
    )
    .map_err(|_| "invalid controller signing key")?;
    if pin.to_peer_id() != controller {
        return Err("logical controller identity does not match signing pin".into());
    }
    let encryption_key = config
        .control_encryption_private_key
        .clone()
        .ok_or_else(|| "control encryption identity is not enrolled".to_string())?;
    let keypair = config
        .ensure_control_keypair()
        .map_err(|error| error.to_string())?;
    let private_network_key: PreSharedKey = config
        .control_private_network_key
        .as_deref()
        .ok_or_else(|| "private control network key is not configured".to_string())?
        .parse()
        .map_err(|_| "invalid private control network key".to_string())?;
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(private_network_key).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair).map_err(|error| error.to_string())?)
        .multiplex(yamux::Config::default())
        .boxed();
    let mut swarm = Swarm::new(
        transport,
        ControlBehaviour {
            request_response: json::Behaviour::new(
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            gossipsub: gossipsub(&keypair)?,
        },
        keypair.public().to_peer_id(),
        SwarmConfig::with_tokio_executor(),
    );
    let topic = gossipsub::Sha256Topic::new(topology_topic(&config.control_network_id, node_id));
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|error| error.to_string())?;
    let network_id = config.control_network_id.clone();
    let (commands, mut receiver) = mpsc::channel(16);
    let worker = tokio::spawn(async move {
        let mut seen = HashSet::new();
        let mut order = VecDeque::new();
        let mut reconnect = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                command = receiver.recv() => {
                    let Some(Command::Request(request, reply)) = command else { break; };
                    let Some(mut config) = current.lock().await.clone() else {
                        let _ = reply.send(Err("control configuration unavailable".into()));
                        continue;
                    };
                    let bootstraps = config.control_bootstrap_addresses.clone();
                    // ponytail: one bounded RPC at a time; reuse connected streams when polling load warrants it.
                    let result = request_to_bootstraps(&mut config, &bootstraps, request).await;
                    let _ = reply.send(result);
                }
                _ = reconnect.tick() => {
                    let guard = current.lock().await;
                    let Some(config) = guard.as_ref() else { continue };
                    for bootstrap in &config.control_bootstrap_addresses {
                        if bootstrap_peer_id(bootstrap).is_ok_and(|peer| config.control_peer_authorized(peer)) {
                          if let Ok(address) = bootstrap.parse::<libp2p::Multiaddr>() {
                            let _ = swarm.dial(address);
                          }
                        }
                    }
                }
                event = swarm.select_next_some() => match event {
                    libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                        request_response::Event::Message {
                            peer,
                            message: request_response::Message::Response { request_id, response },
                            ..
                        },
                    )) => { let _ = (peer, request_id, response); }
                    libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) if message.data.len() <= 64 * 1024 => {
                        if message.source != Some(controller) { continue; }
                        let Ok(envelope) = serde_json::from_slice::<EncryptedEnvelope>(&message.data) else { continue };
                        let Ok(now) = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_err(|_| ())
                            .and_then(|duration| duration.as_millis().try_into().map_err(|_| ())) else { continue };
                        let Ok(snapshot) = open_topology_snapshot(
                            &controller_signing_key, &encryption_key, &network_id, node_id, now, &envelope,
                        ) else { continue };
                        if remember_message_id(&mut seen, &mut order, envelope.meta.message_id) {
                            let _ = updates.try_send(snapshot);
                        }
                    }
                    _ => {}
                }
            }
        }
    });
    Ok(ControlPlane(commands, std::sync::Arc::new(Worker(worker))))
}

/// Enrollment uses a one-shot swarm because no controller identity is pinned yet.
pub async fn enroll(
    config: &mut crate::config::ServerConfig,
    bootstraps: &[String],
    node_name: String,
) -> Result<ControlResponse, String> {
    let controller = bootstrap_peer_id(
        bootstraps
            .first()
            .ok_or_else(|| "at least one controller bootstrap address is required".to_string())?,
    )?;
    if config.controller_peer_id.as_deref().is_some_and(|pin| pin != controller.to_string())
    {
        return Err("bootstrap does not match pinned controller".into());
    }
    if bootstraps.iter().any(|bootstrap| bootstrap_peer_id(bootstrap).as_ref() != Ok(&controller))
    {
        return Err("all controller bootstrap addresses must use the same peer id".to_string());
    }
    let keypair = config
        .ensure_control_keypair()
        .map_err(|error| error.to_string())?;
    let request = ControlRequest::Enroll(cat4igp_shared::control::EnrollmentRequest {
        // The pending transport identity is saved before sending and survives restart.
        request_id: keypair.public().to_peer_id().to_string(),
        node_name,
        invitation_code: config.invite_code.clone(),
        client_peer_id: keypair.public().to_peer_id().to_string(),
        client_signing_key: keypair
            .public()
            .encode_protobuf()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        client_encryption_key: config
            .ensure_control_encryption_key()
            .map_err(|error| error.to_string())?,
        wireguard_public_key: config.wg_public_key.clone().unwrap_or_default(),
    });
    let response = request_to_bootstraps(config, bootstraps, request).await?;
    if let ControlResponse::Enrolled(enrollment) = &response {
        if enrollment.node_id <= 0 || enrollment.topology_revision < 0 || enrollment.network_id.is_empty() {
            return Err("invalid controller enrollment identity".into());
        }
        if config.controller_signing_key.as_ref().is_some_and(|pin| {
            hex_decode(pin).ok() != hex_decode(&enrollment.controller_signing_key).ok()
        }) || (config.controller_signing_key.is_some()
            && enrollment.network_id != config.control_network_id)
        {
            return Err("enrollment does not match trusted bundle".into());
        }
        let signing = hex_decode(&enrollment.controller_signing_key)?;
        let signing = libp2p::identity::PublicKey::try_decode_protobuf(&signing)
            .map_err(|_| "invalid controller signing key".to_string())?;
        if (config
            .controller_peer_id
            .as_deref()
            .is_some_and(|logical| logical != signing.to_peer_id().to_string())
            || (config.controller_signing_key.is_none() && signing.to_peer_id() != controller))
            || enrollment.controller_encryption_key.len() != 64
            || !enrollment
                .controller_encryption_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid controller enrollment identity".to_string());
        }
        config.controller_peer_id = Some(signing.to_peer_id().to_string());
        config.control_bootstrap_addresses = bootstraps.to_vec();
        config.control_node_id = Some(enrollment.node_id);
        config.topology_revision = enrollment.topology_revision;
        config.control_network_id = enrollment.network_id.clone();
        config.controller_signing_key = Some(enrollment.controller_signing_key.clone());
        config.controller_encryption_key = Some(enrollment.controller_encryption_key.clone());
    }
    Ok(response)
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid controller signing key".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid controller signing key".to_string())
        })
        .collect()
}

fn bootstrap_peer_id(bootstrap: &str) -> Result<libp2p::PeerId, String> {
    let address: libp2p::Multiaddr = bootstrap
        .parse()
        .map_err(|_| "invalid controller bootstrap address".to_string())?;
    address
        .iter()
        .find_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .ok_or_else(|| "bootstrap address must include controller peer id".to_string())
}

async fn request_to_bootstraps(
    config: &mut crate::config::ServerConfig,
    bootstraps: &[String],
    request: ControlRequest,
) -> Result<ControlResponse, String> {
    if bootstraps.is_empty() || bootstraps.len() > 16 {
        return Err("expected 1..16 private control bootstraps".into());
    }
    let mut addresses = Vec::with_capacity(bootstraps.len());
    let mut controller = None;
    for bootstrap in bootstraps {
        let peer = bootstrap_peer_id(bootstrap)?;
        if config.controller_signing_key.is_some() && !config.control_peer_authorized(peer) {
            return Err("private bootstrap does not match pinned controller".into());
        }
        if controller.is_some_and(|expected| expected != peer) {
            return Err("all controller bootstrap addresses must use the same peer id".into());
        }
        controller = Some(peer);
        addresses.push(bootstrap.parse().map_err(|_| "invalid controller bootstrap address")?);
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        request_to(config, controller.unwrap(), addresses, request),
    ).await.map_err(|_| "controller request timed out".to_string())?
}

async fn request_to(
    config: &mut crate::config::ServerConfig,
    controller: libp2p::PeerId,
    addresses: Vec<libp2p::Multiaddr>,
    request: ControlRequest,
) -> Result<ControlResponse, String> {
    let keypair = config
        .ensure_control_keypair()
        .map_err(|error| error.to_string())?;
    let private_network_key: PreSharedKey = config
        .control_private_network_key
        .as_deref()
        .ok_or_else(|| "private control network key is not configured".to_string())?
        .parse()
        .map_err(|_| "invalid private control network key".to_string())?;
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(private_network_key).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair).map_err(|error| error.to_string())?)
        .multiplex(yamux::Config::default())
        .boxed();
    let mut swarm = Swarm::new(
        transport,
        ControlBehaviour {
            request_response: json::Behaviour::new(
                [(
                    StreamProtocol::new(CONTROL_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            gossipsub: gossipsub(&keypair)?,
        },
        keypair.public().to_peer_id(),
        SwarmConfig::with_tokio_executor(),
    );
    swarm.dial(libp2p::swarm::dial_opts::DialOpts::peer_id(controller)
        .override_dial_concurrency_factor(std::num::NonZeroU8::new(16).unwrap())
        .addresses(addresses)
        .build()).map_err(|error| error.to_string())?;
    let mut pending = None;
    loop {
        match swarm.select_next_some().await {
            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. }
                if peer_id == controller && pending.is_none() =>
            {
                pending = Some(
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&controller, request.clone()),
                );
            }
            libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) if peer == controller && pending == Some(request_id) => return Ok(response),
            libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    peer,
                    request_id,
                    error,
                    ..
                },
            )) if peer == controller && pending == Some(request_id) => {
                return Err(match error {
                    request_response::OutboundFailure::Timeout
                    | request_response::OutboundFailure::ConnectionClosed => {
                        format!("retryable: {error}")
                    }
                    _ => error.to_string(),
                });
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer),
                error,
                ..
            } if peer == controller => {
                return Err(format!("controller connection failed: {error}"));
            }
            _ => {}
        }
    }
}



#[cfg(test)]
#[path = "control_test.rs"]
pub(super) mod tests;
