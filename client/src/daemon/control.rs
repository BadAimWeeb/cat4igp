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
use std::collections::{HashMap, HashSet, VecDeque};
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
pub struct ControlPlane(mpsc::Sender<Command>);

enum Command {
    Request(
        ControlRequest,
        oneshot::Sender<Result<ControlResponse, String>>,
    ),
}

impl ControlPlane {
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
    let bootstraps = config.control_bootstrap_addresses.clone();
    let network_id = config.control_network_id.clone();
    let (commands, mut receiver) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut pending = HashMap::new();
        let mut seen = HashSet::new();
        let mut order = VecDeque::new();
        let mut reconnect = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                Some(Command::Request(request, reply)) = receiver.recv() => {
                    let request_id = swarm.behaviour_mut().request_response.send_request(&controller, request);
                    pending.insert(request_id, reply);
                }
                _ = reconnect.tick() => {
                    for bootstrap in &bootstraps {
                        if let Ok(address) = bootstrap.parse::<libp2p::Multiaddr>() {
                            let _ = swarm.dial(address);
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
                    )) if peer == controller => {
                        if let Some(reply) = pending.remove(&request_id) {
                            let _ = reply.send(Ok(response));
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                        request_response::Event::OutboundFailure { request_id, error, .. },
                    )) => {
                        if let Some(reply) = pending.remove(&request_id) {
                            let _ = reply.send(Err(error.to_string()));
                        }
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) if message.source == Some(controller) && message.data.len() <= 64 * 1024 => {
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
    Ok(ControlPlane(commands))
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
    if bootstraps
        .iter()
        .any(|bootstrap| bootstrap_peer_id(bootstrap).as_ref() != Ok(&controller))
    {
        return Err("all controller bootstrap addresses must use the same peer id".to_string());
    }
    let keypair = config
        .ensure_control_keypair()
        .map_err(|error| error.to_string())?;
    let request = ControlRequest::Enroll(cat4igp_shared::control::EnrollmentRequest {
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
    let response = request_to_bootstraps(config, controller, bootstraps, request).await?;
    if let ControlResponse::Enrolled(enrollment) = &response {
        let signing = hex_decode(&enrollment.controller_signing_key)?;
        let signing = libp2p::identity::PublicKey::try_decode_protobuf(&signing)
            .map_err(|_| "invalid controller signing key".to_string())?;
        if signing.to_peer_id() != controller
            || enrollment.controller_encryption_key.len() != 64
            || !enrollment
                .controller_encryption_key
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid controller enrollment identity".to_string());
        }
        config.controller_peer_id = Some(controller.to_string());
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
    controller: libp2p::PeerId,
    bootstraps: &[String],
    request: ControlRequest,
) -> Result<ControlResponse, String> {
    let mut errors = Vec::new();
    for bootstrap in bootstraps {
        let Ok(address) = bootstrap.parse() else {
            errors.push(format!("{bootstrap}: invalid multiaddress"));
            continue;
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            request_to(config, controller, address, request.clone()),
        )
        .await
        {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error)) => errors.push(format!("{bootstrap}: {error}")),
            Err(_) => errors.push(format!("{bootstrap}: timed out")),
        }
    }
    Err(format!(
        "all controller bootstrap addresses failed: {}",
        errors.join("; ")
    ))
}

async fn request_to(
    config: &mut crate::config::ServerConfig,
    controller: libp2p::PeerId,
    address: libp2p::Multiaddr,
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
    swarm.dial(address).map_err(|error| error.to_string())?;
    loop {
        match swarm.select_next_some().await {
            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. }
                if peer_id == controller =>
            {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&controller, request.clone());
            }
            libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                    ..
                },
            )) if peer == controller => return Ok(response),
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
