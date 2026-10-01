pub mod db;
pub mod ext;
pub mod models;
pub mod router;
pub mod schema;

use diesel::Connection;
use dotenvy::dotenv;
use futures_util::StreamExt;
use libp2p::{
    StreamProtocol,
    core::{Transport, upgrade::Version},
    gossipsub, identity, noise,
    pnet::{PnetConfig, PreSharedKey},
    request_response::{self, json},
    swarm::{Config as SwarmConfig, NetworkBehaviour, Swarm},
    tcp, yamux,
};
use std::{
    collections::{HashSet, VecDeque},
    env,
};

const CONTROL_PROTOCOL: &str = "/cat4igp/control/1";

fn remember_message_id(
    seen: &mut HashSet<String>,
    order: &mut VecDeque<String>,
    message_id: String,
) -> bool {
    if !seen.insert(message_id.clone()) {
        return false;
    }
    order.push_back(message_id);
    // ponytail: retains 256 answers until controller restart; persist IDs for crash-safe deduplication.
    if order.len() > 256 {
        if let Some(oldest) = order.pop_front() {
            seen.remove(&oldest);
        }
    }
    true
}

#[derive(NetworkBehaviour)]
struct ControlBehaviour {
    request_response: json::Behaviour<
        cat4igp_shared::control::ControlRequest,
        cat4igp_shared::control::ControlResponse,
    >,
    gossipsub: gossipsub::Behaviour,
}

fn gossipsub(keypair: &identity::Keypair) -> Result<gossipsub::Behaviour, String> {
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

fn control_response(
    peer_id: &libp2p::PeerId,
    controller_signing_key: &str,
    controller_keypair: &identity::Keypair,
    network_id: &str,
    seen_message_ids: &mut HashSet<String>,
    message_order: &mut VecDeque<String>,
    request: cat4igp_shared::control::ControlRequest,
) -> (
    cat4igp_shared::control::ControlResponse,
    Vec<cat4igp_shared::control::TopologySnapshot>,
) {
    let mut conn = crate::db::establish_connection();

    if let cat4igp_shared::control::ControlRequest::Enroll(request) = request {
        if request.client_peer_id != peer_id.to_string()
            || request.node_name.is_empty()
            || request.wireguard_public_key.is_empty()
            || request.client_signing_key.is_empty()
            || request.client_encryption_key.is_empty()
            || !matches!(hex_decode(&request.client_encryption_key), Ok(key) if key.len() == 32)
        {
            return (
                cat4igp_shared::control::ControlResponse::Rejected(
                    "invalid enrollment request".to_string(),
                ),
                Vec::new(),
            );
        }
        let signing_key = match hex_decode(&request.client_signing_key).and_then(|encoded| {
            identity::PublicKey::try_decode_protobuf(&encoded)
                .map_err(|_| "invalid client signing key".to_string())
        }) {
            Ok(key) if key.to_peer_id() == *peer_id => request.client_signing_key,
            _ => {
                return (
                    cat4igp_shared::control::ControlResponse::Rejected(
                        "client signing key does not match transport identity".to_string(),
                    ),
                    Vec::new(),
                );
            }
        };
        let controller_encryption_key = match control_encryption_public_key() {
            Ok(key) => key,
            Err(error) => {
                return (
                    cat4igp_shared::control::ControlResponse::Rejected(format!(
                        "controller encryption identity unavailable: {error}"
                    )),
                    Vec::new(),
                );
            }
        };
        return match conn.transaction(|conn| {
            let (node_id, _, join_mesh) =
                crate::db::register_node(conn, &request.node_name, &request.invitation_code)?;
            crate::db::register_control_identity(
                conn,
                node_id,
                &request.client_peer_id,
                &signing_key,
                &request.client_encryption_key,
            )?;
            crate::db::update_wireguard_pubkey(conn, node_id, &request.wireguard_public_key)?;
            if let Some(mesh_id) = join_mesh.filter(|id| *id != 0) {
                crate::db::join_mesh(conn, node_id, mesh_id)?;
            }
            Ok::<_, diesel::result::Error>(node_id)
        }) {
            Ok(node_id) => {
                let snapshots = crate::db::tunnel_node_ids_for_node(&mut conn, node_id)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|affected_node_id| {
                        let revision =
                            crate::db::bump_control_revision(&mut conn, affected_node_id).ok()?;
                        crate::db::topology_snapshot(&mut conn, affected_node_id, revision).ok()
                    })
                    .collect();
                let revision = crate::db::control_identity_for_node(&mut conn, node_id)
                    .map(|identity| identity.topology_revision)
                    .unwrap_or_default();
                (
                    cat4igp_shared::control::ControlResponse::Enrolled(
                        cat4igp_shared::control::EnrollmentResponse {
                            node_id,
                            topology_revision: revision,
                            network_id: match control_network_id() {
                                Ok(network_id) => network_id,
                                Err(error) => {
                                    return (
                                        cat4igp_shared::control::ControlResponse::Rejected(
                                            format!(
                                                "control network identity unavailable: {error}"
                                            ),
                                        ),
                                        Vec::new(),
                                    );
                                }
                            },
                            controller_signing_key: controller_signing_key.to_string(),
                            controller_encryption_key,
                        },
                    ),
                    snapshots,
                )
            }
            Err(_) => (
                cat4igp_shared::control::ControlResponse::Rejected(
                    "enrollment rejected".to_string(),
                ),
                Vec::new(),
            ),
        };
    }

    let identity = match crate::db::control_identity_for_peer(&mut conn, &peer_id.to_string()) {
        Ok(identity) => identity,
        Err(_) => {
            return (
                cat4igp_shared::control::ControlResponse::Rejected(
                    "unknown control identity".to_string(),
                ),
                Vec::new(),
            );
        }
    };
    match request {
        cat4igp_shared::control::ControlRequest::Snapshot => {
            let response = (|| {
                let snapshot = crate::db::topology_snapshot(
                    &mut conn,
                    identity.node_id,
                    identity.topology_revision,
                )?;
                let encryption_key =
                    crate::db::control_identity_for_node(&mut conn, identity.node_id)?
                        .encryption_key;
                let now = chrono::Utc::now().timestamp_millis();
                cat4igp_shared::control::seal_topology_snapshot(
                    controller_keypair,
                    &encryption_key,
                    cat4igp_shared::control::MessageMeta {
                        message_id: uuid::Uuid::new_v4().simple().to_string(),
                        network_id: network_id.to_string(),
                        recipient_node_id: identity.node_id,
                        issued_at_ms: now,
                        expires_at_ms: now + 60_000,
                        topology_revision: identity.topology_revision,
                    },
                    &snapshot,
                )
                .map(cat4igp_shared::control::ControlResponse::SnapshotEnvelope)
                .map_err(|error| {
                    diesel::result::Error::DeserializationError(Box::new(std::io::Error::other(
                        error,
                    )))
                })
            })();
            (
                response.unwrap_or_else(|error| {
                    cat4igp_shared::control::ControlResponse::Rejected(error.to_string())
                }),
                Vec::new(),
            )
        }
        cat4igp_shared::control::ControlRequest::TunnelAnswerEnvelope(envelope) => {
            let answer = match control_encryption_private_key().and_then(|private_key| {
                cat4igp_shared::control::open_tunnel_answer(
                    &identity.signing_key,
                    &private_key,
                    network_id,
                    identity.node_id,
                    chrono::Utc::now().timestamp_millis(),
                    &envelope,
                )
                .map_err(str::to_string)
            }) {
                Ok(answer) => answer,
                Err(error) => {
                    return (
                        cat4igp_shared::control::ControlResponse::Rejected(error),
                        Vec::new(),
                    );
                }
            };
            if !remember_message_id(seen_message_ids, message_order, envelope.meta.message_id) {
                return (
                    cat4igp_shared::control::ControlResponse::Rejected(
                        "replayed tunnel answer".to_string(),
                    ),
                    Vec::new(),
                );
            }
            if let Some(endpoint) = answer.endpoint.as_deref() {
                let endpoint = match endpoint.parse::<std::net::SocketAddr>() {
                    Ok(endpoint)
                        if !endpoint.ip().is_unspecified() && !endpoint.ip().is_multicast() =>
                    {
                        endpoint
                    }
                    _ => {
                        return (
                            cat4igp_shared::control::ControlResponse::Rejected(
                                "endpoint must be a routable socket address".to_string(),
                            ),
                            Vec::new(),
                        );
                    }
                };
                match crate::db::tunnel_endpoint_ipv6(&mut conn, answer.tunnel_id) {
                    Ok(ipv6) if ipv6 == endpoint.is_ipv6() => {}
                    Ok(_) => {
                        return (
                            cat4igp_shared::control::ControlResponse::Rejected(
                                "endpoint address family does not match tunnel".to_string(),
                            ),
                            Vec::new(),
                        );
                    }
                    Err(_) => {
                        return (
                            cat4igp_shared::control::ControlResponse::Rejected(
                                "unknown tunnel".to_string(),
                            ),
                            Vec::new(),
                        );
                    }
                }
            }
            match crate::db::answer_wireguard_tunnel(
                &mut conn,
                answer.tunnel_id,
                identity.node_id,
                answer.endpoint,
                answer.decline_type,
            ) {
                Ok(()) => match crate::db::tunnel_peer_node_ids(&mut conn, answer.tunnel_id)
                    .and_then(|(peer1, peer2)| {
                        crate::db::bump_control_revision(&mut conn, peer1)?;
                        crate::db::bump_control_revision(&mut conn, peer2)?;
                        Ok((peer1, peer2))
                    }) {
                    Ok((peer1, peer2)) => {
                        let snapshots = [peer1, peer2]
                            .into_iter()
                            .filter_map(|node_id| {
                                let revision =
                                    crate::db::control_identity_for_node(&mut conn, node_id)
                                        .ok()?
                                        .topology_revision;
                                crate::db::topology_snapshot(&mut conn, node_id, revision).ok()
                            })
                            .collect();
                        (
                            cat4igp_shared::control::ControlResponse::Accepted,
                            snapshots,
                        )
                    }
                    Err(error) => (
                        cat4igp_shared::control::ControlResponse::Rejected(error.to_string()),
                        Vec::new(),
                    ),
                },
                Err(_) => (
                    cat4igp_shared::control::ControlResponse::Rejected(
                        "unknown tunnel or unauthorized peer".to_string(),
                    ),
                    Vec::new(),
                ),
            }
        }
        cat4igp_shared::control::ControlRequest::Enroll(_) => unreachable!(),
    }
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("CONTROL_PRIVATE_KEY must be hexadecimal".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn control_keypair() -> Result<identity::Keypair, String> {
    let mut conn = crate::db::establish_connection();
    let encoded = match crate::db::get_setting(&mut conn, "control_private_key") {
        Ok(encoded) => encoded,
        Err(diesel::result::Error::NotFound) => {
            let keypair = identity::Keypair::generate_ed25519();
            let encoded = hex_encode(
                &keypair
                    .to_protobuf_encoding()
                    .map_err(|_| "failed to encode controller identity")?,
            );
            crate::db::set_setting(&mut conn, "control_private_key", &encoded)
                .map_err(|error| error.to_string())?;
            return Ok(keypair);
        }
        Err(error) => return Err(error.to_string()),
    };
    identity::Keypair::from_protobuf_encoding(&hex_decode(&encoded)?)
        .map_err(|_| "stored controller identity is invalid".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn control_network_id() -> Result<String, String> {
    let mut conn = crate::db::establish_connection();
    match crate::db::get_setting(&mut conn, "control_network_id") {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err("stored control network id is empty".to_string()),
        Err(diesel::result::Error::NotFound) => {
            let value = uuid::Uuid::new_v4().to_string();
            crate::db::set_setting(&mut conn, "control_network_id", &value)
                .map_err(|error| error.to_string())?;
            Ok(value)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn control_encryption_public_key() -> Result<String, String> {
    let private = control_encryption_private_key()?;
    let private: [u8; 32] = hex_decode(&private)?
        .try_into()
        .map_err(|_| "stored controller encryption identity is invalid")?;
    Ok(hex_encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private)).as_bytes(),
    ))
}

fn control_encryption_private_key() -> Result<String, String> {
    let mut conn = crate::db::establish_connection();
    Ok(
        match crate::db::get_setting(&mut conn, "control_encryption_private_key") {
            Ok(encoded) => encoded,
            Err(diesel::result::Error::NotFound) => {
                let private = x25519_dalek::StaticSecret::random_from_rng(rand08::rngs::OsRng);
                let encoded = hex_encode(&private.to_bytes());
                crate::db::set_setting(&mut conn, "control_encryption_private_key", &encoded)
                    .map_err(|error| error.to_string())?;
                encoded
            }
            Err(error) => return Err(error.to_string()),
        },
    )
}

async fn run_control_plane() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_address = env::var("CONTROL_BIND_MULTIADDR")?;
    let keypair = control_keypair()?;
    let network_id = control_network_id()?;
    let private_network_key: PreSharedKey = env::var("CONTROL_PRIVATE_NETWORK_KEY")
        .map_err(|_| "CONTROL_PRIVATE_NETWORK_KEY must contain a libp2p PSK key file")?
        .parse()
        .map_err(|_| "CONTROL_PRIVATE_NETWORK_KEY is invalid")?;
    eprintln!(
        "[control] controller peer id: {}",
        keypair.public().to_peer_id()
    );
    let transport = tcp::tokio::Transport::new(tcp::Config::default())
        .and_then(move |socket, _| PnetConfig::new(private_network_key).handshake(socket))
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair)?)
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
    let mut seen_message_ids = HashSet::new();
    let mut message_order = VecDeque::new();
    swarm.listen_on(listen_address.parse()?)?;

    loop {
        match swarm.select_next_some().await {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                eprintln!("[control] listening on {address}");
            }
            libp2p::swarm::SwarmEvent::Behaviour(ControlBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                let controller_signing_key = hex_encode(&keypair.public().encode_protobuf());
                let (response, snapshots) = control_response(
                    &peer,
                    &controller_signing_key,
                    &keypair,
                    &network_id,
                    &mut seen_message_ids,
                    &mut message_order,
                    request,
                );
                if let Err(error) = swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                {
                    eprintln!("[control] failed to respond to {peer}: {error:?}");
                }
                for snapshot in snapshots {
                    let topic = gossipsub::Sha256Topic::new(
                        cat4igp_shared::control::topology_topic(&network_id, snapshot.node_id),
                    );
                    let identity = crate::db::control_identity_for_node(
                        &mut crate::db::establish_connection(),
                        snapshot.node_id,
                    )?;
                    let now = chrono::Utc::now().timestamp_millis();
                    let envelope = cat4igp_shared::control::seal_topology_snapshot(
                        &keypair,
                        &identity.encryption_key,
                        cat4igp_shared::control::MessageMeta {
                            message_id: uuid::Uuid::new_v4().simple().to_string(),
                            network_id: network_id.clone(),
                            recipient_node_id: snapshot.node_id,
                            issued_at_ms: now,
                            expires_at_ms: now + 60_000,
                            topology_revision: snapshot.revision,
                        },
                        &snapshot,
                    )?;
                    if let Err(error) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic, serde_json::to_vec(&envelope)?)
                    {
                        eprintln!(
                            "[control] failed to publish topology for {}: {error}",
                            snapshot.node_id
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    let app = router::make_router().await.unwrap();
    let listener = tokio::net::TcpListener::bind(
        env::var("BIND_HOST_PORT").expect("BIND_HOST_PORT must be set"),
    )
    .await
    .unwrap();
    tokio::select! {
        result = axum::serve(listener, app) => result.unwrap(),
        result = run_control_plane() => panic!("control plane stopped: {result:?}"),
    }
}
