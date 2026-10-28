//! Private control-plane transport.
//!
//! A node dials configured bootstrap peers, discovers the controller, then uses
//! a direct connection or an approved relay circuit. Gossipsub is delivery only:
//! `SignedCommand` still requires local signature and recipient verification.

use cat4igp_protocol::{
    DesiredState, EnrollmentRequest, EnrollmentResponse, MAX_ENROLLMENT_PAYLOAD_BYTES, NetworkId,
    NodeId,
};
use ed25519_dalek::VerifyingKey;
use libp2p::{
    PeerId, StreamProtocol, Swarm, SwarmBuilder,
    futures::StreamExt,
    gossipsub::{self, IdentTopic},
    identify,
    identity::Keypair,
    noise, relay, rendezvous,
    request_response::{self, ProtocolSupport},
    swarm::{
        NetworkBehaviour, SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
    yamux,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub const ENROLLMENT_PROTOCOL: &str = "/cat4igp/enrollment/1";

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub enrollment: request_response::json::Behaviour<EnrollmentRequest, EnrollmentResponse>,
    pub identify: identify::Behaviour,
    pub relay: relay::client::Behaviour,
    pub rendezvous: rendezvous::client::Behaviour,
}

impl Behaviour {
    pub fn new(local_key: &Keypair, relay: relay::client::Behaviour) -> Result<Self, &'static str> {
        Ok(Self {
            gossipsub: gossipsub(local_key)?,
            enrollment: enrollment(),
            identify: identify::Behaviour::new(
                identify::Config::new("/cat4igp/1.0.0".into(), local_key.public())
                    .with_agent_version("cat4igp/0.1.0".into()),
            ),
            relay,
            rendezvous: rendezvous::client::Behaviour::new(local_key.clone()),
        })
    }
}

/// Builds a direct TCP/QUIC swarm with relay-circuit transport support.
pub fn swarm(local_key: Keypair) -> anyhow::Result<Swarm<Behaviour>> {
    Ok(SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay| {
            Behaviour::new(key, relay).map_err(|error| std::io::Error::other(error).into())
        })?
        .build())
}

/// Sends one enrollment request after a bootstrap connection is established.
pub fn request_enrollment(
    swarm: &mut Swarm<Behaviour>,
    controller: PeerId,
    request: EnrollmentRequest,
) -> request_response::OutboundRequestId {
    swarm
        .behaviour_mut()
        .enrollment
        .send_request(&controller, request)
}

/// Validates enrollment before joining the network's shared and private topics.
pub fn accept_enrollment(
    swarm: &mut Swarm<Behaviour>,
    response: EnrollmentResponse,
    network_id: &NetworkId,
    node_id: &NodeId,
) -> anyhow::Result<()> {
    if &response.network_id != network_id || &response.node_id != node_id {
        anyhow::bail!("controller enrollment response does not match this node or network");
    }
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&shared_topic(&network_id.to_string()))?;
    swarm.behaviour_mut().gossipsub.subscribe(&command_topic(
        &network_id.to_string(),
        &node_id.to_string(),
    ))?;
    Ok(())
}

pub fn shared_topic(network_id: &str) -> IdentTopic {
    IdentTopic::new(format!("cat4igp/{network_id}/shared/v1"))
}

pub fn command_topic(network_id: &str, node: &str) -> IdentTopic {
    IdentTopic::new(format!("cat4igp/{network_id}/node/{node}/v1"))
}

/// A configured bootstrap peer; controller trust is still established by its
/// independently pinned signing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPeer {
    pub peer_id: PeerId,
    pub address: libp2p::Multiaddr,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapDialError {
    #[error("bootstrap address has a different /p2p peer ID")]
    PeerIdMismatch,
    #[error(transparent)]
    Dial(#[from] libp2p::swarm::DialError),
}

/// Dials a configured bootstrap peer, accepting an omitted matching `/p2p` suffix.
pub fn dial_bootstrap(
    swarm: &mut Swarm<Behaviour>,
    bootstrap: BootstrapPeer,
) -> Result<(), BootstrapDialError> {
    let address = bootstrap
        .address
        .with_p2p(bootstrap.peer_id)
        .map_err(|_| BootstrapDialError::PeerIdMismatch)?;
    swarm.dial(
        DialOpts::peer_id(bootstrap.peer_id)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .addresses(vec![address])
            .build(),
    )?;
    Ok(())
}

pub fn reservation_address(
    bootstrap: &BootstrapPeer,
) -> Result<libp2p::Multiaddr, BootstrapDialError> {
    Ok(bootstrap
        .address
        .clone()
        .with_p2p(bootstrap.peer_id)
        .map_err(|_| BootstrapDialError::PeerIdMismatch)?
        .with(libp2p::multiaddr::Protocol::P2pCircuit))
}

/// Requests a relay reservation after a direct controller connection exists.
pub fn request_relay_reservation(
    swarm: &mut Swarm<Behaviour>,
    controller: &BootstrapPeer,
) -> Result<libp2p::core::transport::ListenerId, anyhow::Error> {
    Ok(swarm.listen_on(reservation_address(controller)?)?)
}

fn rendezvous_namespace(network_id: &NetworkId) -> Result<rendezvous::Namespace, anyhow::Error> {
    Ok(rendezvous::Namespace::new(network_id.to_string())?)
}

/// Builds authenticated PubSub with strict payload limits for direct or relayed
/// controller links. Application signatures remain mandatory.
pub fn gossipsub(
    local_key: &libp2p::identity::Keypair,
) -> Result<gossipsub::Behaviour, &'static str> {
    gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::ConfigBuilder::default()
            .max_transmit_size(64 * 1024)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .expect("fixed Gossipsub configuration is valid"),
    )
}

/// Request-response transport for enrollment over direct or relayed links.
pub fn enrollment() -> request_response::json::Behaviour<EnrollmentRequest, EnrollmentResponse> {
    request_response::json::Behaviour::with_codec(
        request_response::json::codec::Codec::default()
            .set_request_size_maximum(MAX_ENROLLMENT_PAYLOAD_BYTES as u64)
            .set_response_size_maximum(MAX_ENROLLMENT_PAYLOAD_BYTES as u64),
        [(
            StreamProtocol::new(ENROLLMENT_PROTOCOL),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

/// Delivers only enrolled and cryptographically verified controller state.
pub async fn run_control<F>(
    swarm: &mut Swarm<Behaviour>,
    controller: &BootstrapPeer,
    network_id: &NetworkId,
    recipient_secret: &StaticSecret,
    server_key: &VerifyingKey,
    state_store: &crate::state_store::StateStore,
    mut on_desired_state: F,
) -> anyhow::Result<()>
where
    F: FnMut(DesiredState) -> anyhow::Result<()>,
{
    let node_id = NodeId::from_command_key(&PublicKey::from(recipient_secret));
    let mut reservation_requested = false;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } if peer_id == controller.peer_id
                && !endpoint.is_relayed()
                && !reservation_requested =>
            {
                request_relay_reservation(swarm, controller)?;
                reservation_requested = true;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Relay(
                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) if relay_peer_id == controller.peer_id => {
                swarm.behaviour_mut().rendezvous.register(
                    rendezvous_namespace(network_id)?,
                    controller.peer_id,
                    None,
                )?;
            }
            SwarmEvent::Behaviour(BehaviourEvent::Enrollment(
                request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                },
            )) => accept_enrollment(swarm, response, network_id, &node_id)?,
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                if let Ok(state) = crate::command::accept_pubsub_command(
                    &message.topic,
                    &message.data,
                    network_id,
                    recipient_secret,
                    server_key,
                    cat4igp_protocol::unix_now(),
                    state_store,
                ) {
                    on_desired_state(state)?;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{command_topic, shared_topic};

    #[test]
    fn topics_are_network_and_recipient_scoped() {
        assert_ne!(shared_topic("a").hash(), shared_topic("b").hash());
        assert_ne!(
            command_topic("a", "one").hash(),
            command_topic("a", "two").hash()
        );
    }

    #[test]
    fn bootstrap_address_requires_its_configured_peer_id() {
        let peer = libp2p::PeerId::random();
        let other = libp2p::PeerId::random();
        let bare: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(bare.clone().with_p2p(peer).is_ok());
        let mismatched: libp2p::Multiaddr = format!("{bare}/p2p/{other}").parse().unwrap();
        assert_eq!(mismatched.clone().with_p2p(peer), Err(mismatched));
    }

    #[test]
    fn reservation_address_uses_controller_as_relay() {
        let peer = libp2p::PeerId::random();
        let bootstrap = super::BootstrapPeer {
            peer_id: peer,
            address: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
        };
        assert_eq!(
            super::reservation_address(&bootstrap).unwrap().to_string(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer}/p2p-circuit")
        );
    }

    #[test]
    fn rendezvous_namespace_is_network_scoped() {
        assert_eq!(
            super::rendezvous_namespace(&cat4igp_protocol::NetworkId::new("test").unwrap())
                .unwrap()
                .to_string(),
            "test"
        );
    }

    #[test]
    fn authenticated_gossipsub_builds() {
        assert!(super::gossipsub(&libp2p::identity::Keypair::generate_ed25519()).is_ok());
    }

    #[test]
    fn enrollment_behaviour_builds() {
        let _ = super::enrollment();
    }

    #[test]
    fn composed_behaviour_builds() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let (_, relay) = libp2p::relay::client::new(key.public().to_peer_id());
        assert!(super::Behaviour::new(&key, relay).is_ok());
    }

    #[test]
    fn relay_capable_swarm_builds() {
        assert!(super::swarm(libp2p::identity::Keypair::generate_ed25519()).is_ok());
    }

    #[test]
    fn enrollment_request_is_queued() {
        let mut swarm = super::swarm(libp2p::identity::Keypair::generate_ed25519()).unwrap();
        let controller = libp2p::PeerId::random();
        let request = cat4igp_protocol::EnrollmentRequest {
            token: "join".into(),
            libp2p_peer_id: "node".into(),
            command_public_key: [0; 32],
            wireguard_public_key: "wg".into(),
        };
        let _ = super::request_enrollment(&mut swarm, controller, request);
    }

    #[test]
    fn enrollment_response_subscribes_only_matching_node() {
        let mut swarm = super::swarm(libp2p::identity::Keypair::generate_ed25519()).unwrap();
        let network = cat4igp_protocol::NetworkId::new("test").unwrap();
        let node =
            cat4igp_protocol::NodeId::from_command_key(&x25519_dalek::PublicKey::from([1; 32]));
        assert!(
            super::accept_enrollment(
                &mut swarm,
                cat4igp_protocol::EnrollmentResponse {
                    node_id: node.clone(),
                    network_id: network.clone()
                },
                &network,
                &node,
            )
            .is_ok()
        );
        assert!(
            super::accept_enrollment(
                &mut swarm,
                cat4igp_protocol::EnrollmentResponse {
                    node_id: node,
                    network_id: network.clone()
                },
                &cat4igp_protocol::NetworkId::new("other").unwrap(),
                &cat4igp_protocol::NodeId::from_command_key(&x25519_dalek::PublicKey::from(
                    [2; 32]
                )),
            )
            .is_err()
        );
    }
}
