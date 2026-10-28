//! Controller-side private PubSub topic naming.
//!
//! Relay and rendezvous service wiring follows this stable topic contract.

use cat4igp_protocol::{EnrollmentRequest, EnrollmentResponse, MAX_ENROLLMENT_PAYLOAD_BYTES};
use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder,
    gossipsub::{self, IdentTopic},
    identify,
    identity::Keypair,
    noise, relay, rendezvous,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    yamux,
};
use std::io;

pub const ENROLLMENT_PROTOCOL: &str = "/cat4igp/enrollment/1";

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub enrollment: request_response::json::Behaviour<EnrollmentRequest, EnrollmentResponse>,
    pub identify: identify::Behaviour,
    pub relay: relay::Behaviour,
    pub rendezvous: rendezvous::server::Behaviour,
}

impl Behaviour {
    pub fn new(local_key: &Keypair) -> Result<Self, &'static str> {
        Ok(Self {
            gossipsub: gossipsub(local_key)?,
            enrollment: enrollment(),
            identify: identify::Behaviour::new(
                identify::Config::new("/cat4igp/1.0.0".into(), local_key.public())
                    .with_agent_version("cat4igp/0.1.0".into()),
            ),
            relay: relay::Behaviour::new(local_key.public().to_peer_id(), relay::Config::default()),
            rendezvous: rendezvous::server::Behaviour::new(rendezvous::server::Config::default()),
        })
    }
}

/// Builds the controller's direct TCP/QUIC swarm.
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
        .with_behaviour(|key| {
            Behaviour::new(key).map_err(|error| std::io::Error::other(error).into())
        })?
        .build())
}

/// Starts a controller listener; observe swarm events for bind completion.
pub fn listen(
    swarm: &mut Swarm<Behaviour>,
    address: libp2p::Multiaddr,
) -> Result<libp2p::core::transport::ListenerId, libp2p::TransportError<io::Error>> {
    swarm.listen_on(address)
}

pub fn shared_topic(network_id: &str) -> IdentTopic {
    IdentTopic::new(format!("cat4igp/{network_id}/shared/v1"))
}

pub fn command_topic(network_id: &str, node: &str) -> IdentTopic {
    IdentTopic::new(format!("cat4igp/{network_id}/node/{node}/v1"))
}

/// Controller PubSub authenticates every sender before application validation.
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

/// Controller enrollment endpoint for direct or relay-circuit requests.
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

#[cfg(test)]
mod tests {
    use super::{command_topic, shared_topic};

    #[test]
    fn controller_topics_are_private_network_scoped() {
        assert_ne!(
            shared_topic("network-a").hash(),
            shared_topic("network-b").hash()
        );
        assert_ne!(
            command_topic("network-a", "one").hash(),
            shared_topic("network-a").hash()
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
        assert!(super::Behaviour::new(&libp2p::identity::Keypair::generate_ed25519()).is_ok());
    }

    #[test]
    fn swarm_builds() {
        assert!(super::swarm(libp2p::identity::Keypair::generate_ed25519()).is_ok());
    }
}
