use crate::{
    db::Database,
    p2p::{Behaviour, command_topic},
};
use cat4igp_protocol::{
    DesiredState, EnrollmentRequest, EnrollmentResponse, Error, NetworkId, NodeId, SignedCommand,
    seal_and_sign,
};
use ed25519_dalek::SigningKey;
use libp2p::{
    Swarm,
    futures::StreamExt,
    gossipsub::TopicHash,
    request_response::{Event as RequestResponseEvent, Message as RequestResponseMessage},
    swarm::SwarmEvent,
};
use x25519_dalek::PublicKey;

pub struct Controller {
    database: Database,
    network_id: NetworkId,
    signing_key: SigningKey,
}

/// Issues and publishes state on its recipient-only topic.
pub fn publish_state(
    swarm: &mut Swarm<Behaviour>,
    controller: &Controller,
    recipient_key: &PublicKey,
    state: DesiredState,
    expires_at_unix: u64,
) -> Result<libp2p::gossipsub::MessageId, IssueError> {
    let (topic, payload) = controller.publishable_state(recipient_key, state, expires_at_unix)?;
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, payload)
        .map_err(IssueError::Publish)
}

/// Serves enrollment requests from the controller swarm.
pub async fn serve_enrollment(mut swarm: Swarm<crate::p2p::Behaviour>, mut controller: Controller) {
    loop {
        if let SwarmEvent::Behaviour(crate::p2p::BehaviourEvent::Enrollment(
            RequestResponseEvent::Message {
                peer,
                message:
                    RequestResponseMessage::Request {
                        request, channel, ..
                    },
                ..
            },
        )) = swarm.select_next_some().await
        {
            match controller.enroll(peer, request, cat4igp_protocol::unix_now()) {
                Ok(response) => {
                    if let Err(response) = swarm
                        .behaviour_mut()
                        .enrollment
                        .send_response(channel, response)
                    {
                        eprintln!("enrollment requester disconnected: {response:?}");
                    }
                }
                // ponytail: rejected enrollment waits for request timeout; add a versioned error response.
                Err(error) => eprintln!("enrollment rejected: {error}"),
            }
        }
    }
}

impl Controller {
    pub fn new(database: Database, network_id: NetworkId, signing_key: SigningKey) -> Self {
        Self {
            database,
            network_id,
            signing_key,
        }
    }

    pub fn issue_state(
        &self,
        recipient_key: &PublicKey,
        mut state: DesiredState,
        expires_at_unix: u64,
    ) -> Result<SignedCommand, IssueError> {
        let recipient = cat4igp_protocol::NodeId::from_command_key(recipient_key);
        if self.database.enrolled_command_key(&recipient.to_string())?
            != Some(*recipient_key.as_bytes())
        {
            return Err(IssueError::UnknownRecipient);
        }
        state.node_id = recipient.clone();
        state.revision = self.database.next_revision(&recipient.to_string())?;
        Ok(seal_and_sign(
            &state,
            self.network_id.clone(),
            recipient_key,
            state.revision,
            expires_at_unix,
            &self.signing_key,
        )?)
    }

    /// Consumes a one-time token and binds the caller's three public identities.
    pub fn enroll(
        &mut self,
        peer: libp2p::PeerId,
        request: EnrollmentRequest,
        now_unix: u64,
    ) -> Result<EnrollmentResponse, IssueError> {
        if request.libp2p_peer_id != peer.to_string() {
            return Err(IssueError::PeerIdMismatch);
        }
        let command_key = PublicKey::from(request.command_public_key);
        let node_id = NodeId::from_command_key(&command_key);
        if !self.database.enroll_node(
            &request.token,
            now_unix,
            &node_id.to_string(),
            &request.libp2p_peer_id,
            &request.command_public_key,
            &request.wireguard_public_key,
        )? {
            return Err(IssueError::EnrollmentRejected);
        }
        Ok(EnrollmentResponse {
            node_id,
            network_id: self.network_id.clone(),
        })
    }

    /// Serializes a signed, sealed command for the recipient-only PubSub topic.
    pub fn publishable_state(
        &self,
        recipient_key: &PublicKey,
        state: DesiredState,
        expires_at_unix: u64,
    ) -> Result<(TopicHash, Vec<u8>), IssueError> {
        let command = self.issue_state(recipient_key, state, expires_at_unix)?;
        let topic = command_topic(
            &self.network_id.to_string(),
            &command.command.recipient.to_string(),
        )
        .hash();
        Ok((topic, serde_json::to_vec(&command)?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Protocol(#[from] Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("PubSub command publication failed: {0}")]
    Publish(#[from] libp2p::gossipsub::PublishError),
    #[error("enrollment token is invalid, expired, or already used")]
    EnrollmentRejected,
    #[error("enrollment request does not match its libp2p transport peer")]
    PeerIdMismatch,
    #[error("state recipient is not enrolled with this command key")]
    UnknownRecipient,
}

#[cfg(test)]
mod tests {
    use super::Controller;
    use crate::db::Database;
    use cat4igp_protocol::{DesiredState, EnrollmentRequest, NetworkId, verify_desired_state};
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn issued_state_is_bound_to_its_recipient_and_revision() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut controller = Controller::new(
            Database::open(":memory:").unwrap(),
            NetworkId::new("test").unwrap(),
            signing_key.clone(),
        );
        let recipient = StaticSecret::random_from_rng(rand::rngs::OsRng);
        controller
            .database
            .add_enrollment_token("join", 10)
            .unwrap();
        let peer = libp2p::PeerId::random();
        controller
            .enroll(
                peer,
                EnrollmentRequest {
                    token: "join".into(),
                    libp2p_peer_id: peer.to_string(),
                    command_public_key: *PublicKey::from(&recipient).as_bytes(),
                    wireguard_public_key: "wg".into(),
                },
                1,
            )
            .unwrap();
        let command = controller
            .issue_state(
                &PublicKey::from(&recipient),
                DesiredState {
                    node_id: cat4igp_protocol::NodeId::from_command_key(&PublicKey::from(
                        &recipient,
                    )),
                    revision: 0,
                    wireguard: vec![],
                },
                10,
            )
            .unwrap();
        let state = verify_desired_state(
            &command,
            &NetworkId::new("test").unwrap(),
            &recipient,
            &signing_key.verifying_key(),
            1,
        )
        .unwrap();
        assert_eq!(state.revision, 1);
    }

    #[test]
    fn enrollment_binds_request_identities() {
        let mut controller = Controller::new(
            Database::open(":memory:").unwrap(),
            NetworkId::new("test").unwrap(),
            SigningKey::generate(&mut rand::rngs::OsRng),
        );
        controller
            .database
            .add_enrollment_token("join", 10)
            .unwrap();
        let command = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let peer = libp2p::PeerId::random();
        let response = controller
            .enroll(
                peer,
                EnrollmentRequest {
                    token: "join".into(),
                    libp2p_peer_id: peer.to_string(),
                    command_public_key: *PublicKey::from(&command).as_bytes(),
                    wireguard_public_key: "wg".into(),
                },
                1,
            )
            .unwrap();
        assert_eq!(
            response.node_id,
            cat4igp_protocol::NodeId::from_command_key(&PublicKey::from(&command))
        );
    }

    #[test]
    fn enrollment_rejects_a_claimed_different_peer() {
        let mut controller = Controller::new(
            Database::open(":memory:").unwrap(),
            NetworkId::new("test").unwrap(),
            SigningKey::generate(&mut rand::rngs::OsRng),
        );
        controller
            .database
            .add_enrollment_token("join", 10)
            .unwrap();
        assert!(matches!(
            controller.enroll(
                libp2p::PeerId::random(),
                EnrollmentRequest {
                    token: "join".into(),
                    libp2p_peer_id: libp2p::PeerId::random().to_string(),
                    command_public_key: [0; 32],
                    wireguard_public_key: "wg".into()
                },
                1,
            ),
            Err(super::IssueError::PeerIdMismatch)
        ));
    }
}
