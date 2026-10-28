use crate::{p2p::command_topic, state_store::StateStore};
use cat4igp_protocol::{
    DesiredState, Error, NetworkId, SignedCommand, require_newer_revision, verify_desired_state,
};
use ed25519_dalek::VerifyingKey;
use libp2p::gossipsub::TopicHash;
use x25519_dalek::{PublicKey, StaticSecret};

/// Verifies a PubSub-delivered command and atomically persists its desired state.
/// Reconciliation must happen only after this function succeeds.
pub fn accept_command(
    command: &SignedCommand,
    network_id: &NetworkId,
    recipient_secret: &StaticSecret,
    server_key: &VerifyingKey,
    now_unix: u64,
    state_store: &StateStore,
) -> Result<DesiredState, AcceptError> {
    let state = verify_desired_state(command, network_id, recipient_secret, server_key, now_unix)?;
    require_newer_revision(state.revision, state_store.accepted_revision()?)?;
    state_store.persist_state(&state, command.command.expires_at_unix)?;
    Ok(state)
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error(transparent)]
    Protocol(#[from] Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("PubSub message arrived on an unexpected topic")]
    WrongTopic,
}

/// Decodes a command only from this node's private PubSub topic.
pub fn accept_pubsub_command(
    topic: &TopicHash,
    payload: &[u8],
    network_id: &NetworkId,
    recipient_secret: &StaticSecret,
    server_key: &VerifyingKey,
    now_unix: u64,
    state_store: &StateStore,
) -> Result<DesiredState, AcceptError> {
    let node_id = cat4igp_protocol::NodeId::from_command_key(&PublicKey::from(recipient_secret));
    if topic != &command_topic(&network_id.to_string(), &node_id.to_string()).hash() {
        return Err(AcceptError::WrongTopic);
    }
    let command = serde_json::from_slice(payload)?;
    accept_command(
        &command,
        network_id,
        recipient_secret,
        server_key,
        now_unix,
        state_store,
    )
}

#[cfg(test)]
mod tests {
    use super::accept_pubsub_command;
    use crate::{p2p::command_topic, state_store::StateStore};
    use cat4igp_protocol::{DesiredState, NetworkId, seal_and_sign};
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn accepts_only_recipient_topic_and_advances_revision() {
        let server = SigningKey::generate(&mut rand::rngs::OsRng);
        let recipient = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let network = NetworkId::new("network").unwrap();
        let command = seal_and_sign(
            &DesiredState {
                node_id: cat4igp_protocol::NodeId::from_command_key(&PublicKey::from(&recipient)),
                revision: 1,
                wireguard: vec![],
            },
            network.clone(),
            &PublicKey::from(&recipient),
            1,
            10,
            &server,
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!("cat4igp-command-{}", std::process::id()));
        let store = StateStore::new(&path);
        let payload = serde_json::to_vec(&command).unwrap();
        let topic =
            command_topic(&network.to_string(), &command.command.recipient.to_string()).hash();
        assert_eq!(
            accept_pubsub_command(
                &topic,
                &payload,
                &network,
                &recipient,
                &server.verifying_key(),
                1,
                &store
            )
            .unwrap()
            .revision,
            1
        );
        std::fs::remove_file(path).unwrap();
    }
}
