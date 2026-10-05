//! Replica credentials travel only in bounded direct Noise streams, never pubsub.
use super::*;
use futures_util::StreamExt;
use libp2p::{request_response, swarm::SwarmEvent};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ponytail: exact application schema/protocol epoch; incompatible changes require stop-all upgrades.
pub const APPLICATION_VERSION: u8 = 1;

pub fn transport_fingerprint(psk: libp2p::pnet::PreSharedKey) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(psk.to_key_file().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub application_version: u8,
    pub cluster_id: String,
    pub request_id: String,
    pub node_id: u64,
    pub address: Multiaddr,
    pub code: String,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplicaJoin([redacted])")
    }
}

impl Request {
    pub fn validate(&self, source: PeerId, cluster: &str) -> Result<(), String> {
        if self.application_version != APPLICATION_VERSION
            || self.cluster_id != cluster
            || cluster.is_empty()
            || cluster.len() > 64
            || self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.node_id == 0
            || self.code.len() != 64
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid replica join".into());
        }
        ControllerEndpoint {
            peer_id: source,
            addresses: vec![self.address.clone()],
        }
        .validate()
        .map_err(str::to_owned)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum Response {
    // No PSK, snapshot, serving authorization or Raft membership is released.
    Pending {
        request_id: String,
        node_id: u64,
        peer_id: PeerId,
    },
    Bootstrap {
        request_id: String,
        node_id: u64,
        peer_id: PeerId,
        cluster_id: String,
        cluster_psk: String,
        #[serde(default)]
        transport_generation: u64,
        replicas: std::collections::BTreeMap<u64, ControllerEndpoint>,
    },
    Rejected,
    Unavailable,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplicaJoinResponse([redacted])")
    }
}

impl Response {
    pub fn validate(&self, request: &Request, peer: PeerId) -> Result<(), String> {
        match self {
            Self::Bootstrap {
                request_id,
                node_id,
                peer_id,
                cluster_id,
                cluster_psk,
                replicas,
                ..
            } => {
                if request_id != &request.request_id
                    || *node_id != request.node_id
                    || *peer_id != peer
                    || cluster_id != &request.cluster_id
                    || replicas.is_empty()
                    || replicas.len() > 64
                    || replicas.keys().any(|id| *id == 0)
                    || cluster_psk.len() > 128
                    || !cluster_psk.is_ascii()
                    || cluster_psk.parse::<libp2p::pnet::PreSharedKey>().is_err()
                    || replicas
                        .values()
                        .map(|r| r.peer_id)
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        != replicas.len()
                    || replicas.get(node_id)
                        != Some(&ControllerEndpoint {
                            peer_id: peer,
                            addresses: vec![request.address.clone()],
                        })
                {
                    return Err("invalid replica bootstrap".into());
                }
                for endpoint in replicas.values() {
                    endpoint.validate().map_err(str::to_owned)?;
                }
                let mut addresses = std::collections::HashSet::new();
                for endpoint in replicas.values() {
                    if endpoint.addresses.len() != 1 {
                        return Err("ambiguous transport endpoint".into());
                    }
                    let mut address = endpoint.addresses[0].clone();
                    address.pop();
                    if !addresses.insert(address) {
                        return Err("duplicate transport endpoint".into());
                    }
                }
                Ok(())
            }
            Self::Pending {
                request_id,
                node_id,
                peer_id,
            } if request_id != &request.request_id
                || *node_id != request.node_id
                || *peer_id != peer =>
            {
                Err("uncorrelated admission response".into())
            }
            _ => Ok(()),
        }
    }
}

/// Discover with an out-of-band authority pin before disclosing the code to a roster endpoint.
pub async fn request(
    key: &identity::Keypair,
    pin: &identity::PublicKey,
    bootstraps: &[Multiaddr],
    minimum_revision: u64,
    request: Request,
) -> Result<Response, String> {
    request.validate(key.public().to_peer_id(), &request.cluster_id)?;
    let proof = super::transport::discover(
        key,
        pin,
        &request.cluster_id,
        Role::Replica,
        bootstraps,
        minimum_revision,
    )
    .await?;
    let peer = proof.body.endpoint.peer_id;
    let mut swarm = super::transport::swarm(key)?;
    for address in &proof.body.endpoint.addresses {
        swarm.add_peer_address(peer, address.clone());
    }
    let id = swarm
        .behaviour_mut()
        .join
        .send_request(&peer, request.clone());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(super::transport::Event::Join(
                    request_response::Event::Message {
                        peer: source,
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    },
                )) if source == peer && request_id == id => {
                    response.validate(&request, key.public().to_peer_id())?;
                    if let Response::Pending {
                        request_id,
                        node_id,
                        peer_id,
                    } = &response
                    {
                        if request_id != &request.request_id
                            || *node_id != request.node_id
                            || *peer_id != key.public().to_peer_id()
                        {
                            return Err("uncorrelated admission response".into());
                        }
                    }
                    return Ok(response);
                }
                SwarmEvent::Behaviour(super::transport::Event::Join(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) if request_id == id => return Err("replica join unavailable".into()),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "replica join deadline exceeded".to_owned())?
}
