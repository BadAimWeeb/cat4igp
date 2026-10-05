//! Public-metadata Gossipsub contracts. Discovery is not admission or consensus.
//! Callers supply an out-of-band pinned logical key, never a key from this topic.
use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use rand08::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub mod join;
pub mod transport;

pub const VERSION: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const QUERY_TTL_MS: i64 = 30_000;
const ROSTER_TTL_MS: i64 = 300_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Client,
    Replica,
}

pub fn topic(cluster_id: &str, role: Role) -> Result<String, &'static str> {
    cluster(cluster_id)?;
    let role = match role {
        Role::Client => "client",
        Role::Replica => "replica",
    };
    Ok(format!("/cat4igp/discovery/v1/{cluster_id}/{role}"))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindControllers {
    pub version: u16,
    pub cluster_id: String,
    pub role: Role,
    pub requester: PeerId,
    pub nonce: [u8; 16],
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

impl FindControllers {
    pub fn new(
        cluster_id: String,
        role: Role,
        requester: PeerId,
        now_ms: i64,
    ) -> Result<Self, &'static str> {
        cluster(&cluster_id)?;
        let mut nonce = [0; 16];
        rand08::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            version: VERSION,
            cluster_id,
            role,
            requester,
            nonce,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.checked_add(QUERY_TTL_MS).ok_or("invalid time")?,
        })
    }

    /// `source` is the authenticated Gossipsub author, not the relay peer.
    pub fn validate(
        &self,
        source: PeerId,
        cluster_id: &str,
        role: Role,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        cluster(&self.cluster_id)?;
        if self.version != VERSION
            || self.cluster_id != cluster_id
            || self.role != role
            || self.requester != source
        {
            return Err("unrelated discovery query");
        }
        lifetime(self.issued_at_ms, self.expires_at_ms, now_ms, QUERY_TTL_MS)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerEndpoint {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

impl ControllerEndpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.addresses.is_empty() || self.addresses.len() > 4 {
            return Err("invalid address count");
        }
        for (index, address) in self.addresses.iter().enumerate() {
            if address.to_vec().len() > 256 || self.addresses[..index].contains(address) {
                return Err("invalid address");
            }
            // ponytail: IP/TCP endpoints only; add DNS after enabling the DNS transport.
            let mut parts = address.iter();
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (
                    Some(Protocol::Ip4(ip)),
                    Some(Protocol::Tcp(port)),
                    Some(Protocol::P2p(peer)),
                    None,
                ) if !ip.is_unspecified()
                    && !ip.is_multicast()
                    && port != 0
                    && peer == self.peer_id => {}
                (
                    Some(Protocol::Ip6(ip)),
                    Some(Protocol::Tcp(port)),
                    Some(Protocol::P2p(peer)),
                    None,
                ) if !ip.is_unspecified()
                    && !ip.is_multicast()
                    && port != 0
                    && peer == self.peer_id => {}
                _ => return Err("invalid controller address"),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerRoster {
    pub version: u16,
    pub cluster_id: String,
    pub revision: u64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub controllers: Vec<ControllerEndpoint>,
    /// Explicit public Noise discovery listeners, never inferred from control addresses.
    /// Empty is omitted so pre-extension roster signatures remain valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovery_endpoints: Vec<ControllerEndpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signature: Vec<u8>,
}

fn signing_bytes<T: Serialize>(domain: &str, body: &T) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(&(domain, body)).map_err(|_| "invalid discovery encoding")?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("discovery message too large");
    }
    Ok(bytes)
}

fn sign<T: Serialize>(
    body: T,
    domain: &str,
    key: &identity::Keypair,
) -> Result<Signed<T>, &'static str> {
    let signature = key
        .sign(&signing_bytes(domain, &body)?)
        .map_err(|_| "discovery signing failed")?;
    Ok(Signed { body, signature })
}

fn verify<T: Serialize>(
    signed: &Signed<T>,
    domain: &str,
    pin: &identity::PublicKey,
) -> Result<(), &'static str> {
    if signed.signature.len() != 64
        || !pin.verify(&signing_bytes(domain, &signed.body)?, &signed.signature)
    {
        return Err("invalid discovery signature");
    }
    Ok(())
}

impl ControllerRoster {
    pub fn sign(self, key: &identity::Keypair) -> Result<Signed<Self>, &'static str> {
        sign(self, "cat4igp/discovery/roster/v1", key)
    }
}

impl Signed<ControllerRoster> {
    pub fn validate(
        &self,
        pin: &identity::PublicKey,
        cluster_id: &str,
        minimum_revision: u64,
        now_ms: i64,
    ) -> Result<(), &'static str> {
        verify(self, "cat4igp/discovery/roster/v1", pin)?;
        let roster = &self.body;
        cluster(&roster.cluster_id)?;
        if roster.version != VERSION
            || roster.cluster_id != cluster_id
            || roster.revision < minimum_revision
        {
            return Err("untrusted roster");
        }
        lifetime(
            roster.issued_at_ms,
            roster.expires_at_ms,
            now_ms,
            ROSTER_TTL_MS,
        )?;
        if roster.controllers.is_empty() || roster.controllers.len() > 16 {
            return Err("invalid roster size");
        }
        for (index, endpoint) in roster.controllers.iter().enumerate() {
            endpoint.validate()?;
            if roster.controllers[..index]
                .iter()
                .any(|other| other.peer_id == endpoint.peer_id)
            {
                return Err("duplicate controller");
            }
        }
        if roster.discovery_endpoints.len() > 16 {
            return Err("invalid discovery roster size");
        }
        for (index, endpoint) in roster.discovery_endpoints.iter().enumerate() {
            endpoint.validate()?;
            if !roster
                .controllers
                .iter()
                .any(|serving| serving.peer_id == endpoint.peer_id)
                || roster.discovery_endpoints[..index]
                    .iter()
                    .any(|other| other.peer_id == endpoint.peer_id)
            {
                return Err("unauthorized or duplicate discovery controller");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerAvailable {
    pub version: u16,
    pub cluster_id: String,
    pub role: Role,
    pub recipient: PeerId,
    pub nonce: [u8; 16],
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub endpoint: ControllerEndpoint,
    pub roster: Signed<ControllerRoster>,
}

impl ControllerAvailable {
    pub fn sign(self, key: &identity::Keypair) -> Result<Signed<Self>, &'static str> {
        sign(self, "cat4igp/discovery/available/v1", key)
    }
}

impl Signed<ControllerAvailable> {
    /// Only returns authorized public endpoints. Never grants replica admission.
    /// Caller must retain the highest verified roster revision and deduplicate by peer.
    pub fn validate(
        &self,
        pin: &identity::PublicKey,
        pending: &FindControllers,
        source: PeerId,
        minimum_revision: u64,
        now_ms: i64,
    ) -> Result<&ControllerEndpoint, &'static str> {
        pending.validate(pending.requester, &pending.cluster_id, pending.role, now_ms)?;
        verify(self, "cat4igp/discovery/available/v1", pin)?;
        let response = &self.body;
        if response.version != VERSION
            || response.cluster_id != pending.cluster_id
            || response.role != pending.role
            || response.recipient != pending.requester
            || response.nonce != pending.nonce
            || response.endpoint.peer_id != source
        {
            return Err("unrelated discovery response");
        }
        lifetime(
            response.issued_at_ms,
            response.expires_at_ms,
            now_ms,
            QUERY_TTL_MS,
        )?;
        if response.issued_at_ms < pending.issued_at_ms
            || response.expires_at_ms > pending.expires_at_ms
            || response.expires_at_ms > response.roster.body.expires_at_ms
        {
            return Err("invalid response lifetime");
        }
        response
            .roster
            .validate(pin, &pending.cluster_id, minimum_revision, now_ms)?;
        if !response
            .roster
            .body
            .controllers
            .contains(&response.endpoint)
        {
            return Err("unauthorized controller");
        }
        Ok(&response.endpoint)
    }
}

/// Bound raw input before JSON allocation; unknown fields (including secrets) reject.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("discovery message too large");
    }
    serde_json::from_slice(bytes).map_err(|_| "invalid discovery message")
}

pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, &'static str> {
    let bytes = serde_json::to_vec(message).map_err(|_| "invalid discovery message")?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err("discovery message too large");
    }
    Ok(bytes)
}

fn cluster(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid cluster id");
    }
    Ok(())
}

fn lifetime(issued: i64, expires: i64, now: i64, maximum: i64) -> Result<(), &'static str> {
    if issued > now
        || now >= expires
        || !matches!(expires.checked_sub(issued), Some(duration) if duration > 0 && duration <= maximum)
    {
        return Err("expired or invalid discovery lifetime");
    }
    Ok(())
}

#[cfg(test)]
#[path = "discovery_test.rs"]
mod tests;
