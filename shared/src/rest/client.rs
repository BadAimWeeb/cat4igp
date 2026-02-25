use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct RegisterPayload {
    pub node_name: String,
    pub invitation_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegisterResponse {
    pub success: bool,
    pub auth_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateNamePayload {
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeInfoResponse {
    pub success: bool,
    pub id: i32,
    pub name: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SingleNode {
    pub id: i32,
    pub name: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AllNodesResponse {
    pub success: bool,
    pub nodes: Vec<SingleNode>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardTunnelInfo {
    pub tunnel_id: i32,
    pub peer_node_id: i32,
    pub public_key: String,
    pub preferred_port: u16,
    pub remote_endpoint: Option<String>,
    pub local_answered: crate::custom_type::WireguardAnswered,
    pub remote_response: crate::custom_type::WireguardAnswered,
    pub mtu: i32,
    pub endpoint_ipv6: bool,
    pub fec: bool,
    pub faketcp: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardTunnelsResponse {
    pub success: bool,
    pub tunnels: Vec<WireguardTunnelInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardTunnelAnswerPayload {
    pub tunnel_id: i32,
    pub decline_type: Option<i16>,
    pub endpoint: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardPubKeyAskPayload {
    pub node_id_peer: i32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardPubKeyResponse {
    pub success: bool,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WireguardPubKeyUpdatePayload {
    pub public_key: String,
}