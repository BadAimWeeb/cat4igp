use axum::{Json, extract::Extension};
use serde::{Serialize, Deserialize};

use crate::{ext::WireguardAnswered};

#[derive(Serialize, Deserialize)]
pub struct StandardResponse {
    success: bool,
    message: Option<String>,
}


#[derive(Deserialize)]
pub struct RegisterPayload {
    node_name: String,
    invitation_key: String
}

#[derive(Serialize)]
pub struct RegisterResponse {
    success: bool,
    auth_key: String
}

pub async fn register(Json(payload): Json<RegisterPayload>) -> Result<Json<RegisterResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let (nid, auth_key) = crate::db::register_node(&mut conn, &payload.node_name, &payload.invitation_key).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Registration error: {}", e))
        }))
    })?;

    // mesh group handling
    let default_mesh_group = crate::db::get_setting(&mut conn, "default_mesh_group");
    if let Ok(group_id_string) = default_mesh_group {
        // convert from string to integer
        let group_id_try = group_id_string.parse::<i32>();
        if let Ok(group_id) = group_id_try {
            // join mesh
            let _ = crate::db::join_mesh(&mut conn, nid, group_id);
        }
    }

    Ok(Json(RegisterResponse {
        success: true,
        auth_key,
    }))
}


#[derive(Deserialize)]
pub struct UpdateNamePayload {
    new_name: String
}

pub async fn update_name(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<UpdateNamePayload>
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::update_node_name(&mut conn, node.id, &payload.new_name).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to update name: {}", e))
        }))
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}


#[derive(Serialize)]
pub struct NodeInfoResponse {
    success: bool,
    id: i32,
    name: String,
    created_at: i64
}

pub async fn get_self_info(
    Extension(node): Extension<crate::models::Node>,
) -> Json<NodeInfoResponse> {
    Json(NodeInfoResponse {
        success: true,
        id: node.id,
        name: node.name,
        created_at: node.created_at.and_utc().timestamp_millis(),
    })
}


#[derive(Serialize)]
pub struct NodeResponse {
    id: i32,
    name: String,
    created_at: i64,
}

#[derive(Serialize)]
pub struct AllNodesResponse {
    success: bool,
    nodes: Vec<NodeResponse>
}

pub async fn get_all_nodes() -> Result<Json<AllNodesResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let nodes = crate::db::get_node_list(&mut conn).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to get node list: {}", e))
        }))
    })?;

    let node_responses: Vec<NodeResponse> = nodes.into_iter().map(|n| {
        NodeResponse {
            id: n.id,
            name: n.name,
            created_at: n.created_at.and_utc().timestamp_millis(),
        }
    }).collect();

    Ok(Json(AllNodesResponse {
        success: true,
        nodes: node_responses,
    }))
}


#[derive(Serialize)]
pub struct WireguardTunnelInfo {
    tunnel_id: i32,
    peer_node_id: i32,
    public_key: String,
    remote_endpoint: Option<String>,
    local_answered: WireguardAnswered,
    remote_response: WireguardAnswered,
    mtu: i32,
    endpoint_ipv6: bool,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
pub struct WireguardTunnelsResponse {
    success: bool,
    tunnels: Vec<WireguardTunnelInfo>
}

pub async fn get_wireguard_tunnels(
    Extension(node): Extension<crate::models::Node>,
) -> Result<Json<WireguardTunnelsResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let tunnels = crate::db::get_wireguard_answers(&mut conn, node.id).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to get wireguard tunnels: {}", e))
        }))
    })?;

    let mut tunnel_infos: Vec<WireguardTunnelInfo> = Vec::new();

    for tunnel in tunnels {
        let self_p1 = tunnel.node_id_peer1 == node.id;

        let peer_node_id = if self_p1 {
            tunnel.node_id_peer2
        } else {
            tunnel.node_id_peer1
        };

        let local_answered = if self_p1 {
            tunnel.peer1_answered
        } else {
            tunnel.peer2_answered
        };

        let remote_response = if self_p1 {
            tunnel.peer2_answered
        } else {
            tunnel.peer1_answered
        };

        let public_key = crate::db::get_wireguard_pubkey(&mut conn, peer_node_id).unwrap_or_default();

        tunnel_infos.push(WireguardTunnelInfo {
            tunnel_id: tunnel.id,
            peer_node_id,
            public_key,
            remote_endpoint: tunnel.endpoint_peer2.clone(),
            local_answered: local_answered.into(),
            remote_response: remote_response.into(),
            mtu: tunnel.mtu,
            endpoint_ipv6: tunnel.endpoint_ipv6,
            created_at: tunnel.created_at.and_utc().timestamp_millis(),
            updated_at: tunnel.updated_at.and_utc().timestamp_millis(),
        });
    }

    Ok(Json(WireguardTunnelsResponse {
        success: true,
        tunnels: tunnel_infos,
    }))
}


#[derive(Deserialize)]
pub struct WireguardTunnelAnswerPayload {
    tunnel_id: i32,
    decline_type: Option<i16>,
    endpoint: Option<String>,
}

pub async fn answer_wireguard_tunnel(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<WireguardTunnelAnswerPayload>
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::answer_wireguard_tunnel(
        &mut conn,
        payload.tunnel_id,
        node.id,
        payload.endpoint,
        payload.decline_type
    ).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to answer wireguard tunnel: {}", e))
        }))
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}


#[derive(Deserialize)]
pub struct WireguardPubKeyAskPayload {
    node_id_peer: i32
}

#[derive(Serialize)]
pub struct WireguardPubKeyResponse {
    success: bool,
    public_key: String
}

pub async fn get_wireguard_pubkey(
    Json(payload): Json<WireguardPubKeyAskPayload>
) -> Result<Json<WireguardPubKeyResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let public_key = crate::db::get_wireguard_pubkey(&mut conn, payload.node_id_peer).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to get wireguard public key: {}", e))
        }))
    })?;

    Ok(Json(WireguardPubKeyResponse {
        success: true,
        public_key,
    }))
}


#[derive(Deserialize)]
pub struct WireguardPubKeyUpdatePayload {
    public_key: String
}

pub async fn update_wireguard_pubkey(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<WireguardPubKeyUpdatePayload>
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::update_wireguard_pubkey(&mut conn, node.id, &payload.public_key).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to update wireguard public key: {}", e))
        }))
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}
