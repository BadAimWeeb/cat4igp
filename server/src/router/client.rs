use axum::{Json, extract::Extension};

use cat4igp_shared::rest::StandardResponse;
use cat4igp_shared::rest::client as REST;

pub async fn register(
    Json(payload): Json<REST::RegisterPayload>,
) -> Result<Json<REST::RegisterResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let (nid, auth_key, override_join_mesh) =
        crate::db::register_node(&mut conn, &payload.node_name, &payload.invitation_key).map_err(
            |e| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(StandardResponse {
                        success: false,
                        message: Some(format!("Registration error: {}", e)),
                    }),
                )
            },
        )?;

    // mesh group handling
    if let Some(group_id) = override_join_mesh {
        // 0 override means do not join any mesh, even default one
        if group_id != 0 {
            // join specified mesh
            let _ = crate::db::join_mesh(&mut conn, nid, group_id);
        }
    } else {
        // join default mesh
        let default_mesh_group = crate::db::get_setting(&mut conn, "default_mesh_group");
        if let Ok(group_id_string) = default_mesh_group {
            // convert from string to integer
            let group_id_try = group_id_string.parse::<i32>();
            if let Ok(group_id) = group_id_try {
                // join mesh
                let _ = crate::db::join_mesh(&mut conn, nid, group_id);
            }
        }
    }

    Ok(Json(REST::RegisterResponse {
        success: true,
        auth_key,
    }))
}

pub async fn update_name(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<REST::UpdateNamePayload>,
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::update_node_name(&mut conn, node.id, &payload.new_name).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to update name: {}", e)),
            }),
        )
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}

pub async fn get_self_info(
    Extension(node): Extension<crate::models::Node>,
) -> Json<REST::NodeInfoResponse> {
    Json(REST::NodeInfoResponse {
        success: true,
        id: node.id,
        name: node.name,
        created_at: node.created_at.and_utc().timestamp_millis(),
    })
}

pub async fn get_all_nodes()
-> Result<Json<REST::AllNodesResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let nodes = crate::db::get_node_list(&mut conn).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to get node list: {}", e)),
            }),
        )
    })?;

    let node_responses: Vec<REST::SingleNode> = nodes
        .into_iter()
        .map(|n| REST::SingleNode {
            id: n.id,
            name: n.name,
            created_at: n.created_at.and_utc().timestamp_millis(),
        })
        .collect();

    Ok(Json(REST::AllNodesResponse {
        success: true,
        nodes: node_responses,
    }))
}

pub async fn get_wireguard_tunnels(
    Extension(node): Extension<crate::models::Node>,
) -> Result<Json<REST::WireguardTunnelsResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let tunnels = crate::db::get_wireguard_answers(&mut conn, node.id).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to get wireguard tunnels: {}", e)),
            }),
        )
    })?;

    let mut tunnel_infos: Vec<REST::WireguardTunnelInfo> = Vec::new();

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

        let local_endpoint = if self_p1 {
            tunnel.endpoint_peer1.clone()
        } else {
            tunnel.endpoint_peer2.clone()
        };

        let remote_endpoint = if self_p1 {
            tunnel.endpoint_peer2.clone()
        } else {
            tunnel.endpoint_peer1.clone()
        };

        let public_key =
            crate::db::get_wireguard_pubkey(&mut conn, peer_node_id).unwrap_or_default();

        tunnel_infos.push(REST::WireguardTunnelInfo {
            tunnel_id: tunnel.id,
            peer_node_id,
            public_key,
            preferred_port: local_endpoint
                .map_or(0, |e| {
                    e.split(':').nth(1)
                        .map_or(0, |p| p.parse::<u16>().unwrap_or_default())
                }),
            remote_endpoint,
            local_answered: local_answered.into(),
            remote_response: remote_response.into(),
            mtu: tunnel.mtu,
            endpoint_ipv6: tunnel.endpoint_ipv6,
            fec: tunnel.fec,
            faketcp: tunnel.faketcp,
            created_at: tunnel.created_at.and_utc().timestamp_millis(),
            updated_at: tunnel.updated_at.and_utc().timestamp_millis(),
        });
    }

    Ok(Json(REST::WireguardTunnelsResponse {
        success: true,
        tunnels: tunnel_infos,
    }))
}

pub async fn answer_wireguard_tunnel(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<REST::WireguardTunnelAnswerPayload>,
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::answer_wireguard_tunnel(
        &mut conn,
        payload.tunnel_id,
        node.id,
        payload.endpoint,
        payload.decline_type,
    )
    .map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to answer wireguard tunnel: {}", e)),
            }),
        )
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}

pub async fn get_wireguard_pubkey(
    Json(payload): Json<REST::WireguardPubKeyAskPayload>,
) -> Result<Json<REST::WireguardPubKeyResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let public_key =
        crate::db::get_wireguard_pubkey(&mut conn, payload.node_id_peer).map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(StandardResponse {
                    success: false,
                    message: Some(format!("Failed to get wireguard public key: {}", e)),
                }),
            )
        })?;

    Ok(Json(REST::WireguardPubKeyResponse {
        success: true,
        public_key,
    }))
}

pub async fn update_wireguard_pubkey(
    Extension(node): Extension<crate::models::Node>,
    Json(payload): Json<REST::WireguardPubKeyUpdatePayload>,
) -> Result<Json<StandardResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    crate::db::update_wireguard_pubkey(&mut conn, node.id, &payload.public_key).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to update wireguard public key: {}", e)),
            }),
        )
    })?;

    Ok(Json(StandardResponse {
        success: true,
        message: None,
    }))
}
