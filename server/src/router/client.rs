use axum::{Json, extract::Extension};
use serde::{Serialize, Deserialize};

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

pub async fn register(Json(payload): Json<RegisterPayload>) -> Result<Json<String>, (axum::http::StatusCode, String)> {
    let mut conn = crate::db::establish_connection();

    let auth_key = crate::db::register_node(&mut conn, &payload.node_name, &payload.invitation_key).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, format!("Registration error: {}", e))
    })?;

    Ok(Json(auth_key))
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
