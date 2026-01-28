use axum::{Json, extract::Extension};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct StandardResponse {
    success: bool,
    message: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateInvitePayload {
    expires_at: Option<i64>,
    max_uses: Option<i32>,
    join_mesh: Option<i32>
}

#[derive(Serialize)]
pub struct CreateInviteResponse {
    success: bool,
    invite_code: String
}

pub async fn create_invite(Json(payload): Json<CreateInvitePayload>) -> Result<Json<CreateInviteResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let expires_at = if let Some(ts) = payload.expires_at {
        let o = chrono::DateTime::<chrono::Utc>::from_timestamp(ts / 1000, (ts % 1000) as u32 * 1_000_000);

        if let Some(x) = o {
            Some(x.naive_utc())
        } else {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                Json(StandardResponse {
                    success: false,
                    message: Some("Invalid expires_at timestamp".to_string()),
                }),
            ));
        }
    } else {
        None
    };

    let invite_code = crate::db::create_invite_key(&mut conn, expires_at, payload.max_uses, payload.join_mesh).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to create invite: {}", e))
        }))
    })?;

    Ok(Json(CreateInviteResponse {
        success: true,
        invite_code,
    }))
}

#[derive(Serialize)]
pub struct GetInvitesResponse {
    success: bool,
    invites: Vec<crate::models::Invite>,
}

pub async fn get_invites() -> Result<Json<GetInvitesResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let invites = crate::db::get_invites(&mut conn).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to get invites: {}", e))
        }))
    })?;

    Ok(Json(GetInvitesResponse {
        success: true,
        invites,
    }))
}

#[derive(Deserialize)]
pub struct CreateMeshPayload {
    name: String,
    auto_wireguard: Option<bool>,
    auto_wireguard_mtu: Option<i32>,
}

#[derive(Serialize)]
pub struct CreateMeshResponse {
    success: bool,
    mesh_group_id: i32,
}

pub async fn create_mesh(
    Json(payload): Json<CreateMeshPayload>,
) -> Result<Json<CreateMeshResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let auto_wireguard = payload.auto_wireguard.unwrap_or(false);
    let auto_wireguard_mtu = if auto_wireguard { payload.auto_wireguard_mtu.unwrap_or(1420) } else { 0 };

    let mesh_group = crate::db::create_mesh_group(&mut conn, &payload.name, auto_wireguard, auto_wireguard_mtu).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to create mesh group: {}", e)),
            }),
        )
    })?;

    Ok(Json(CreateMeshResponse {
        success: true,
        mesh_group_id: mesh_group,
    }))
}
