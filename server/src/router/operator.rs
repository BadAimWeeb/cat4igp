use axum::Json;
use cat4igp_shared::rest::StandardResponse;
use cat4igp_shared::rest::operator as REST;

pub async fn create_invite(Json(payload): Json<REST::CreateInvitePayload>) -> Result<Json<REST::CreateInviteResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
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

    Ok(Json(REST::CreateInviteResponse {
        success: true,
        invite_code,
    }))
}

pub async fn get_invites() -> Result<Json<REST::GetInvitesResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let invites = crate::db::get_invites(&mut conn).map_err(|e| {
        (axum::http::StatusCode::BAD_REQUEST, Json(StandardResponse {
            success: false,
            message: Some(format!("Failed to get invites: {}", e))
        }))
    })?;

    Ok(Json(REST::GetInvitesResponse {
        success: true,
        invites: invites.into_iter().map(|inv| REST::Invite {
            id: inv.id,
            code: inv.code,
            created_at: inv.created_at,
            expires_at: inv.expires_at,
            used_count: inv.used_count,
            override_join_mesh: inv.override_join_mesh,
            max_uses: inv.max_uses,
        }).collect(),
    }))
}

pub async fn create_mesh(
    Json(payload): Json<REST::CreateMeshPayload>,
) -> Result<Json<REST::CreateMeshResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
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

    Ok(Json(REST::CreateMeshResponse {
        success: true,
        mesh_group_id: mesh_group,
    }))
}
