use axum::Json;
use cat4igp_shared::rest::StandardResponse;
use cat4igp_shared::rest::operator as REST;

pub async fn create_invite(
    axum::extract::State(jobs): axum::extract::State<crate::DatabaseSender>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<REST::CreateInvitePayload>,
) -> Result<Json<REST::CreateInviteResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    // ponytail: legacy calls are unique attempts; use a stable Idempotency-Key for durable retries.
    let request_id = match headers.get("Idempotency-Key") {
        Some(value) => value
            .to_str()
            .ok()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or_else(|| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(StandardResponse {
                        success: false,
                        message: Some("Idempotency-Key must contain 1..128 ASCII bytes".into()),
                    }),
                )
            })?
            .to_owned(),
        None => uuid::Uuid::new_v4().to_string(),
    };
    let expires_at = if let Some(ts) = payload.expires_at {
        let o = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ts);

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

    let unavailable = || {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(StandardResponse {
                success: false,
                message: Some("database submission unavailable; outcome may be unknown".into()),
            }),
        )
    };
    let (reply, result) = tokio::sync::oneshot::channel();
    jobs.try_send(crate::DatabaseJob::Invite {
        request_id,
        expires_at,
        max_uses: payload.max_uses,
        join_mesh: payload.join_mesh,
        reply,
    })
    .map_err(|_| unavailable())?;
    let invite_code = result
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())?
        .map_err(|e| {
            (
                axum::http::StatusCode::CONFLICT,
                Json(StandardResponse {
                    success: false,
                    message: Some(format!("Failed to create invite: {}", e)),
                }),
            )
        })?;

    Ok(Json(REST::CreateInviteResponse {
        success: true,
        invite_code,
    }))
}

pub async fn get_invites()
-> Result<Json<REST::GetInvitesResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let invites = crate::db::get_invites(&mut conn).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(StandardResponse {
                success: false,
                message: Some(format!("Failed to get invites: {}", e)),
            }),
        )
    })?;

    Ok(Json(REST::GetInvitesResponse {
        success: true,
        invites: invites
            .into_iter()
            .map(|inv| REST::Invite {
                id: inv.id,
                code: inv.code,
                created_at: inv.created_at,
                expires_at: inv.expires_at,
                used_count: inv.used_count,
                override_join_mesh: inv.override_join_mesh,
                max_uses: inv.max_uses,
            })
            .collect(),
    }))
}

pub async fn create_mesh(
    Json(payload): Json<REST::CreateMeshPayload>,
) -> Result<Json<REST::CreateMeshResponse>, (axum::http::StatusCode, Json<StandardResponse>)> {
    let mut conn = crate::db::establish_connection();

    let auto_wireguard = payload.auto_wireguard.unwrap_or(false);
    let auto_wireguard_mtu = if auto_wireguard {
        payload.auto_wireguard_mtu.unwrap_or(1420)
    } else {
        0
    };

    let mesh_group =
        crate::db::create_mesh_group(&mut conn, &payload.name, auto_wireguard, auto_wireguard_mtu)
            .map_err(|e| {
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
