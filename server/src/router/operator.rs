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
    max_uses: Option<i32>
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

    let invite_code = crate::db::create_invite_key(&mut conn, expires_at, payload.max_uses).map_err(|e| {
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
