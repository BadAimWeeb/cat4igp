use serde::{Serialize, Deserialize};
use chrono;

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateInvitePayload {
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub join_mesh: Option<i32>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateInviteResponse {
    pub success: bool,
    pub invite_code: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Invite {
    pub id: i32,
    pub code: String,
    pub created_at: chrono::NaiveDateTime,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub used_count: i32,
    pub override_join_mesh: Option<i32>,
    pub max_uses: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetInvitesResponse {
    pub success: bool,
    pub invites: Vec<Invite>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateMeshPayload {
    pub name: String,
    pub auto_wireguard: Option<bool>,
    pub auto_wireguard_mtu: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateMeshResponse {
    pub success: bool,
    pub mesh_group_id: i32,
}
