use diesel::prelude::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::nodes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Node {
    pub id: i32,
    pub name: String,
    pub auth_key: String,
    pub created_at: chrono::NaiveDateTime,
    pub last_seen: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::nodes)]
pub struct NewNode<'a> {
    pub name: &'a str,
    pub auth_key: &'a str,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::wireguard_static_key)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct WireguardStaticKey {
    pub node_id: i32,
    pub public_key: String,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::wireguard_static_key)]
pub struct NewWireguardStaticKey<'a> {
    pub node_id: i32,
    pub public_key: &'a str,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::wireguard_tunnels)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct WireguardTunnel {
    pub id: i32,
    pub node_id_peer1: i32,
    pub node_id_peer2: i32,
    pub endpoint_peer1: Option<String>,
    pub endpoint_peer2: Option<String>,
    pub peer1_answered: bool,
    pub peer2_answered: bool,
    pub mtu: i32,
    pub endpoint_ipv6: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::wireguard_tunnels)]
pub struct NewWireguardTunnel {
    pub node_id_peer1: i32,
    pub node_id_peer2: i32,
    pub endpoint_peer1: Option<String>,
    pub endpoint_peer2: Option<String>,
    pub mtu: i32,
    pub endpoint_ipv6: bool
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::invites)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Invite {
    pub id: i32,
    pub code: String,
    pub created_at: chrono::NaiveDateTime,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub used_count: i32,
    pub max_uses: Option<i32>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::invites)]
pub struct NewInvite<'a> {
    pub code: &'a str,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub max_uses: Option<i32>,
}
