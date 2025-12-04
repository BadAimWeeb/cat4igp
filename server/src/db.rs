use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;
use crate::models::{Node, Invite};
use uuid::Uuid;

pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn authenticate(conn: &mut SqliteConnection, key: &str) -> Result<Node, diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    nodes
        .filter(auth_key.eq(key))
        .select(Node::as_select())
        .first(conn)
}

pub fn register_node(conn: &mut SqliteConnection, node_name: &str, invitation_key: &str) -> Result<String, diesel::result::Error> {
    use crate::schema::nodes;
    use crate::schema::invites::dsl::*;

    let inv = invites
        .filter(code.eq(invitation_key))
        .first::<Invite>(conn)?;

    if let Some(max) = inv.max_uses {
        if inv.used_count >= max {
            return Err(diesel::result::Error::NotFound);
        }
    }

    diesel::update(invites.filter(id.eq(inv.id)))
        .set(used_count.eq(used_count + 1))
        .execute(conn)?;

    let nauthk = Uuid::new_v4().to_string();

    let new_node = crate::models::NewNode {
        name: node_name,
        auth_key: &nauthk,
    };

    diesel::insert_into(nodes::table)
        .values(&new_node)
        .execute(conn)?;

    Ok(nauthk)
}

pub fn update_node_name(conn: &mut SqliteConnection, node_id_val: i32, new_name: &str) -> Result<(), diesel::result::Error> {
    use crate::schema::nodes::dsl::*;

    diesel::update(nodes.filter(id.eq(node_id_val)))
        .set(name.eq(new_name))
        .execute(conn)?;
    
    Ok(())
}

pub fn update_wireguard_pubkey(conn: &mut SqliteConnection, node_id_val: i32, pubkey: &str) -> Result<(), diesel::result::Error> {
    use crate::schema::wireguard_static_key;
    use crate::schema::wireguard_static_key::dsl::*;

    let new_pk = crate::models::NewWireguardStaticKey {
        node_id: node_id_val,
        public_key: pubkey,
    };

    diesel::insert_into(wireguard_static_key::table)
        .values(&new_pk)
        .on_conflict(node_id)
        .do_update()
        .set(public_key.eq(pubkey))
        .execute(conn)?;
    Ok(())
}

pub fn get_wireguard_pubkey(conn: &mut SqliteConnection, node_id_val: i32) -> Result<String, diesel::result::Error> {
    use crate::schema::wireguard_static_key::dsl::*;

    let key_record = wireguard_static_key
        .filter(node_id.eq(node_id_val))
        .select(public_key)
        .first::<String>(conn)?;

    Ok(key_record)
}


