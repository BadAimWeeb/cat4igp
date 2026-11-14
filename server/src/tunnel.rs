use diesel::{prelude::*, sql_types::Integer, SqliteConnection};

/// Remove descendants whose parent no longer exists, including deeper chains.
/// The recursive CTE uses UNION so corrupt legacy cycles cannot loop forever.
pub(crate) fn remove_orphaned(conn: &mut SqliteConnection) -> QueryResult<()> {
    diesel::sql_query("CREATE TEMP TABLE IF NOT EXISTS deleted_tunnel_descendants (id INTEGER PRIMARY KEY)").execute(conn)?;
    diesel::sql_query("DELETE FROM deleted_tunnel_descendants").execute(conn)?;
    diesel::sql_query("WITH RECURSIVE orphan(id) AS (\
        SELECT child_id FROM tunnel_dependencies d WHERE NOT EXISTS \
            (SELECT 1 FROM tunnel_id_registry p WHERE p.id=d.parent_id) \
        UNION SELECT d.child_id FROM tunnel_dependencies d JOIN orphan o ON d.parent_id=o.id) \
        INSERT INTO deleted_tunnel_descendants SELECT id FROM orphan").execute(conn)?;
    diesel::sql_query("DELETE FROM application_kv WHERE key IN (SELECT 'l2tp_active/' || id FROM deleted_tunnel_descendants)").execute(conn)?;
    diesel::sql_query("DELETE FROM l2tpv2_tunnels WHERE id IN (SELECT id FROM deleted_tunnel_descendants)").execute(conn)?;
    diesel::sql_query("DELETE FROM l2tpv3_tunnels WHERE id IN (SELECT id FROM deleted_tunnel_descendants)").execute(conn)?;
    diesel::sql_query("DELETE FROM tunnel_dependencies WHERE NOT EXISTS (SELECT 1 FROM tunnel_id_registry t WHERE t.id=child_id)").execute(conn)?;
    Ok(())
}

/// Validate the currently supported parent type and peer pair without assuming
/// that future tunnel types have WireGuard's storage layout.
pub(crate) fn supports_underlay(conn: &mut SqliteConnection, parent: i32, peers: (i32, i32), required_kind: &str) -> QueryResult<bool> {
    #[derive(QueryableByName)]
    struct Present { #[diesel(sql_type = Integer)] value: i32 }
    let result = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM tunnel_id_registry t JOIN (\
        SELECT id,node_id_peer1,node_id_peer2 FROM wireguard_tunnels \
        UNION ALL SELECT id,node_id_peer1,node_id_peer2 FROM l2tpv2_tunnels \
        UNION ALL SELECT id,node_id_peer1,node_id_peer2 FROM l2tpv3_tunnels \
        ) p ON p.id=t.id WHERE t.id=? AND t.kind=? AND \
        ((p.node_id_peer1=? AND p.node_id_peer2=?) OR (p.node_id_peer1=? AND p.node_id_peer2=?))) AS value")
        .bind::<Integer,_>(parent).bind::<diesel::sql_types::Text,_>(required_kind)
        .bind::<Integer,_>(peers.0).bind::<Integer,_>(peers.1).bind::<Integer,_>(peers.1).bind::<Integer,_>(peers.0)
        .get_result::<Present>(conn)?;
    Ok(result.value != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    #[test]
    fn removing_parent_removes_transitive_descendants() {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        conn.batch_execute("INSERT INTO wireguard_tunnels(id,node_id_peer1,node_id_peer2,endpoint_ipv6) VALUES(1,1,2,0); \
            INSERT INTO l2tpv2_tunnels VALUES(2,1,2,'a','b',1,2,'c','d','secret',1400,1); \
            INSERT INTO l2tpv3_tunnels VALUES(3,'static',1,2,'a','b',1,2,1,2,'0123456789abcdef','fedcba9876543210','pure',NULL,1500); \
            INSERT INTO application_kv VALUES('l2tp_active/3','true'); \
            INSERT INTO tunnel_dependencies VALUES(3,2); DELETE FROM wireguard_tunnels WHERE id=1;").unwrap();
        remove_orphaned(&mut conn).unwrap();
        conn.batch_execute("CREATE TEMP TABLE graph_check(ok INTEGER CHECK(ok=1)); \
            INSERT INTO graph_check SELECT NOT EXISTS(SELECT 1 FROM l2tpv2_tunnels) AND NOT EXISTS(SELECT 1 FROM l2tpv3_tunnels) AND NOT EXISTS(SELECT 1 FROM tunnel_dependencies) AND NOT EXISTS(SELECT 1 FROM application_kv WHERE key='l2tp_active/3');").unwrap();
    }

    #[test]
    fn ids_advance_across_tunnel_types_and_deletions() {
        use crate::admin::{Action, Mutation};
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        crate::db::migrate(&mut conn, true).unwrap();
        conn.batch_execute("INSERT INTO nodes(id,name,auth_key) VALUES(1,'a','a'),(2,'b','b');").unwrap();
        conn.batch_execute("INSERT INTO node_control_identities(node_id,peer_id,signing_key,encryption_key) VALUES(1,'a','a','a'),(2,'b','b','b');").unwrap();
        conn.batch_execute("INSERT INTO application_kv(key,value) VALUES('wireguard_key/1',json_object('public_key','a')),('wireguard_key/2',json_object('public_key','b'));").unwrap();
        for node in [1, 2] {
            crate::db::set_feature_support(&mut conn, node, cat4igp_shared::control::FeatureSupport { l2tp_v2: true, l2tp_v3: true, ..Default::default() }).unwrap();
        }
        crate::db::create_wireguard_tunnel(&mut conn, 1, 2, 1420, false).unwrap();
        let mutation = |request_id: &str, action| Mutation { request_id: request_id.into(), action, applied_at: chrono::Utc::now().naive_utc() };
        let v2 = Action::CreateL2tpV2Tunnel { node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "192.0.2.1".into(), endpoint_peer2: "192.0.2.2".into(), udp_port_peer1: 1701, udp_port_peer2: 1702, address_peer1: "10.0.0.1".into(), address_peer2: "10.0.0.2".into(), secret: "secret".into(), mtu: 1400, wireguard_tunnel_id: None };
        assert!(crate::admin::apply(&mut conn, &mutation("v2", v2)).unwrap().is_ok());
        let v3 = Action::CreateL2tpTunnel { node_id_peer1: 1, node_id_peer2: 2, endpoint_peer1: "192.0.2.1".into(), endpoint_peer2: "192.0.2.2".into(), udp_port_peer1: 1703, udp_port_peer2: 1704, session_id_peer1: 1, session_id_peer2: 2, cookie_peer1: "0123456789abcdef".into(), cookie_peer2: "fedcba9876543210".into(), security_mode: "pure".into(), wireguard_tunnel_id: None, mtu: 1400 };
        assert!(crate::admin::apply(&mut conn, &mutation("v3", v3)).unwrap().is_ok());
        assert_eq!(crate::db::l2tp_v2_rows(&mut conn).unwrap()[0].id, 2);
        assert_eq!(crate::db::l2tp_rows(&mut conn).unwrap()[0].id, 3);
        assert!(crate::admin::apply(&mut conn, &mutation("delete", Action::DeleteL2tpV2Tunnel { id: 2 })).unwrap().is_ok());
        assert_eq!(crate::db::next_management_id(&mut conn, "tunnel").unwrap(), 4);
    }
}
