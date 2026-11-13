CREATE TEMP TABLE l2tpv2_downgrade_guard (ok INTEGER CHECK(ok = 1));
INSERT INTO l2tpv2_downgrade_guard SELECT CASE WHEN EXISTS (SELECT 1 FROM l2tpv2_tunnels WHERE wireguard_tunnel_id IS NOT NULL OR mtu > 1500) THEN 0 ELSE 1 END;
DROP TABLE l2tpv2_downgrade_guard;
CREATE TABLE l2tpv2_tunnels_old (
    id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 2147483647),
    node_id_peer1 INTEGER NOT NULL CHECK(node_id_peer1 > 0),
    node_id_peer2 INTEGER NOT NULL CHECK(node_id_peer2 > 0 AND node_id_peer1 != node_id_peer2),
    endpoint_peer1 TEXT NOT NULL,
    endpoint_peer2 TEXT NOT NULL,
    udp_port_peer1 INTEGER NOT NULL CHECK(udp_port_peer1 BETWEEN 1 AND 65535),
    udp_port_peer2 INTEGER NOT NULL CHECK(udp_port_peer2 BETWEEN 1 AND 65535),
    address_peer1 TEXT NOT NULL,
    address_peer2 TEXT NOT NULL,
    secret TEXT NOT NULL,
    mtu INTEGER NOT NULL CHECK(mtu BETWEEN 1280 AND 1500)
);
INSERT INTO l2tpv2_tunnels_old SELECT id,node_id_peer1,node_id_peer2,endpoint_peer1,endpoint_peer2,udp_port_peer1,udp_port_peer2,address_peer1,address_peer2,secret,mtu FROM l2tpv2_tunnels;
DROP TABLE l2tpv2_tunnels;
ALTER TABLE l2tpv2_tunnels_old RENAME TO l2tpv2_tunnels;
