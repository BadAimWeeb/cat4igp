CREATE TABLE l2tpv2_tunnels_new (
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
    mtu INTEGER NOT NULL CHECK(mtu BETWEEN 1280 AND 65000 AND (wireguard_tunnel_id IS NOT NULL OR mtu <= 1500)),
    wireguard_tunnel_id INTEGER CHECK(wireguard_tunnel_id > 0)
);
INSERT INTO l2tpv2_tunnels_new SELECT *, NULL FROM l2tpv2_tunnels;
DROP TABLE l2tpv2_tunnels;
ALTER TABLE l2tpv2_tunnels_new RENAME TO l2tpv2_tunnels;
