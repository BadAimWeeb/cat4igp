-- Inactive static L2TPv3/Ethernet profile. No API creates or activates these rows.
CREATE TABLE l2tpv3_tunnels (
    id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 2147483647),
    construction TEXT NOT NULL CHECK(construction = 'static'),
    node_id_peer1 INTEGER NOT NULL CHECK(node_id_peer1 BETWEEN 1 AND 2147483647),
    node_id_peer2 INTEGER NOT NULL CHECK(node_id_peer2 BETWEEN 1 AND 2147483647 AND node_id_peer2 != node_id_peer1),
    endpoint_peer1 TEXT NOT NULL CHECK(length(endpoint_peer1) BETWEEN 1 AND 45),
    endpoint_peer2 TEXT NOT NULL CHECK(length(endpoint_peer2) BETWEEN 1 AND 45),
    udp_port_peer1 INTEGER NOT NULL CHECK(udp_port_peer1 BETWEEN 1 AND 65535),
    udp_port_peer2 INTEGER NOT NULL CHECK(udp_port_peer2 BETWEEN 1 AND 65535),
    session_id_peer1 INTEGER NOT NULL CHECK(session_id_peer1 BETWEEN 1 AND 4294967295),
    session_id_peer2 INTEGER NOT NULL CHECK(session_id_peer2 BETWEEN 1 AND 4294967295),
    cookie_peer1 TEXT NOT NULL CHECK(length(cookie_peer1) = 16 AND cookie_peer1 NOT GLOB '*[^0-9a-f]*'),
    cookie_peer2 TEXT NOT NULL CHECK(length(cookie_peer2) = 16 AND cookie_peer2 NOT GLOB '*[^0-9a-f]*'),
    security_mode TEXT NOT NULL CHECK(security_mode IN ('pure', 'wireguard')),
    wireguard_tunnel_id INTEGER,
    mtu INTEGER NOT NULL CHECK(mtu BETWEEN 576 AND 65535),
        CHECK((security_mode = 'pure' AND wireguard_tunnel_id IS NULL) OR
            (security_mode = 'wireguard' AND wireguard_tunnel_id IS NOT NULL AND wireguard_tunnel_id BETWEEN 1 AND 2147483647))
);