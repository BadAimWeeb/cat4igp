// @generated automatically by Diesel CLI.

diesel::table! {
    invites (id) {
        id -> Integer,
        code -> Text,
        created_at -> Timestamp,
        expires_at -> Nullable<Timestamp>,
        used_count -> Integer,
        max_uses -> Nullable<Integer>,
    }
}

diesel::table! {
    mesh_group_memberships (id) {
        id -> Integer,
        mesh_group_id -> Integer,
        node_id -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    mesh_groups (id) {
        id -> Integer,
        name -> Text,
        auto_wireguard -> Bool,
        auto_wireguard_mtu -> Integer,
        created_at -> Timestamp,
    }
}

diesel::table! {
    nodes (id) {
        id -> Integer,
        name -> Text,
        auth_key -> Text,
        created_at -> Timestamp,
        last_seen -> Nullable<Timestamp>,
    }
}

diesel::table! {
    settings (id) {
        id -> Integer,
        key -> Text,
        value -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    wireguard_static_key (node_id) {
        node_id -> Integer,
        public_key -> Text,
        created_at -> Timestamp,
    }
}

diesel::table! {
    wireguard_tunnels (id) {
        id -> Integer,
        node_id_peer1 -> Integer,
        node_id_peer2 -> Integer,
        endpoint_peer1 -> Nullable<Text>,
        endpoint_peer2 -> Nullable<Text>,
        peer1_answered -> SmallInt,
        peer2_answered -> SmallInt,
        mtu -> Integer,
        endpoint_ipv6 -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    invites,
    mesh_group_memberships,
    mesh_groups,
    nodes,
    settings,
    wireguard_static_key,
    wireguard_tunnels,
);
