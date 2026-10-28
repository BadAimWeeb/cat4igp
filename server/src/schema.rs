// @generated automatically by Diesel CLI.

diesel::table! {
    invites (id) {
        id -> Integer,
        code -> Text,
        created_at -> Timestamp,
        expires_at -> Nullable<Timestamp>,
        used_count -> Integer,
        max_uses -> Nullable<Integer>,
        override_join_mesh -> Nullable<Integer>,
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
        auto_wireguard_fec -> Bool,
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
    node_control_identities (node_id) {
        node_id -> Integer,
        peer_id -> Text,
        signing_key -> Text,
        encryption_key -> Text,
        topology_revision -> BigInt,
        created_at -> Timestamp,
        updated_at -> Timestamp,
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
        fec -> Bool,
        faketcp -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    administrator (id) {
        id -> Integer,
        username -> Text,
        password_hash -> Text,
    }
}

diesel::table! {
    administrator_results (request_id) {
        request_id -> Text,
        fingerprint -> Text,
        result -> Text,
    }
}

diesel::table! {
    operator_invite_results (request_id) {
        request_id -> Text,
        fingerprint -> Text,
        result -> Text,
    }
}

diesel::table! {
    control_enrollment_results (peer_id) {
        peer_id -> Text,
        request_id -> Text,
        fingerprint -> Text,
        result -> Text,
    }
}

diesel::table! {
    control_answer_results (node_id, request_id) {
        node_id -> Integer,
        request_id -> Text,
        fingerprint -> Text,
        result -> Text,
        expires_at -> Timestamp,
    }
}

diesel::table! {
    node_revocations (peer_id) {
        peer_id -> Text,
        node_id -> Integer,
        revoked_at -> Timestamp,
    }
}

diesel::table! {
    tunnel_intents (tunnel_id, kind, mesh_id) {
        tunnel_id -> Integer,
        kind -> Text,
        mesh_id -> Integer,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    administrator,
    administrator_results,
    operator_invite_results,
    control_enrollment_results,
    control_answer_results,
    node_revocations,
    tunnel_intents,
    invites,
    mesh_group_memberships,
    mesh_groups,
    node_control_identities,
    nodes,
    settings,
    wireguard_static_key,
    wireguard_tunnels,
);
