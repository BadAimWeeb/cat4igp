-- Your SQL goes here
CREATE TABLE `nodes`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`name` TEXT NOT NULL,
	`auth_key` TEXT NOT NULL,
	`created_at` TIMESTAMP NOT NULL,
	`last_seen` TIMESTAMP
);

CREATE TABLE `wireguard_static_key`(
	`node_id` INTEGER NOT NULL PRIMARY KEY,
	`public_key` TEXT NOT NULL,
	`created_at` TIMESTAMP NOT NULL
);

CREATE TABLE `wireguard_tunnels`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`node_id_peer1` INTEGER NOT NULL,
	`node_id_peer2` INTEGER NOT NULL,
	`endpoint_peer1` TEXT,
	`endpoint_peer2` TEXT,
	`peer1_answered` SMALLINT NOT NULL,
	`peer2_answered` SMALLINT NOT NULL,
	`mtu` INTEGER NOT NULL,
	`endpoint_ipv6` BOOL NOT NULL,
	`created_at` TIMESTAMP NOT NULL,
	`updated_at` TIMESTAMP NOT NULL
);

CREATE TABLE `invites`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`code` TEXT NOT NULL,
	`created_at` TIMESTAMP NOT NULL,
	`expires_at` TIMESTAMP,
	`used_count` INTEGER NOT NULL,
	`max_uses` INTEGER
);

