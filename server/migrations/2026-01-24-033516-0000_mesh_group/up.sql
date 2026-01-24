-- Your SQL goes here




CREATE TABLE `settings`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`key` TEXT NOT NULL,
	`value` TEXT NOT NULL,
	`created_at` TIMESTAMP NOT NULL,
	`updated_at` TIMESTAMP NOT NULL
);

CREATE TABLE `mesh_groups`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`name` TEXT NOT NULL,
	`auto_wireguard` BOOL NOT NULL,
	`auto_wireguard_mtu` INTEGER NOT NULL,
	`created_at` TIMESTAMP NOT NULL
);

CREATE TABLE `mesh_group_memberships`(
	`id` INTEGER NOT NULL PRIMARY KEY,
	`mesh_group_id` INTEGER NOT NULL,
	`node_id` INTEGER NOT NULL,
	`created_at` TIMESTAMP NOT NULL
);

