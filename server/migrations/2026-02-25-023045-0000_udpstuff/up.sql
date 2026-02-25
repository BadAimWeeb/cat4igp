-- Your SQL goes here
ALTER TABLE `invites` ADD COLUMN `override_join_mesh` INTEGER;






ALTER TABLE `wireguard_tunnels` ADD COLUMN `fec` BOOL NOT NULL;
ALTER TABLE `wireguard_tunnels` ADD COLUMN `faketcp` BOOL NOT NULL;

