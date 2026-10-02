ALTER TABLE `wireguard_tunnels` ADD COLUMN `fec` BOOL NOT NULL DEFAULT 0;
ALTER TABLE `wireguard_tunnels` ADD COLUMN `faketcp` BOOL NOT NULL DEFAULT 0;

