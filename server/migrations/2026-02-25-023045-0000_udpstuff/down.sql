-- This file should undo anything in `up.sql`
ALTER TABLE `invites` DROP COLUMN `override_join_mesh`;






ALTER TABLE `wireguard_tunnels` DROP COLUMN `fec`;
ALTER TABLE `wireguard_tunnels` DROP COLUMN `faketcp`;

