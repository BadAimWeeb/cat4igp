-- Validate without rewriting legacy rows; Diesel runs this migration in a transaction.
CREATE TEMP TABLE l2tpv3_cookie_validation (valid INTEGER NOT NULL CHECK(valid = 1));
INSERT INTO l2tpv3_cookie_validation
SELECT 0 FROM l2tpv3_tunnels
WHERE typeof(cookie_peer1) != 'text' OR length(cookie_peer1) != 16 OR length(CAST(cookie_peer1 AS BLOB)) != 16 OR cookie_peer1 GLOB '*[^0-9a-f]*'
  OR typeof(cookie_peer2) != 'text' OR length(cookie_peer2) != 16 OR length(CAST(cookie_peer2 AS BLOB)) != 16 OR cookie_peer2 GLOB '*[^0-9a-f]*';
DROP TABLE l2tpv3_cookie_validation;

CREATE TRIGGER l2tpv3_cookie_insert BEFORE INSERT ON l2tpv3_tunnels
WHEN typeof(NEW.cookie_peer1) != 'text' OR length(NEW.cookie_peer1) != 16 OR length(CAST(NEW.cookie_peer1 AS BLOB)) != 16 OR NEW.cookie_peer1 GLOB '*[^0-9a-f]*'
  OR typeof(NEW.cookie_peer2) != 'text' OR length(NEW.cookie_peer2) != 16 OR length(CAST(NEW.cookie_peer2 AS BLOB)) != 16 OR NEW.cookie_peer2 GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT, 'invalid l2tpv3 cookie'); END;

CREATE TRIGGER l2tpv3_cookie_update BEFORE UPDATE ON l2tpv3_tunnels
WHEN typeof(NEW.cookie_peer1) != 'text' OR length(NEW.cookie_peer1) != 16 OR length(CAST(NEW.cookie_peer1 AS BLOB)) != 16 OR NEW.cookie_peer1 GLOB '*[^0-9a-f]*'
  OR typeof(NEW.cookie_peer2) != 'text' OR length(NEW.cookie_peer2) != 16 OR length(CAST(NEW.cookie_peer2 AS BLOB)) != 16 OR NEW.cookie_peer2 GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT, 'invalid l2tpv3 cookie'); END;