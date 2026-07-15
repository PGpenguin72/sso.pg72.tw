-- Four-tier platform role model: bootadmin / admin / developer / user.
--
-- The bootstrap administrator row itself cannot be converted here because
-- BOOTSTRAP_ADMIN_EMAIL lives in a Worker secret binding that SQL cannot
-- read. The Worker converts it idempotently: access control always computes
-- the effective role from the configured email, and the stored role is
-- promoted to 'bootadmin' on the next session creation.

DROP TRIGGER user_role_insert_guard;
DROP TRIGGER user_role_update_guard;

CREATE TRIGGER user_role_insert_guard
BEFORE INSERT ON user
WHEN NEW.role IS NOT NULL
  AND NEW.role NOT IN ('user', 'developer', 'admin', 'bootadmin')
BEGIN
  SELECT RAISE(ABORT, 'invalid user role');
END;

CREATE TRIGGER user_role_update_guard
BEFORE UPDATE OF role ON user
WHEN NEW.role IS NOT NULL
  AND NEW.role NOT IN ('user', 'developer', 'admin', 'bootadmin')
BEGIN
  SELECT RAISE(ABORT, 'invalid user role');
END;

-- Database-boundary protection for the bootstrap administrator. Removing
-- these guards (for example after rotating BOOTSTRAP_ADMIN_EMAIL) is a
-- deliberate break-glass migration, never a runtime code path.

CREATE TRIGGER user_bootadmin_delete_guard
BEFORE DELETE ON user
WHEN OLD.role = 'bootadmin'
BEGIN
  SELECT RAISE(ABORT, 'bootadmin account is protected');
END;

CREATE TRIGGER user_bootadmin_demote_guard
BEFORE UPDATE OF role ON user
WHEN OLD.role = 'bootadmin' AND NEW.role IS NOT 'bootadmin'
BEGIN
  SELECT RAISE(ABORT, 'bootadmin account is protected');
END;

CREATE TRIGGER user_bootadmin_suspend_guard
BEFORE UPDATE OF status ON user
WHEN OLD.role = 'bootadmin' AND NEW.status IS NOT 'active'
BEGIN
  SELECT RAISE(ABORT, 'bootadmin account is protected');
END;

-- Invitations may now grant 'developer'. 'bootadmin' stays excluded: it is
-- derived from configuration, never granted. The CHECK constraint requires a
-- table rebuild; no other table references invitation.

CREATE TABLE invitation_new (
  id TEXT PRIMARY KEY NOT NULL,
  email_normalized TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'developer', 'admin')),
  created_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  consumed_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (email_normalized = lower(trim(email_normalized))),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);

INSERT INTO invitation_new
  (id, email_normalized, role, created_by_user_id, consumed_by_user_id,
   expires_at, consumed_at, revoked_at, created_at)
SELECT id, email_normalized, role, created_by_user_id, consumed_by_user_id,
       expires_at, consumed_at, revoked_at, created_at
FROM invitation;

DROP TABLE invitation;

ALTER TABLE invitation_new RENAME TO invitation;

CREATE INDEX invitation_status_idx
  ON invitation (email_normalized, expires_at, consumed_at, revoked_at);
