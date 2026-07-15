-- Release consumed invitations when the consuming account is deleted.
--
-- 0002 declared invitation.consumed_by_user_id with ON DELETE SET NULL, so a
-- consumed invitation row outlived its account and permanently blocked the
-- email: the admin re-invite upsert only updates rows with consumed_at IS
-- NULL, and registration requires an unconsumed invitation. Rebuild the table
-- so the consumed invitation is deleted together with the account, letting the
-- same email be re-invited and re-registered as a brand-new subject. Rows
-- already orphaned by the old SET NULL behaviour are dropped during the copy.

CREATE TABLE invitation_new (
  id TEXT PRIMARY KEY NOT NULL,
  email_normalized TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  consumed_by_user_id TEXT REFERENCES user(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (email_normalized = lower(trim(email_normalized))),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL),
  CHECK (consumed_at IS NULL OR consumed_by_user_id IS NOT NULL)
);

INSERT INTO invitation_new
  (id, email_normalized, role, created_by_user_id, consumed_by_user_id,
   expires_at, consumed_at, revoked_at, created_at)
SELECT id, email_normalized, role, created_by_user_id, consumed_by_user_id,
       expires_at, consumed_at, revoked_at, created_at
  FROM invitation
 WHERE consumed_at IS NULL
    OR consumed_by_user_id IN (SELECT id FROM user);

DROP TABLE invitation;

ALTER TABLE invitation_new RENAME TO invitation;

CREATE INDEX invitation_status_idx
  ON invitation (email_normalized, expires_at, consumed_at, revoked_at);
