CREATE TABLE invitation (
  id TEXT PRIMARY KEY NOT NULL,
  email_normalized TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  consumed_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (email_normalized = lower(trim(email_normalized))),
  CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX invitation_status_idx
  ON invitation (email_normalized, expires_at, consumed_at, revoked_at);

CREATE TABLE audit_event (
  id TEXT PRIMARY KEY NOT NULL,
  event_type TEXT NOT NULL,
  actor_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  subject_id TEXT,
  client_id TEXT,
  session_id TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
  ip_hash TEXT,
  user_agent_hash TEXT,
  metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
  occurred_at TEXT NOT NULL
);

CREATE INDEX audit_event_subject_time_idx
  ON audit_event (subject_id, occurred_at DESC);

CREATE INDEX audit_event_type_time_idx
  ON audit_event (event_type, occurred_at DESC);

CREATE TABLE security_event_delivery (
  event_id TEXT PRIMARY KEY NOT NULL,
  delivered_at TEXT NOT NULL
);

CREATE TABLE logout_delivery (
  id TEXT PRIMARY KEY NOT NULL,
  event_id TEXT NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauthClient(clientId) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  delivered_at TEXT,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (event_id, client_id)
);

CREATE INDEX logout_delivery_retry_idx
  ON logout_delivery (status, next_attempt_at);

CREATE TRIGGER user_role_insert_guard
BEFORE INSERT ON user
WHEN NEW.role IS NOT NULL AND NEW.role NOT IN ('user', 'admin')
BEGIN
  SELECT RAISE(ABORT, 'invalid user role');
END;

CREATE TRIGGER user_role_update_guard
BEFORE UPDATE OF role ON user
WHEN NEW.role IS NOT NULL AND NEW.role NOT IN ('user', 'admin')
BEGIN
  SELECT RAISE(ABORT, 'invalid user role');
END;

CREATE TRIGGER user_status_insert_guard
BEFORE INSERT ON user
WHEN NEW.status IS NOT NULL AND NEW.status NOT IN ('active', 'suspended')
BEGIN
  SELECT RAISE(ABORT, 'invalid user status');
END;

CREATE TRIGGER user_status_update_guard
BEFORE UPDATE OF status ON user
WHEN NEW.status IS NOT NULL AND NEW.status NOT IN ('active', 'suspended')
BEGIN
  SELECT RAISE(ABORT, 'invalid user status');
END;
