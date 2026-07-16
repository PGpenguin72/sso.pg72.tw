CREATE TABLE oauth_transaction (
  id TEXT PRIMARY KEY NOT NULL,
  state TEXT NOT NULL UNIQUE,
  code_verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX oauth_transaction_expiry_idx
  ON oauth_transaction (expires_at, consumed_at);

CREATE TABLE rp_session (
  id TEXT PRIMARY KEY NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  subject TEXT NOT NULL,
  central_session_id TEXT,
  display_name TEXT,
  email TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE INDEX rp_session_subject_idx ON rp_session (subject);
CREATE INDEX rp_session_expiry_idx ON rp_session (expires_at);
