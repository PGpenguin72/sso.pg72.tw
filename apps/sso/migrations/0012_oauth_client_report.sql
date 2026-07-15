-- User-submitted OAuth client abuse reports.
--
-- Any signed-in user can report a client shown on the consent screen
-- (impersonation, phishing, scope abuse, other). Reports are retained even if
-- the reporter account or the reported client is later removed, so the client
-- is not a cascading foreign key and the reporter is set to NULL on account
-- deletion. Administrators triage reports through the /api/admin/oauth-reports
-- endpoints.
CREATE TABLE oauth_client_report (
  id TEXT PRIMARY KEY NOT NULL,
  reporter_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  client_id TEXT NOT NULL,
  reason TEXT NOT NULL
    CHECK (reason IN ('impersonation', 'phishing', 'scope_abuse', 'other')),
  detail TEXT,
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'resolved')),
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  resolved_by_user_id TEXT REFERENCES user(id) ON DELETE SET NULL,
  CHECK (
    (status = 'open' AND resolved_at IS NULL)
    OR (status = 'resolved' AND resolved_at IS NOT NULL)
  )
);

CREATE INDEX oauth_client_report_status_idx
  ON oauth_client_report (status, created_at DESC, id DESC);

CREATE INDEX oauth_client_report_client_idx
  ON oauth_client_report (client_id, created_at DESC);
