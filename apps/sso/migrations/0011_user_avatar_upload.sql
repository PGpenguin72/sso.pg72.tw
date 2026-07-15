-- Self-hosted avatar uploads.
--
-- Users may upload their own avatar (PNG/JPEG/WebP). The bytes live in D1 so
-- the image is served from the SSO origin with no external dependency and no
-- CSP change (img-src 'self' still covers it). Only the current avatar is
-- kept per user; a new upload replaces the previous row and mints a fresh id
-- so the URL changes and stale caches are bypassed.
--
-- When user.image points at `${AUTH_BASE_URL}/api/account/avatar/<id>` the
-- avatar mode is "upload"; the same googleImage column added in 0009 keeps the
-- original Google picture so switching back stays lossless.
-- The image is stored as base64 TEXT (`data`) rather than a BLOB: it avoids
-- BLOB bind/round-trip edge cases, keeps the row self-contained, and the
-- byte_size ceiling already bounds the storage cost.
CREATE TABLE user_avatar (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  content_type TEXT NOT NULL
    CHECK (content_type IN ('image/png', 'image/jpeg', 'image/webp')),
  data TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size > 0),
  width INTEGER,
  height INTEGER,
  created_at TEXT NOT NULL
);

CREATE INDEX user_avatar_user_idx ON user_avatar (user_id, created_at DESC);
