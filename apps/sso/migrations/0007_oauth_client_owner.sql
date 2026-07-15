-- Developer-owned OAuth clients.
--
-- ownerUserId records which account created (and may manage) the client.
-- Deliberately not ON DELETE CASCADE: deleting the owner must never delete
-- the client. Application code disables owned clients and revokes their
-- tokens before the owner row is removed; the ON DELETE SET NULL foreign
-- key is a safety net that orphans the client if a delete path bypasses the
-- application layer. NULL means unowned and therefore admin-managed
-- (covers pre-existing seeded clients such as pg72-copy and pg72-diary).

ALTER TABLE oauthClient
  ADD COLUMN ownerUserId TEXT REFERENCES user(id) ON DELETE SET NULL;

CREATE INDEX oauth_client_owner_idx ON oauthClient (ownerUserId);
