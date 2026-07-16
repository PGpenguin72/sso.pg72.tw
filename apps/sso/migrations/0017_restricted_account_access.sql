-- Persistent least-privilege state for accounts created through public
-- registration. Existing, invited, and bootstrap accounts backfill to the
-- standard default. Suspension remains the separate user.status lifecycle.

ALTER TABLE "user" ADD COLUMN "accessLevel" text NOT NULL DEFAULT 'standard'
  CHECK ("accessLevel" IN ('standard', 'restricted'));

CREATE INDEX "user_access_level_idx"
  ON "user" ("accessLevel", "createdAt" DESC);

-- Restricted accounts never carry an elevated platform role. Promotion to
-- standard access and any later role grant are deliberately separate actions.
CREATE TRIGGER "user_restricted_role_insert_guard"
BEFORE INSERT ON "user"
WHEN NEW."accessLevel" = 'restricted'
  AND COALESCE(NEW."role", 'user') <> 'user'
BEGIN
  SELECT RAISE(ABORT, 'restricted account cannot hold an elevated role');
END;

CREATE TRIGGER "user_restricted_role_update_guard"
BEFORE UPDATE OF "accessLevel", "role" ON "user"
WHEN NEW."accessLevel" = 'restricted'
  AND COALESCE(NEW."role", 'user') <> 'user'
BEGIN
  SELECT RAISE(ABORT, 'restricted account cannot hold an elevated role');
END;

CREATE TRIGGER "user_bootadmin_access_guard"
BEFORE UPDATE OF "accessLevel" ON "user"
WHEN OLD."role" = 'bootadmin' AND NEW."accessLevel" <> 'standard'
BEGIN
  SELECT RAISE(ABORT, 'bootadmin account is protected');
END;

-- The first Google account is part of the public signup transaction. A
-- restricted account may not add another provider identity afterwards. The
-- legalAcceptedAt condition keeps manually inserted/restricted empty users
-- from using this narrow initial-account exception.
CREATE TRIGGER "restricted_account_provider_link_guard"
BEFORE INSERT ON "account"
WHEN EXISTS (
  SELECT 1
    FROM "user"
   WHERE "id" = NEW."userId"
     AND "accessLevel" = 'restricted'
     AND (
       NEW."providerId" <> 'google'
       OR "legalAcceptedAt" IS NULL
       OR EXISTS (SELECT 1 FROM "account" WHERE "userId" = NEW."userId")
       OR EXISTS (SELECT 1 FROM "passkey" WHERE "userId" = NEW."userId")
     )
)
BEGIN
  SELECT RAISE(ABORT, 'restricted account cannot link providers');
END;

-- Defense in depth for developer-owned clients. System clients have no owner
-- and remain controlled by the request-scoped admin guard.
CREATE TRIGGER "restricted_client_owner_insert_guard"
BEFORE INSERT ON "oauthClient"
WHEN NEW."ownerUserId" IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM "user"
     WHERE "id" = NEW."ownerUserId"
       AND "status" = 'active'
       AND "accessLevel" = 'standard'
  )
BEGIN
  SELECT RAISE(ABORT, 'client owner is not eligible');
END;

CREATE TRIGGER "restricted_client_owner_update_guard"
BEFORE UPDATE OF "ownerUserId" ON "oauthClient"
WHEN NEW."ownerUserId" IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM "user"
     WHERE "id" = NEW."ownerUserId"
       AND "status" = 'active'
       AND "accessLevel" = 'standard'
  )
BEGIN
  SELECT RAISE(ABORT, 'client owner is not eligible');
END;
