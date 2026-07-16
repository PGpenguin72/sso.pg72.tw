-- Durable OIDC back-channel logout state.
--
-- The access-token trigger records the actual RP that completed a token
-- exchange for a live central session. Revocation transactions snapshot those
-- visits into logout_delivery before deleting the central session, so Queue is
-- only a delivery accelerator and can never be the source of truth.

ALTER TABLE "oauthClient" ADD COLUMN "backchannelLogoutUri" text
  CHECK (
    "backchannelLogoutUri" IS NULL
    OR (
      length("backchannelLogoutUri") BETWEEN 9 AND 512
      AND instr("backchannelLogoutUri", '*') = 0
      AND instr("backchannelLogoutUri", '#') = 0
      AND instr("backchannelLogoutUri", '@') = 0
      AND (
        substr("backchannelLogoutUri", 1, 8) = 'https://'
        OR "backchannelLogoutUri" GLOB 'http://localhost:*/*'
        OR "backchannelLogoutUri" GLOB 'http://127.0.0.1:*/*'
        OR "backchannelLogoutUri" GLOB 'http://[[]::1[]]:*/*'
      )
    )
  );

-- Earlier manually managed clients stored the standard key only in metadata.
-- Backfill the dedicated delivery column only when the legacy value already
-- satisfies the same canonical HTTPS constraints.
UPDATE "oauthClient"
   SET "backchannelLogoutUri" =
       json_extract("metadata", '$.backchannel_logout_uri')
 WHERE json_valid("metadata")
   AND json_type("metadata", '$.backchannel_logout_uri') = 'text'
   AND length(json_extract("metadata", '$.backchannel_logout_uri'))
       BETWEEN 9 AND 512
   AND substr(json_extract("metadata", '$.backchannel_logout_uri'), 1, 8)
       = 'https://'
   AND instr(json_extract("metadata", '$.backchannel_logout_uri'), '*') = 0
   AND instr(json_extract("metadata", '$.backchannel_logout_uri'), '#') = 0
   AND instr(json_extract("metadata", '$.backchannel_logout_uri'), '@') = 0;

-- Preserve any pre-0018 rows as migration evidence. That legacy table was
-- never consumed by the Worker and lacks both sid and endpoint snapshots, so
-- its rows cannot be safely promoted into deliverable logout work.
ALTER TABLE "logout_delivery" RENAME TO "logout_delivery_legacy_0018";

CREATE TABLE "rp_session_client" (
  "session_id" text NOT NULL
    REFERENCES "session" ("id") ON DELETE CASCADE,
  "client_id" text NOT NULL
    REFERENCES "oauthClient" ("clientId") ON DELETE CASCADE,
  "first_seen_at" date NOT NULL,
  "last_seen_at" date NOT NULL,
  PRIMARY KEY ("session_id", "client_id"),
  CHECK ("last_seen_at" >= "first_seen_at")
);

CREATE INDEX "rp_session_client_client_idx"
  ON "rp_session_client" ("client_id", "last_seen_at" DESC);

CREATE TABLE "logout_delivery" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "event_id" text NOT NULL
    REFERENCES "audit_event" ("id") ON DELETE RESTRICT,
  "session_id" text NOT NULL,
  "user_id" text NOT NULL,
  "client_id" text NOT NULL,
  "backchannel_logout_uri" text,
  "reason" text NOT NULL CHECK (
    "reason" IN (
      'sign_out',
      'self_revoke',
      'rp_initiated_logout',
      'admin_revoke',
      'suspend',
      'restrict',
      'account_delete'
    )
  ),
  "status" text NOT NULL CHECK (
    "status" IN ('pending', 'processing', 'retry', 'delivered', 'dead')
  ),
  "attempts" integer NOT NULL DEFAULT 0
    CHECK ("attempts" BETWEEN 0 AND 5),
  "replay_count" integer NOT NULL DEFAULT 0 CHECK ("replay_count" >= 0),
  "jti" text UNIQUE,
  "next_attempt_at" date,
  "lease_id" text,
  "lease_expires_at" date,
  "delivered_at" date,
  "last_error_code" text,
  "created_at" date NOT NULL,
  "updated_at" date NOT NULL,
  UNIQUE ("event_id", "session_id", "client_id"),
  CHECK (
    "backchannel_logout_uri" IS NULL
    OR (
      length("backchannel_logout_uri") BETWEEN 9 AND 512
      AND instr("backchannel_logout_uri", '*') = 0
      AND instr("backchannel_logout_uri", '#') = 0
      AND instr("backchannel_logout_uri", '@') = 0
      AND (
        substr("backchannel_logout_uri", 1, 8) = 'https://'
        OR "backchannel_logout_uri" GLOB 'http://localhost:*/*'
        OR "backchannel_logout_uri" GLOB 'http://127.0.0.1:*/*'
        OR "backchannel_logout_uri" GLOB 'http://[[]::1[]]:*/*'
      )
    )
  ),
  CHECK (
    "status" <> 'processing'
    OR ("lease_id" IS NOT NULL AND "lease_expires_at" IS NOT NULL)
  ),
  CHECK (
    ("status" IN ('pending', 'retry') AND "next_attempt_at" IS NOT NULL)
    OR ("status" NOT IN ('pending', 'retry') AND "next_attempt_at" IS NULL)
  ),
  CHECK (
    ("status" = 'delivered' AND "delivered_at" IS NOT NULL)
    OR ("status" <> 'delivered' AND "delivered_at" IS NULL)
  )
);

CREATE INDEX "logout_delivery_due_idx"
  ON "logout_delivery" ("status", "next_attempt_at", "lease_expires_at");

CREATE INDEX "logout_delivery_operator_idx"
  ON "logout_delivery" ("status", "updated_at" DESC);

CREATE TABLE "logout_delivery_attempt" (
  "id" text PRIMARY KEY NOT NULL,
  "delivery_id" integer NOT NULL
    REFERENCES "logout_delivery" ("id") ON DELETE CASCADE,
  "replay_count" integer NOT NULL CHECK ("replay_count" >= 0),
  "attempt_number" integer NOT NULL CHECK ("attempt_number" BETWEEN 1 AND 5),
  "outcome" text NOT NULL CHECK (
    "outcome" IN ('delivered', 'retry', 'dead')
  ),
  "http_status" integer CHECK ("http_status" BETWEEN 100 AND 599),
  "error_code" text,
  "attempted_at" date NOT NULL,
  UNIQUE ("delivery_id", "replay_count", "attempt_number")
);

CREATE INDEX "logout_delivery_attempt_time_idx"
  ON "logout_delivery_attempt" ("attempted_at" DESC);

-- Any user-bound access token is proof that this exact RP completed a token
-- flow for this exact live session. The trigger and token insert commit in the
-- same SQLite transaction, including refresh rotation.
CREATE TRIGGER "oauth_access_token_record_rp_visit"
AFTER INSERT ON "oauthAccessToken"
WHEN NEW."sessionId" IS NOT NULL
  AND NEW."userId" IS NOT NULL
  AND EXISTS (
    SELECT 1
      FROM "session"
     WHERE "id" = NEW."sessionId"
       AND "userId" = NEW."userId"
  )
BEGIN
  INSERT INTO "rp_session_client" (
    "session_id", "client_id", "first_seen_at", "last_seen_at"
  ) VALUES (
    NEW."sessionId", NEW."clientId", NEW."createdAt", NEW."createdAt"
  )
  ON CONFLICT ("session_id", "client_id") DO UPDATE SET
    "last_seen_at" = excluded."last_seen_at"
  WHERE excluded."last_seen_at" > "rp_session_client"."last_seen_at";
END;
