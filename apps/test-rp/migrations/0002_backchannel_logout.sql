-- RP sessions without a central sid predate the enforced PGID sid contract and
-- cannot participate in global logout. Remove those invalid local sessions,
-- then make the invariant structural for all future writes.

DELETE FROM "rp_session" WHERE "central_session_id" IS NULL;

CREATE TABLE "rp_session_0018" (
  "id" text PRIMARY KEY NOT NULL,
  "token_hash" text NOT NULL UNIQUE,
  "subject" text NOT NULL,
  "central_session_id" text NOT NULL,
  "display_name" text,
  "email" text,
  "expires_at" text NOT NULL,
  "created_at" text NOT NULL,
  "last_seen_at" text NOT NULL
);

INSERT INTO "rp_session_0018" (
  "id", "token_hash", "subject", "central_session_id", "display_name",
  "email", "expires_at", "created_at", "last_seen_at"
)
SELECT
  "id", "token_hash", "subject", "central_session_id", "display_name",
  "email", "expires_at", "created_at", "last_seen_at"
FROM "rp_session";

DROP TABLE "rp_session";
ALTER TABLE "rp_session_0018" RENAME TO "rp_session";

CREATE INDEX "rp_session_subject_idx" ON "rp_session" ("subject");
CREATE INDEX "rp_session_expiry_idx" ON "rp_session" ("expires_at");
CREATE INDEX "rp_session_central_sid_idx"
  ON "rp_session" ("central_session_id");

CREATE TABLE "backchannel_logout_receipt" (
  "jti" text PRIMARY KEY NOT NULL,
  "central_session_id" text NOT NULL,
  "issuer" text NOT NULL,
  "received_at" text NOT NULL
);

CREATE INDEX "backchannel_logout_receipt_time_idx"
  ON "backchannel_logout_receipt" ("received_at" DESC);
