-- Immutable audit archive source ledger and encrypted-batch state.
--
-- This migration is deliberately schema-only. It does not read a KEK, create
-- an archive key sentinel, bind R2 or Queue resources, schedule Cron work,
-- delete retained objects, or make encrypted archive continuity operational.
-- D1 remains authoritative; future Queue messages may carry only an opaque
-- batch key and dispatch generation.

CREATE TABLE "audit_archive_source" (
  "sequence" integer PRIMARY KEY AUTOINCREMENT CHECK (
    typeof("sequence") = 'integer'
    AND "sequence" BETWEEN 1 AND 9007199254740991
  ),
  "event_id" text NOT NULL UNIQUE
    REFERENCES "audit_event" ("id") ON DELETE CASCADE
);

-- Conflict-aware INSERT guards are required in addition to UPDATE/DELETE
-- guards: SQLite's INSERT OR REPLACE can implicitly delete a conflicting row
-- without firing its delete trigger when recursive_triggers is disabled.
CREATE TRIGGER "audit_archive_source_insert_guard"
BEFORE INSERT ON "audit_archive_source"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_source"
   WHERE "sequence" = NEW."sequence" OR "event_id" = NEW."event_id"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive source is immutable');
END;

CREATE TRIGGER "audit_archive_source_update_guard"
BEFORE UPDATE ON "audit_archive_source"
BEGIN
  SELECT RAISE(ABORT, 'audit archive source is immutable');
END;

-- The only valid source-row deletion is the FK cascade from a parent audit
-- event that has already disappeared. This preserves the Passkey step-up
-- compensation path, which may delete its just-inserted success audit.
CREATE TRIGGER "audit_archive_source_delete_guard"
BEFORE DELETE ON "audit_archive_source"
WHEN EXISTS (
  SELECT 1 FROM "audit_event" WHERE "id" = OLD."event_id"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive source is immutable');
END;

-- Install capture before backfill so every audit committed concurrently with
-- migration execution is represented. Existing rows receive deterministic
-- sequence numbers in occurred_at/id order.
CREATE TRIGGER "audit_event_archive_source_insert"
AFTER INSERT ON "audit_event"
BEGIN
  INSERT INTO "audit_archive_source" ("event_id") VALUES (NEW."id");
END;

INSERT INTO "audit_archive_source" ("event_id")
SELECT "id" FROM "audit_event" ORDER BY "occurred_at", "id";

CREATE TABLE "audit_archive_key_sentinel" (
  "key_version" text PRIMARY KEY NOT NULL CHECK (
    length("key_version") BETWEEN 2 AND 7
    AND substr("key_version", 1, 1) = 'v'
    AND substr("key_version", 2, 1) BETWEEN '1' AND '9'
    AND substr("key_version", 2) NOT GLOB '*[^0-9]*'
  ),
  "domain" text NOT NULL CHECK (
    "domain" = 'pgid.audit_archive_kek_fingerprint.v1'
  ),
  "fingerprint_ref" text NOT NULL UNIQUE CHECK (
    length("fingerprint_ref") = 43
    AND "fingerprint_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("fingerprint_ref", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "fingerprint_hash_version" integer NOT NULL CHECK (
    typeof("fingerprint_hash_version") = 'integer'
    AND "fingerprint_hash_version" = 1
  ),
  "created_at" date NOT NULL CHECK (
    length("created_at") = 24
    AND "created_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("created_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  )
);

CREATE TRIGGER "audit_archive_key_sentinel_insert_guard"
BEFORE INSERT ON "audit_archive_key_sentinel"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_key_sentinel"
   WHERE "key_version" = NEW."key_version"
      OR "fingerprint_ref" = NEW."fingerprint_ref"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive key sentinel is immutable');
END;

CREATE TRIGGER "audit_archive_key_sentinel_update_guard"
BEFORE UPDATE ON "audit_archive_key_sentinel"
BEGIN
  SELECT RAISE(ABORT, 'audit archive key sentinel is immutable');
END;

CREATE TRIGGER "audit_archive_key_sentinel_delete_guard"
BEFORE DELETE ON "audit_archive_key_sentinel"
BEGIN
  SELECT RAISE(ABORT, 'audit archive key sentinel is immutable');
END;

CREATE TABLE "audit_archive_checkpoint" (
  "id" integer PRIMARY KEY NOT NULL CHECK (
    typeof("id") = 'integer' AND "id" = 1
  ),
  "revision" integer NOT NULL CHECK (
    typeof("revision") = 'integer'
    AND "revision" BETWEEN 0 AND 9007199254740990
  ),
  "last_sequence" integer NOT NULL CHECK (
    typeof("last_sequence") = 'integer'
    AND "last_sequence" BETWEEN 0 AND 9007199254740991
  ),
  "last_batch_key" text UNIQUE CHECK (
    "last_batch_key" IS NULL OR (
      length("last_batch_key") = 43
      AND "last_batch_key" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("last_batch_key", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "last_archived_at" date CHECK (
    "last_archived_at" IS NULL OR (
      length("last_archived_at") = 24
      AND "last_archived_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("last_archived_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_archived_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "last_archived_at", '+0 seconds'
      )
        = "last_archived_at"
    )
  ),
  CHECK (
    ("revision" = 0 AND "last_sequence" = 0
      AND "last_batch_key" IS NULL AND "last_archived_at" IS NULL)
    OR ("revision" > 0 AND "last_sequence" > 0
      AND "last_batch_key" IS NOT NULL AND "last_archived_at" IS NOT NULL)
  )
);

INSERT INTO "audit_archive_checkpoint" (
  "id", "revision", "last_sequence", "last_batch_key", "last_archived_at"
) VALUES (1, 0, 0, NULL, NULL);

CREATE TRIGGER "audit_archive_checkpoint_insert_guard"
BEFORE INSERT ON "audit_archive_checkpoint"
BEGIN
  SELECT RAISE(ABORT, 'audit archive checkpoint is immutable');
END;

CREATE TRIGGER "audit_archive_checkpoint_delete_guard"
BEFORE DELETE ON "audit_archive_checkpoint"
BEGIN
  SELECT RAISE(ABORT, 'audit archive checkpoint is immutable');
END;

CREATE TABLE "audit_archive_batch" (
  "batch_key" text PRIMARY KEY NOT NULL CHECK (
    length("batch_key") = 43
    AND "batch_key" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("batch_key", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "batch_generation" integer NOT NULL CHECK (
    typeof("batch_generation") = 'integer'
    AND "batch_generation" BETWEEN 1 AND 9007199254740991
  ),
  "checkpoint_revision" integer NOT NULL UNIQUE CHECK (
    typeof("checkpoint_revision") = 'integer'
    AND "checkpoint_revision" BETWEEN 0 AND 9007199254740990
  ),
  "checkpoint_from_sequence" integer NOT NULL CHECK (
    typeof("checkpoint_from_sequence") = 'integer'
    AND "checkpoint_from_sequence" BETWEEN 0 AND 9007199254740991
  ),
  "schema_version" integer NOT NULL CHECK (
    typeof("schema_version") = 'integer' AND "schema_version" = 1
  ),
  "contract" text NOT NULL CHECK (
    "contract" = 'pgid-audit-archive-v1'
  ),
  "manifest_json" text NOT NULL CHECK (
    json_valid("manifest_json") AND json_type("manifest_json") = 'object'
  ),
  "first_sequence" integer NOT NULL CHECK (
    typeof("first_sequence") = 'integer'
    AND "first_sequence" BETWEEN 1 AND 9007199254740991
  ),
  "last_sequence" integer NOT NULL CHECK (
    typeof("last_sequence") = 'integer'
    AND "last_sequence" BETWEEN 1 AND 9007199254740991
  ),
  "event_count" integer NOT NULL CHECK (
    typeof("event_count") = 'integer' AND "event_count" BETWEEN 1 AND 100
  ),
  "plaintext_bytes" integer NOT NULL CHECK (
    typeof("plaintext_bytes") = 'integer'
    AND "plaintext_bytes" BETWEEN 1 AND 393216
  ),
  "plaintext_sha256" text NOT NULL CHECK (
    length("plaintext_sha256") = 64
    AND "plaintext_sha256" NOT GLOB '*[^a-f0-9]*'
  ),
  "key_version" text NOT NULL
    REFERENCES "audit_archive_key_sentinel" ("key_version")
    ON DELETE RESTRICT,
  "content_type" text NOT NULL CHECK (
    "content_type" = 'application/vnd.pg72.pgid-audit-archive+json'
  ),
  "object_key" text NOT NULL UNIQUE,
  "object_bytes" integer NOT NULL CHECK (
    typeof("object_bytes") = 'integer'
    AND "object_bytes" BETWEEN 1 AND 524288
  ),
  "object_sha256" text NOT NULL UNIQUE CHECK (
    length("object_sha256") = 64
    AND "object_sha256" NOT GLOB '*[^a-f0-9]*'
  ),
  "encrypted_envelope" blob,
  "status" text NOT NULL CHECK (
    "status" IN ('pending', 'processing', 'retry', 'archived', 'dead', 'corrupt')
  ),
  "dispatch_generation" integer NOT NULL CHECK (
    typeof("dispatch_generation") = 'integer'
    AND "dispatch_generation" BETWEEN 1 AND 1000000
  ),
  "attempts" integer NOT NULL CHECK (
    typeof("attempts") = 'integer' AND "attempts" BETWEEN 0 AND 5
  ),
  "next_attempt_at" date CHECK (
    "next_attempt_at" IS NULL OR (
      length("next_attempt_at") = 24
      AND "next_attempt_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("next_attempt_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      )
        = "next_attempt_at"
    )
  ),
  "lease_id" text UNIQUE CHECK (
    "lease_id" IS NULL OR (
      length("lease_id") = 43
      AND "lease_id" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("lease_id", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "lease_expires_at" date CHECK (
    "lease_expires_at" IS NULL OR (
      length("lease_expires_at") = 24
      AND "lease_expires_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("lease_expires_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "lease_expires_at", '+0 seconds'
      )
        = "lease_expires_at"
    )
  ),
  "r2_version" text CHECK (
    "r2_version" IS NULL OR (
      length("r2_version") BETWEEN 1 AND 256
      AND instr("r2_version", char(0)) = 0
      AND instr("r2_version", char(10)) = 0
      AND instr("r2_version", char(13)) = 0
    )
  ),
  "r2_etag" text CHECK (
    "r2_etag" IS NULL OR (
      length("r2_etag") BETWEEN 1 AND 256
      AND instr("r2_etag", char(0)) = 0
      AND instr("r2_etag", char(10)) = 0
      AND instr("r2_etag", char(13)) = 0
    )
  ),
  "r2_readback_sha256" text CHECK (
    "r2_readback_sha256" IS NULL OR (
      length("r2_readback_sha256") = 64
      AND "r2_readback_sha256" NOT GLOB '*[^a-f0-9]*'
    )
  ),
  "r2_readback_at" date CHECK (
    "r2_readback_at" IS NULL OR (
      length("r2_readback_at") = 24
      AND "r2_readback_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("r2_readback_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      )
        = "r2_readback_at"
    )
  ),
  "archived_at" date CHECK (
    "archived_at" IS NULL OR (
      length("archived_at") = 24
      AND "archived_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("archived_at") IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "archived_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "archived_at", '+0 seconds')
        = "archived_at"
    )
  ),
  "envelope_gc_at" date CHECK (
    "envelope_gc_at" IS NULL OR (
      length("envelope_gc_at") = 24
      AND "envelope_gc_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("envelope_gc_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "envelope_gc_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "envelope_gc_at", '+0 seconds'
      )
        = "envelope_gc_at"
    )
  ),
  "last_error_code" text CHECK (
    "last_error_code" IS NULL OR "last_error_code" IN (
      'queue_unavailable', 'r2_transient', 'r2_object_conflict',
      'r2_readback_mismatch', 'crypto_integrity', 'key_unavailable',
      'lease_expired', 'internal_error'
    )
  ),
  "manual_replay_audit_id" text UNIQUE
    REFERENCES "audit_event" ("id") ON DELETE RESTRICT,
  "created_at" date NOT NULL CHECK (
    length("created_at") = 24
    AND "created_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("created_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "created_at", '+0 seconds')
      = "created_at"
  ),
  "updated_at" date NOT NULL CHECK (
    length("updated_at") = 24
    AND "updated_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("updated_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "updated_at", '+0 seconds')
      = "updated_at"
  ),
  CHECK ("batch_generation" = "checkpoint_revision" + 1),
  CHECK ("checkpoint_from_sequence" < "first_sequence"),
  CHECK ("last_sequence" >= "first_sequence"),
  CHECK ("updated_at" >= "created_at"),
  CHECK (
    "object_key" = 'audit/v1/'
      || printf('%016d', "first_sequence") || '-'
      || printf('%016d', "last_sequence") || '/'
      || "object_sha256" || '.pgid-audit'
  ),
  CHECK (
    "manifest_json" = json_object(
      'batchGeneration', "batch_generation",
      'checkpointFromSequence', "checkpoint_from_sequence",
      'contentType', "content_type",
      'contract', "contract",
      'createdAt', "created_at",
      'eventCount', "event_count",
      'firstSequence', "first_sequence",
      'keyVersion', "key_version",
      'lastSequence', "last_sequence",
      'objectBytes', "object_bytes",
      'objectKey', "object_key",
      'objectSha256', "object_sha256",
      'plaintextSha256', "plaintext_sha256",
      'schemaVersion', "schema_version"
    )
  ),
  CHECK (
    ("status" = 'pending' AND "attempts" = 0)
    OR ("status" = 'processing' AND "attempts" BETWEEN 1 AND 5)
    OR ("status" = 'retry' AND "attempts" BETWEEN 1 AND 4)
    OR ("status" = 'archived' AND "attempts" BETWEEN 1 AND 5)
    OR ("status" = 'dead' AND "attempts" = 5)
    OR ("status" = 'corrupt' AND "attempts" BETWEEN 1 AND 5)
  ),
  CHECK (
    ("status" IN ('pending', 'retry') AND "next_attempt_at" IS NOT NULL)
    OR ("status" NOT IN ('pending', 'retry') AND "next_attempt_at" IS NULL)
  ),
  CHECK (
    ("status" = 'processing'
      AND "lease_id" IS NOT NULL AND "lease_expires_at" IS NOT NULL)
    OR ("status" <> 'processing'
      AND "lease_id" IS NULL AND "lease_expires_at" IS NULL)
  ),
  CHECK (
    ("r2_version" IS NULL AND "r2_etag" IS NULL
      AND "r2_readback_sha256" IS NULL AND "r2_readback_at" IS NULL)
    OR ("r2_version" IS NOT NULL AND "r2_etag" IS NOT NULL
      AND "r2_readback_sha256" IS NOT NULL AND "r2_readback_at" IS NOT NULL)
  ),
  CHECK (
    ("status" = 'archived'
      AND "r2_version" IS NOT NULL
      AND "r2_readback_sha256" = "object_sha256"
      AND "r2_readback_at" = "archived_at"
      AND "archived_at" = "envelope_gc_at"
      AND "encrypted_envelope" IS NULL
      AND "last_error_code" IS NULL)
    OR ("status" <> 'archived'
      AND "r2_version" IS NULL
      AND "archived_at" IS NULL
      AND "envelope_gc_at" IS NULL
      AND "encrypted_envelope" IS NOT NULL
      AND typeof("encrypted_envelope") = 'blob'
      AND length("encrypted_envelope") = "object_bytes")
  ),
  CHECK (
    ("status" IN ('retry', 'dead', 'corrupt')
      AND "last_error_code" IS NOT NULL)
    OR ("status" NOT IN ('retry', 'dead', 'corrupt')
      AND "last_error_code" IS NULL)
  ),
  CHECK (
    "status" <> 'corrupt' OR "last_error_code" IN (
      'r2_object_conflict', 'r2_readback_mismatch', 'crypto_integrity'
    )
  ),
  CHECK (
    "status" = 'corrupt' OR "last_error_code" IS NULL
      OR "last_error_code" NOT IN (
        'r2_object_conflict', 'r2_readback_mismatch', 'crypto_integrity'
      )
  )
);

CREATE TABLE "audit_archive_batch_item" (
  "batch_key" text NOT NULL,
  "ordinal" integer NOT NULL CHECK (
    typeof("ordinal") = 'integer' AND "ordinal" BETWEEN 1 AND 100
  ),
  "source_sequence" integer NOT NULL UNIQUE CHECK (
    typeof("source_sequence") = 'integer'
    AND "source_sequence" BETWEEN 1 AND 9007199254740991
  ),
  "event_id" text NOT NULL UNIQUE CHECK (
    length("event_id") BETWEEN 1 AND 256
    AND "event_id" NOT GLOB '*[^A-Za-z0-9._:-]*'
  ),
  "event_type" text NOT NULL CHECK (
    length("event_type") BETWEEN 1 AND 128
    AND "event_type" NOT GLOB '*[^a-z0-9._-]*'
    AND substr("event_type", 1, 1) GLOB '[a-z0-9]'
    AND substr("event_type", -1) GLOB '[a-z0-9]'
    AND instr("event_type", '..') = 0
    AND instr("event_type", '._') = 0
    AND instr("event_type", '.-') = 0
    AND instr("event_type", '_.') = 0
    AND instr("event_type", '__') = 0
    AND instr("event_type", '_-') = 0
    AND instr("event_type", '-.') = 0
    AND instr("event_type", '-_') = 0
    AND instr("event_type", '--') = 0
  ),
  "actor_user_id" text CHECK (
    "actor_user_id" IS NULL OR (
      length("actor_user_id") BETWEEN 1 AND 256
      AND "actor_user_id" NOT GLOB '*[^A-Za-z0-9._:-]*'
    )
  ),
  "actor_ref" text CHECK (
    "actor_ref" IS NULL OR (
      length("actor_ref") = 43
      AND "actor_ref" NOT GLOB '*[^A-Za-z0-9_-]*'
      AND substr("actor_ref", -1) IN (
        'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
        'g', 'k', 'o', 's', 'w', '0', '4', '8'
      )
    )
  ),
  "actor_ref_hash_version" integer CHECK (
    "actor_ref_hash_version" IS NULL OR (
      typeof("actor_ref_hash_version") = 'integer'
      AND "actor_ref_hash_version" = 1
    )
  ),
  "subject_id" text CHECK (
    "subject_id" IS NULL OR (
      length("subject_id") BETWEEN 1 AND 256
      AND "subject_id" NOT GLOB '*[^A-Za-z0-9._:-]*'
    )
  ),
  "client_id" text CHECK (
    "client_id" IS NULL OR (
      length("client_id") BETWEEN 1 AND 256
      AND "client_id" NOT GLOB '*[^A-Za-z0-9._:-]*'
    )
  ),
  "session_id" text CHECK (
    "session_id" IS NULL OR (
      length("session_id") BETWEEN 1 AND 256
      AND "session_id" NOT GLOB '*[^A-Za-z0-9._:-]*'
    )
  ),
  "outcome" text NOT NULL CHECK (
    "outcome" IN ('success', 'denied', 'failure')
  ),
  "ip_hash" text CHECK (
    "ip_hash" IS NULL OR (
      length("ip_hash") BETWEEN 16 AND 128
      AND "ip_hash" NOT GLOB '*[^A-Za-z0-9_-]*'
    )
  ),
  "user_agent_hash" text CHECK (
    "user_agent_hash" IS NULL OR (
      length("user_agent_hash") BETWEEN 16 AND 128
      AND "user_agent_hash" NOT GLOB '*[^A-Za-z0-9_-]*'
    )
  ),
  "metadata_json" text CHECK (
    "metadata_json" IS NULL OR (
      length(CAST("metadata_json" AS blob)) <= 16384
      AND json_valid("metadata_json")
      AND json_type("metadata_json") = 'object'
    )
  ),
  "occurred_at" date NOT NULL CHECK (
    length("occurred_at") = 24
    AND "occurred_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("occurred_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "occurred_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "occurred_at", '+0 seconds')
      = "occurred_at"
  ),
  "canonical_record_json" text NOT NULL CHECK (
    json_valid("canonical_record_json")
    AND json_type("canonical_record_json") = 'object'
  ),
  "canonical_record_bytes" integer NOT NULL CHECK (
    typeof("canonical_record_bytes") = 'integer'
    AND "canonical_record_bytes" BETWEEN 1 AND 65536
  ),
  PRIMARY KEY ("batch_key", "ordinal"),
  FOREIGN KEY ("batch_key") REFERENCES "audit_archive_batch" ("batch_key")
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  CHECK (
    ("actor_ref" IS NULL AND "actor_ref_hash_version" IS NULL)
    OR ("actor_ref" IS NOT NULL AND "actor_ref_hash_version" = 1)
  ),
  CHECK (
    "canonical_record_json" = json_object(
      'actorRef', "actor_ref",
      'actorRefHashVersion', "actor_ref_hash_version",
      'actorUserId', "actor_user_id",
      'clientId', "client_id",
      'eventId', "event_id",
      'eventType', "event_type",
      'ipHash', "ip_hash",
      'metadataJson', "metadata_json",
      'occurredAt', "occurred_at",
      'outcome', "outcome",
      'sequence', "source_sequence",
      'sessionId', "session_id",
      'subjectId', "subject_id",
      'userAgentHash', "user_agent_hash"
    )
  ),
  CHECK (
    "canonical_record_bytes" = length(CAST("canonical_record_json" AS blob))
  )
);

CREATE TABLE "audit_archive_attempt" (
  "id" text PRIMARY KEY NOT NULL CHECK (
    length("id") = 43
    AND "id" NOT GLOB '*[^A-Za-z0-9_-]*'
    AND substr("id", -1) IN (
      'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
      'g', 'k', 'o', 's', 'w', '0', '4', '8'
    )
  ),
  "batch_key" text NOT NULL
    REFERENCES "audit_archive_batch" ("batch_key") ON DELETE RESTRICT,
  "dispatch_generation" integer NOT NULL CHECK (
    typeof("dispatch_generation") = 'integer'
    AND "dispatch_generation" BETWEEN 1 AND 1000000
  ),
  "attempt_number" integer NOT NULL CHECK (
    typeof("attempt_number") = 'integer' AND "attempt_number" BETWEEN 1 AND 5
  ),
  "lease_id" text NOT NULL UNIQUE CHECK ("lease_id" = "id"),
  "outcome" text NOT NULL CHECK (
    "outcome" IN (
      'in_flight', 'archived', 'retry', 'dead', 'corrupt', 'lease_expired'
    )
  ),
  "resulting_status" text NOT NULL CHECK (
    "resulting_status" IN (
      'processing', 'archived', 'retry', 'dead', 'corrupt'
    )
  ),
  "next_attempt_at" date CHECK (
    "next_attempt_at" IS NULL OR (
      length("next_attempt_at") = 24
      AND "next_attempt_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("next_attempt_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "next_attempt_at", '+0 seconds'
      )
        = "next_attempt_at"
    )
  ),
  "r2_version" text CHECK (
    "r2_version" IS NULL OR length("r2_version") BETWEEN 1 AND 256
  ),
  "r2_etag" text CHECK (
    "r2_etag" IS NULL OR length("r2_etag") BETWEEN 1 AND 256
  ),
  "r2_readback_sha256" text CHECK (
    "r2_readback_sha256" IS NULL OR (
      length("r2_readback_sha256") = 64
      AND "r2_readback_sha256" NOT GLOB '*[^a-f0-9]*'
    )
  ),
  "r2_readback_at" date CHECK (
    "r2_readback_at" IS NULL OR (
      length("r2_readback_at") = 24
      AND "r2_readback_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("r2_readback_at") IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      ) IS NOT NULL
      AND strftime(
        '%Y-%m-%dT%H:%M:%fZ', "r2_readback_at", '+0 seconds'
      )
        = "r2_readback_at"
    )
  ),
  "error_code" text CHECK (
    "error_code" IS NULL OR "error_code" IN (
      'queue_unavailable', 'r2_transient', 'r2_object_conflict',
      'r2_readback_mismatch', 'crypto_integrity', 'key_unavailable',
      'lease_expired', 'internal_error'
    )
  ),
  "started_at" date NOT NULL CHECK (
    length("started_at") = 24
    AND "started_at" GLOB '????-??-??T??:??:??.???Z'
    AND unixepoch("started_at") IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', "started_at", '+0 seconds')
      = "started_at"
  ),
  "completed_at" date CHECK (
    "completed_at" IS NULL OR (
      length("completed_at") = 24
      AND "completed_at" GLOB '????-??-??T??:??:??.???Z'
      AND unixepoch("completed_at") IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        IS NOT NULL
      AND strftime('%Y-%m-%dT%H:%M:%fZ', "completed_at", '+0 seconds')
        = "completed_at"
    )
  ),
  UNIQUE ("batch_key", "dispatch_generation", "attempt_number"),
  CHECK ("completed_at" IS NULL OR "completed_at" >= "started_at"),
  CHECK (
    ("r2_version" IS NULL AND "r2_etag" IS NULL
      AND "r2_readback_sha256" IS NULL AND "r2_readback_at" IS NULL)
    OR ("r2_version" IS NOT NULL AND "r2_etag" IS NOT NULL
      AND "r2_readback_sha256" IS NOT NULL AND "r2_readback_at" IS NOT NULL)
  ),
  CHECK (
    ("outcome" = 'in_flight' AND "resulting_status" = 'processing'
      AND "next_attempt_at" IS NULL AND "r2_version" IS NULL
      AND "error_code" IS NULL AND "completed_at" IS NULL)
    OR ("outcome" = 'archived' AND "resulting_status" = 'archived'
      AND "next_attempt_at" IS NULL AND "r2_version" IS NOT NULL
      AND "r2_readback_at" = "completed_at"
      AND "error_code" IS NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'retry' AND "resulting_status" = 'retry'
      AND "attempt_number" BETWEEN 1 AND 4
      AND "next_attempt_at" IS NOT NULL AND "r2_version" IS NULL
      AND "error_code" IS NOT NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'dead' AND "resulting_status" = 'dead'
      AND "attempt_number" = 5
      AND "next_attempt_at" IS NULL AND "r2_version" IS NULL
      AND "error_code" IS NOT NULL AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'corrupt' AND "resulting_status" = 'corrupt'
      AND "next_attempt_at" IS NULL AND "r2_version" IS NOT NULL
      AND "r2_readback_at" = "completed_at"
      AND "error_code" IN (
        'r2_object_conflict', 'r2_readback_mismatch', 'crypto_integrity'
      ) AND "completed_at" IS NOT NULL)
    OR ("outcome" = 'lease_expired'
      AND "resulting_status" = CASE
        WHEN "attempt_number" = 5 THEN 'dead' ELSE 'retry' END
      AND (("attempt_number" < 5 AND "next_attempt_at" IS NOT NULL)
        OR ("attempt_number" = 5 AND "next_attempt_at" IS NULL))
      AND "r2_version" IS NULL AND "error_code" = 'lease_expired'
      AND "completed_at" IS NOT NULL)
  ),
  CHECK (
    "outcome" = 'corrupt' OR "error_code" IS NULL
      OR "error_code" NOT IN (
        'r2_object_conflict', 'r2_readback_mismatch', 'crypto_integrity'
      )
  )
);

CREATE INDEX "audit_archive_batch_due_idx"
  ON "audit_archive_batch" ("status", "next_attempt_at", "batch_key")
  WHERE "status" IN ('pending', 'retry');

CREATE INDEX "audit_archive_batch_expired_lease_idx"
  ON "audit_archive_batch" ("status", "lease_expires_at", "batch_key")
  WHERE "status" = 'processing';

CREATE INDEX "audit_archive_batch_operator_idx"
  ON "audit_archive_batch" ("status", "updated_at" DESC, "batch_key");

CREATE INDEX "audit_archive_attempt_time_idx"
  ON "audit_archive_attempt" ("started_at" DESC, "id");

CREATE INDEX "audit_archive_attempt_error_idx"
  ON "audit_archive_attempt" ("error_code", "completed_at" DESC, "id")
  WHERE "error_code" IS NOT NULL;

CREATE INDEX "audit_archive_attempt_outcome_idx"
  ON "audit_archive_attempt" ("outcome", "completed_at" DESC, "id");

CREATE TRIGGER "audit_archive_batch_item_insert_guard"
BEFORE INSERT ON "audit_archive_batch_item"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_batch_item"
   WHERE ("batch_key" = NEW."batch_key" AND "ordinal" = NEW."ordinal")
      OR "source_sequence" = NEW."source_sequence"
      OR "event_id" = NEW."event_id"
)
OR NOT EXISTS (
  SELECT 1
    FROM "audit_archive_source" AS source
    JOIN "audit_event" AS event ON event."id" = source."event_id"
   WHERE source."sequence" = NEW."source_sequence"
     AND source."event_id" = NEW."event_id"
     AND event."event_type" = NEW."event_type"
     AND event."actor_user_id" IS NEW."actor_user_id"
     AND event."actor_ref" IS NEW."actor_ref"
     AND event."actor_ref_hash_version" IS NEW."actor_ref_hash_version"
     AND event."subject_id" IS NEW."subject_id"
     AND event."client_id" IS NEW."client_id"
     AND event."session_id" IS NEW."session_id"
     AND event."outcome" = NEW."outcome"
     AND event."ip_hash" IS NEW."ip_hash"
     AND event."user_agent_hash" IS NEW."user_agent_hash"
     AND event."metadata_json" IS NEW."metadata_json"
     AND event."occurred_at" = NEW."occurred_at"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive item does not match live source');
END;

CREATE TRIGGER "audit_archive_batch_item_update_guard"
BEFORE UPDATE ON "audit_archive_batch_item"
BEGIN
  SELECT RAISE(ABORT, 'audit archive batch item is immutable');
END;

CREATE TRIGGER "audit_archive_batch_item_delete_guard"
BEFORE DELETE ON "audit_archive_batch_item"
BEGIN
  SELECT RAISE(ABORT, 'audit archive batch item is immutable');
END;

-- Replacing an audit row can otherwise cascade-delete its live source and
-- assign a new sequence. Archived event IDs remain reserved even after the
-- mutable audit/source rows have legitimately disappeared.
CREATE TRIGGER "audit_event_archive_identity_insert_guard"
BEFORE INSERT ON "audit_event"
WHEN EXISTS (SELECT 1 FROM "audit_event" WHERE "id" = NEW."id")
  OR EXISTS (
    SELECT 1 FROM "audit_archive_batch_item" WHERE "event_id" = NEW."id"
  )
BEGIN
  SELECT RAISE(ABORT, 'audit event identity cannot be replaced');
END;

CREATE TRIGGER "audit_archive_batch_insert_guard"
BEFORE INSERT ON "audit_archive_batch"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_batch"
   WHERE "batch_key" = NEW."batch_key"
      OR "checkpoint_revision" = NEW."checkpoint_revision"
      OR "object_key" = NEW."object_key"
      OR "object_sha256" = NEW."object_sha256"
)
OR NEW."status" <> 'pending'
OR NEW."dispatch_generation" <> 1
OR NEW."attempts" <> 0
OR NEW."manual_replay_audit_id" IS NOT NULL
OR NEW."created_at" <> NEW."updated_at"
OR NEW."next_attempt_at" < NEW."created_at"
OR NOT EXISTS (
  SELECT 1 FROM "audit_archive_checkpoint" AS checkpoint
   WHERE checkpoint."id" = 1
     AND checkpoint."revision" = NEW."checkpoint_revision"
     AND checkpoint."last_sequence" = NEW."checkpoint_from_sequence"
     AND (checkpoint."last_archived_at" IS NULL
       OR NEW."created_at" >= checkpoint."last_archived_at")
)
OR NEW."first_sequence" IS NOT (
  SELECT min(source."sequence") FROM "audit_archive_source" AS source
   WHERE source."sequence" > NEW."checkpoint_from_sequence"
)
OR NEW."last_sequence" IS NOT (
  SELECT max(item."source_sequence")
    FROM "audit_archive_batch_item" AS item
   WHERE item."batch_key" = NEW."batch_key"
)
OR NEW."event_count" <> (
  SELECT count(*) FROM "audit_archive_batch_item" AS item
   WHERE item."batch_key" = NEW."batch_key"
)
OR 1 <> (
  SELECT min(item."ordinal") FROM "audit_archive_batch_item" AS item
   WHERE item."batch_key" = NEW."batch_key"
)
OR NEW."event_count" <> (
  SELECT max(item."ordinal") FROM "audit_archive_batch_item" AS item
   WHERE item."batch_key" = NEW."batch_key"
)
OR NEW."plaintext_bytes" <> (
  length(CAST('{"contract":"pgid-audit-records-v1","records":[' AS blob))
  + coalesce((
      SELECT sum(item."canonical_record_bytes")
        FROM "audit_archive_batch_item" AS item
       WHERE item."batch_key" = NEW."batch_key"
    ), 0)
  + NEW."event_count" - 1
  + length(CAST('],"schemaVersion":1}' AS blob))
)
OR EXISTS (
  SELECT 1 FROM "audit_archive_source" AS source
   WHERE source."sequence" > NEW."checkpoint_from_sequence"
     AND source."sequence" <= NEW."last_sequence"
     AND NOT EXISTS (
       SELECT 1 FROM "audit_archive_batch_item" AS item
        WHERE item."batch_key" = NEW."batch_key"
          AND item."source_sequence" = source."sequence"
          AND item."event_id" = source."event_id"
     )
)
OR EXISTS (
  SELECT 1 FROM "audit_archive_batch_item" AS item
   WHERE item."batch_key" = NEW."batch_key"
     AND NOT EXISTS (
       SELECT 1 FROM "audit_archive_source" AS source
        WHERE source."sequence" = item."source_sequence"
          AND source."event_id" = item."event_id"
          AND source."sequence" > NEW."checkpoint_from_sequence"
          AND source."sequence" <= NEW."last_sequence"
     )
)
OR EXISTS (
  SELECT 1
    FROM "audit_archive_batch_item" AS item
    LEFT JOIN "audit_archive_source" AS source
      ON source."sequence" = item."source_sequence"
     AND source."event_id" = item."event_id"
    LEFT JOIN "audit_event" AS event ON event."id" = source."event_id"
   WHERE item."batch_key" = NEW."batch_key"
     AND (
       source."sequence" IS NULL
       OR event."id" IS NULL
       OR event."event_type" IS NOT item."event_type"
       OR event."actor_user_id" IS NOT item."actor_user_id"
       OR event."actor_ref" IS NOT item."actor_ref"
       OR event."actor_ref_hash_version" IS NOT item."actor_ref_hash_version"
       OR event."subject_id" IS NOT item."subject_id"
       OR event."client_id" IS NOT item."client_id"
       OR event."session_id" IS NOT item."session_id"
       OR event."outcome" IS NOT item."outcome"
       OR event."ip_hash" IS NOT item."ip_hash"
       OR event."user_agent_hash" IS NOT item."user_agent_hash"
       OR event."metadata_json" IS NOT item."metadata_json"
       OR event."occurred_at" IS NOT item."occurred_at"
     )
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive batch snapshot is incomplete or stale');
END;

CREATE TRIGGER "audit_archive_batch_delete_guard"
BEFORE DELETE ON "audit_archive_batch"
BEGIN
  SELECT RAISE(ABORT, 'audit archive batch is immutable');
END;

CREATE TRIGGER "audit_archive_batch_identity_update_guard"
BEFORE UPDATE ON "audit_archive_batch"
WHEN NEW."batch_key" <> OLD."batch_key"
  OR NEW."batch_generation" <> OLD."batch_generation"
  OR NEW."checkpoint_revision" <> OLD."checkpoint_revision"
  OR NEW."checkpoint_from_sequence" <> OLD."checkpoint_from_sequence"
  OR NEW."schema_version" <> OLD."schema_version"
  OR NEW."contract" <> OLD."contract"
  OR NEW."manifest_json" <> OLD."manifest_json"
  OR NEW."first_sequence" <> OLD."first_sequence"
  OR NEW."last_sequence" <> OLD."last_sequence"
  OR NEW."event_count" <> OLD."event_count"
  OR NEW."plaintext_bytes" <> OLD."plaintext_bytes"
  OR NEW."plaintext_sha256" <> OLD."plaintext_sha256"
  OR NEW."key_version" <> OLD."key_version"
  OR NEW."content_type" <> OLD."content_type"
  OR NEW."object_key" <> OLD."object_key"
  OR NEW."object_bytes" <> OLD."object_bytes"
  OR NEW."object_sha256" <> OLD."object_sha256"
  OR NEW."created_at" <> OLD."created_at"
  OR NOT (
    NEW."encrypted_envelope" IS OLD."encrypted_envelope"
    OR (OLD."status" = 'processing' AND NEW."status" = 'archived'
      AND NEW."encrypted_envelope" IS NULL)
  )
BEGIN
  SELECT RAISE(ABORT, 'audit archive batch identity is immutable');
END;

CREATE TRIGGER "audit_archive_attempt_insert_guard"
BEFORE INSERT ON "audit_archive_attempt"
WHEN EXISTS (
  SELECT 1 FROM "audit_archive_attempt"
   WHERE "id" = NEW."id" OR "lease_id" = NEW."lease_id"
      OR ("batch_key" = NEW."batch_key"
        AND "dispatch_generation" = NEW."dispatch_generation"
        AND "attempt_number" = NEW."attempt_number")
)
OR NEW."outcome" <> 'in_flight'
OR NOT EXISTS (
  SELECT 1 FROM "audit_archive_batch" AS batch
   WHERE batch."batch_key" = NEW."batch_key"
     AND batch."status" = 'processing'
     AND batch."dispatch_generation" = NEW."dispatch_generation"
     AND batch."attempts" = NEW."attempt_number"
     AND batch."lease_id" = NEW."lease_id"
     AND NEW."started_at" = batch."updated_at"
     AND NEW."started_at" < batch."lease_expires_at"
)
BEGIN
  SELECT RAISE(ABORT, 'audit archive attempt does not match active claim');
END;

CREATE TRIGGER "audit_archive_attempt_delete_guard"
BEFORE DELETE ON "audit_archive_attempt"
BEGIN
  SELECT RAISE(ABORT, 'audit archive attempt is immutable');
END;

CREATE TRIGGER "audit_archive_attempt_transition_guard"
BEFORE UPDATE ON "audit_archive_attempt"
WHEN OLD."outcome" <> 'in_flight'
  OR NEW."id" <> OLD."id"
  OR NEW."batch_key" <> OLD."batch_key"
  OR NEW."dispatch_generation" <> OLD."dispatch_generation"
  OR NEW."attempt_number" <> OLD."attempt_number"
  OR NEW."lease_id" <> OLD."lease_id"
  OR NEW."started_at" <> OLD."started_at"
  OR NEW."outcome" NOT IN (
    'archived', 'retry', 'dead', 'corrupt', 'lease_expired'
  )
  OR NOT EXISTS (
    SELECT 1 FROM "audit_archive_batch" AS batch
     WHERE batch."batch_key" = OLD."batch_key"
       AND batch."status" = 'processing'
       AND batch."dispatch_generation" = OLD."dispatch_generation"
       AND batch."attempts" = OLD."attempt_number"
       AND batch."lease_id" = OLD."lease_id"
       AND (
         (NEW."outcome" = 'lease_expired'
           AND NEW."completed_at" >= batch."lease_expires_at")
         OR (NEW."outcome" <> 'lease_expired'
           AND NEW."completed_at" < batch."lease_expires_at")
       )
       AND (
         NEW."outcome" <> 'archived'
         OR NEW."r2_readback_sha256" = batch."object_sha256"
       )
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid audit archive attempt transition');
END;

-- Claims atomically create their in-flight attempt. The lease is also the
-- opaque attempt ID, so no random value can drift between parent and evidence.
CREATE TRIGGER "audit_archive_batch_claim_attempt"
AFTER UPDATE ON "audit_archive_batch"
WHEN OLD."status" IN ('pending', 'retry') AND NEW."status" = 'processing'
BEGIN
  INSERT INTO "audit_archive_attempt" (
    "id", "batch_key", "dispatch_generation", "attempt_number", "lease_id",
    "outcome", "resulting_status", "next_attempt_at",
    "r2_version", "r2_etag", "r2_readback_sha256", "r2_readback_at",
    "error_code", "started_at", "completed_at"
  ) VALUES (
    NEW."lease_id", NEW."batch_key", NEW."dispatch_generation", NEW."attempts",
    NEW."lease_id", 'in_flight', 'processing', NULL,
    NULL, NULL, NULL, NULL, NULL, NEW."updated_at", NULL
  );
END;

-- One terminal attempt update owns the entire D1 result. Success writes all R2
-- read-back evidence, marks the batch archived, and clears the encrypted BLOB
-- in this single parent UPDATE. SQLite checks that row before the batch AFTER
-- trigger advances the checkpoint.
CREATE TRIGGER "audit_archive_attempt_apply_terminal"
AFTER UPDATE ON "audit_archive_attempt"
WHEN OLD."outcome" = 'in_flight' AND NEW."outcome" <> 'in_flight'
BEGIN
  UPDATE "audit_archive_batch"
     SET "status" = CASE NEW."outcome"
           WHEN 'archived' THEN 'archived'
           WHEN 'retry' THEN 'retry'
           WHEN 'dead' THEN 'dead'
           WHEN 'corrupt' THEN 'corrupt'
           WHEN 'lease_expired' THEN
             CASE WHEN NEW."attempt_number" = 5 THEN 'dead' ELSE 'retry' END
         END,
         "next_attempt_at" = NEW."next_attempt_at",
         "lease_id" = NULL,
         "lease_expires_at" = NULL,
         "r2_version" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_version" ELSE NULL END,
         "r2_etag" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_etag" ELSE NULL END,
         "r2_readback_sha256" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_readback_sha256" ELSE NULL END,
         "r2_readback_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."r2_readback_at" ELSE NULL END,
         "archived_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."completed_at" ELSE NULL END,
         "envelope_gc_at" = CASE WHEN NEW."outcome" = 'archived'
           THEN NEW."completed_at" ELSE NULL END,
         "encrypted_envelope" = CASE WHEN NEW."outcome" = 'archived'
           THEN NULL ELSE "encrypted_envelope" END,
         "last_error_code" = NEW."error_code",
         "updated_at" = NEW."completed_at"
   WHERE "batch_key" = OLD."batch_key"
     AND "status" = 'processing'
     AND "dispatch_generation" = OLD."dispatch_generation"
     AND "attempts" = OLD."attempt_number"
     AND "lease_id" = OLD."lease_id";
END;

CREATE TRIGGER "audit_archive_batch_transition_guard"
BEFORE UPDATE ON "audit_archive_batch"
WHEN NEW."updated_at" <= OLD."updated_at"
OR NOT (
  (OLD."status" IN ('pending', 'retry')
    AND NEW."status" = 'processing'
    AND NEW."dispatch_generation" = OLD."dispatch_generation"
    AND NEW."attempts" = OLD."attempts" + 1
    AND NEW."next_attempt_at" IS NULL
    AND NEW."lease_id" IS NOT NULL
    AND NEW."lease_id" IS NOT OLD."lease_id"
    AND NEW."lease_expires_at" IS NOT NULL
    AND NEW."updated_at" >= OLD."next_attempt_at"
    AND NEW."lease_expires_at" > NEW."updated_at"
    AND NEW."lease_expires_at" <= strftime(
      '%Y-%m-%dT%H:%M:%fZ', NEW."updated_at", '+300 seconds'
    )
    AND NEW."r2_version" IS OLD."r2_version"
    AND NEW."r2_etag" IS OLD."r2_etag"
    AND NEW."r2_readback_sha256" IS OLD."r2_readback_sha256"
    AND NEW."r2_readback_at" IS OLD."r2_readback_at"
    AND NEW."archived_at" IS OLD."archived_at"
    AND NEW."envelope_gc_at" IS OLD."envelope_gc_at"
    AND NEW."last_error_code" IS NULL
    AND NEW."manual_replay_audit_id" IS OLD."manual_replay_audit_id")
  OR (OLD."status" = 'processing'
    AND NEW."status" IN ('archived', 'retry', 'dead', 'corrupt')
    AND NEW."dispatch_generation" = OLD."dispatch_generation"
    AND NEW."attempts" = OLD."attempts"
    AND NEW."lease_id" IS NULL AND NEW."lease_expires_at" IS NULL
    AND NEW."manual_replay_audit_id" IS OLD."manual_replay_audit_id"
    AND EXISTS (
      SELECT 1 FROM "audit_archive_attempt" AS attempt
       WHERE attempt."batch_key" = OLD."batch_key"
         AND attempt."dispatch_generation" = OLD."dispatch_generation"
         AND attempt."attempt_number" = OLD."attempts"
         AND attempt."lease_id" = OLD."lease_id"
         AND attempt."outcome" <> 'in_flight'
         AND attempt."resulting_status" = NEW."status"
         AND attempt."next_attempt_at" IS NEW."next_attempt_at"
         AND attempt."error_code" IS NEW."last_error_code"
         AND attempt."completed_at" = NEW."updated_at"
         AND (
           (NEW."status" = 'archived'
             AND attempt."outcome" = 'archived'
             AND attempt."r2_version" = NEW."r2_version"
             AND attempt."r2_etag" = NEW."r2_etag"
             AND attempt."r2_readback_sha256" = NEW."r2_readback_sha256"
             AND attempt."r2_readback_at" = NEW."r2_readback_at"
             AND NEW."archived_at" = attempt."completed_at"
             AND NEW."envelope_gc_at" = attempt."completed_at")
           OR (NEW."status" <> 'archived'
             AND NEW."r2_version" IS NULL
             AND NEW."archived_at" IS NULL
             AND NEW."envelope_gc_at" IS NULL)
         )
    ))
  OR (OLD."status" = 'dead'
    AND NEW."status" = 'pending'
    AND NEW."dispatch_generation" = OLD."dispatch_generation" + 1
    AND NEW."attempts" = 0
    AND NEW."next_attempt_at" IS NOT NULL
    AND NEW."next_attempt_at" >= NEW."updated_at"
    AND NEW."lease_id" IS NULL AND NEW."lease_expires_at" IS NULL
    AND NEW."r2_version" IS NULL AND NEW."archived_at" IS NULL
    AND NEW."envelope_gc_at" IS NULL AND NEW."last_error_code" IS NULL
    AND NEW."manual_replay_audit_id" IS NOT NULL
    AND NEW."manual_replay_audit_id" IS NOT OLD."manual_replay_audit_id"
    AND EXISTS (
      SELECT 1 FROM "audit_event" AS event
       WHERE event."id" = NEW."manual_replay_audit_id"
         AND event."event_type" = 'audit.archive.manual_replay'
         AND event."outcome" = 'success'
         AND event."subject_id" = OLD."batch_key"
         AND event."metadata_json" = json_object(
           'dispatchGeneration', NEW."dispatch_generation"
         )
         AND event."occurred_at" = NEW."updated_at"
    ))
)
BEGIN
  SELECT RAISE(ABORT, 'invalid audit archive batch transition');
END;

CREATE TRIGGER "audit_archive_checkpoint_transition_guard"
BEFORE UPDATE ON "audit_archive_checkpoint"
WHEN NEW."id" <> OLD."id"
  OR NEW."revision" <> OLD."revision" + 1
  OR NEW."last_sequence" <= OLD."last_sequence"
  OR NEW."last_batch_key" IS NULL
  OR NEW."last_archived_at" IS NULL
  OR (OLD."last_archived_at" IS NOT NULL
    AND NEW."last_archived_at" < OLD."last_archived_at")
  OR NOT EXISTS (
    SELECT 1 FROM "audit_archive_batch" AS batch
     WHERE batch."batch_key" = NEW."last_batch_key"
       AND batch."status" = 'archived'
       AND batch."checkpoint_revision" = OLD."revision"
       AND batch."checkpoint_from_sequence" = OLD."last_sequence"
       AND batch."last_sequence" = NEW."last_sequence"
       AND batch."archived_at" = NEW."last_archived_at"
       AND batch."envelope_gc_at" = NEW."last_archived_at"
       AND batch."encrypted_envelope" IS NULL
  )
BEGIN
  SELECT RAISE(ABORT, 'invalid audit archive checkpoint transition');
END;

CREATE TRIGGER "audit_archive_batch_advance_checkpoint"
AFTER UPDATE OF "status" ON "audit_archive_batch"
WHEN OLD."status" = 'processing' AND NEW."status" = 'archived'
BEGIN
  UPDATE "audit_archive_checkpoint"
     SET "revision" = OLD."checkpoint_revision" + 1,
         "last_sequence" = NEW."last_sequence",
         "last_batch_key" = NEW."batch_key",
         "last_archived_at" = NEW."archived_at"
   WHERE "id" = 1;
END;
