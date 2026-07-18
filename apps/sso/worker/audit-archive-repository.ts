import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES,
  AUDIT_ARCHIVE_MAX_RECORDS,
  encodeCanonicalAuditRecordsV1,
  type AuditArchiveManifestV1,
  type AuditArchiveOutcome,
  type AuditArchiveRecordV1,
} from "./audit-archive-crypto";

const ARCHIVE_KEY_FINGERPRINT_DOMAIN =
  "pgid.audit_archive_kek_fingerprint.v1";
const MAX_SEQUENCE = 9_007_199_254_740_991;
const MAX_CHECKPOINT_REVISION = MAX_SEQUENCE - 1;
const MAX_DISPATCH_GENERATION = 1_000_000;
const MAX_ATTEMPTS = 5;
const MAX_LEASE_SECONDS = 300;
const MAX_RUNTIME_WORK_ITEMS = 25;
const CURRENT_R2_CONFLICT_EVIDENCE_FORMAT = "observed_v1";
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const KEY_VERSION_PATTERN = /^v[1-9][0-9]{0,5}$/;
const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const EVENT_TYPE_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const HASH_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const CANONICAL_REFERENCE_PATTERN =
  /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const FORBIDDEN_CREDENTIAL_MARKERS = [
  `pg72_${"at"}_`,
  `pg72_${"rt"}_`,
  `pg72_${"cs"}_`,
  `PGID${"R1"}`,
] as const;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const CHECKPOINT_KEYS = [
  "lastArchivedAt",
  "lastBatchKey",
  "lastSequence",
  "revision",
] as const;
const CHECKPOINT_ROW_KEYS = [
  "last_archived_at",
  "last_batch_key",
  "last_sequence",
  "revision",
] as const;
const SOURCE_ROW_KEYS = [
  "actor_ref",
  "actor_ref_hash_version",
  "actor_user_id",
  "client_id",
  "event_id",
  "event_type",
  "ip_hash",
  "metadata_json",
  "occurred_at",
  "outcome",
  "sequence",
  "session_id",
  "subject_id",
  "user_agent_hash",
] as const;
const MANIFEST_KEYS = [
  "batchGeneration",
  "checkpointFromSequence",
  "contentType",
  "contract",
  "createdAt",
  "eventCount",
  "firstSequence",
  "keyVersion",
  "lastSequence",
  "objectBytes",
  "objectKey",
  "objectSha256",
  "plaintextSha256",
  "schemaVersion",
] as const;

export interface AuditArchiveCheckpoint {
  lastArchivedAt: string | null;
  lastBatchKey: string | null;
  lastSequence: number;
  revision: number;
}

export interface AuditArchiveSourceSelection {
  checkpoint: AuditArchiveCheckpoint;
  hasMore: boolean;
  records: readonly AuditArchiveRecordV1[];
}

export interface InitializeAuditArchiveKeyInput {
  createdAt: string;
  fingerprintRef: string;
  keyVersion: string;
}

export interface AuditArchiveKeyInitializationResult {
  createdAt: string;
  initialized: boolean;
  keyVersion: string;
}

export interface QueueAuditArchiveBatchInput {
  batchKey: string;
  checkpoint: AuditArchiveCheckpoint;
  encryptedEnvelope: Uint8Array<ArrayBuffer>;
  manifest: AuditArchiveManifestV1;
  records: readonly AuditArchiveRecordV1[];
}

export type QueueAuditArchiveBatchResult =
  | "conflict"
  | "duplicate"
  | "queued";

export interface AuditArchiveLease {
  attemptNumber: number;
  batchKey: string;
  dispatchGeneration: number;
  leaseExpiresAt: string;
  leaseId: string;
  startedAt: string;
  updatedAt: string;
}

export interface AcquireAuditArchiveLeaseInput {
  batchKey: string;
  claimedAt: string;
  dispatchGeneration: number;
  leaseExpiresAt: string;
  leaseId: string;
}

export interface ReadClaimedAuditArchiveBatchInput {
  lease: AuditArchiveLease;
}

export interface AuditArchiveClaimedBatch {
  batchKey: string;
  checkpointFromSequence: number;
  checkpointRevision: number;
  contentType: string;
  encryptedEnvelope: Uint8Array<ArrayBuffer>;
  keyVersion: string;
  manifest: AuditArchiveManifestV1;
  objectBytes: number;
  objectKey: string;
  objectSha256: string;
}

export type AuditArchiveRuntimeBatchStatus =
  | "corrupt"
  | "dead"
  | "pending"
  | "processing"
  | "retry";

export interface AuditArchiveRuntimeBatchReference {
  batchKey: string;
  dispatchGeneration: number;
}

export interface AuditArchiveRuntimeCheckpointBatch {
  batchKey: string;
  status: AuditArchiveRuntimeBatchStatus;
}

export interface SelectAuditArchiveRuntimeWorkInput {
  asOf: string;
  limit: number;
}

export interface AuditArchiveRuntimeWork {
  checkpointBatch: AuditArchiveRuntimeCheckpointBatch | null;
  due: readonly AuditArchiveRuntimeBatchReference[];
  dueHasMore: boolean;
  expired: readonly AuditArchiveLease[];
  expiredHasMore: boolean;
}

export interface RenewAuditArchiveLeaseInput {
  lease: AuditArchiveLease;
  leaseExpiresAt: string;
  renewedAt: string;
}

export interface AdoptAuditArchiveLeaseInput {
  asOf: string;
  lease: AuditArchiveLease;
}

export interface AuditArchiveLeaseAdoptionResult {
  lease: AuditArchiveLease | null;
  status: "adopted" | "conflict" | "current";
}

export interface AuditArchiveLeaseMutationResult {
  lease: AuditArchiveLease | null;
  status: "acquired" | "conflict" | "duplicate" | "renewed";
}

export interface AuditArchiveR2Evidence {
  etag: string;
  observedBytes: number;
  readbackAt: string;
  readbackSha256: string;
  storedSha256: string | null;
  version: string;
}

export interface AuditArchiveR2ConflictEvidence {
  etag: string;
  observedBytes: number;
  readbackAt: string;
  readbackSha256: string | null;
  storedSha256: string | null;
  version: string;
}

export interface FinalizeAuditArchiveLeaseInput {
  completedAt: string;
  evidence: AuditArchiveR2Evidence;
  lease: AuditArchiveLease;
}

export type AuditArchiveTransientErrorCode =
  | "internal_error"
  | "key_unavailable"
  | "queue_unavailable"
  | "r2_transient";

export type AuditArchiveIntegrityErrorCode =
  | "crypto_integrity"
  | "r2_object_conflict"
  | "r2_readback_mismatch";

interface FailAuditArchiveLeaseBase {
  completedAt: string;
  lease: AuditArchiveLease;
}

export type FailAuditArchiveLeaseInput =
  | (FailAuditArchiveLeaseBase & {
    errorCode: AuditArchiveTransientErrorCode;
    evidence: null;
    nextAttemptAt: string | null;
  })
  | (FailAuditArchiveLeaseBase & {
    errorCode: "crypto_integrity";
    evidence: AuditArchiveR2Evidence | null;
    nextAttemptAt: null;
  })
  | (FailAuditArchiveLeaseBase & {
    errorCode: "r2_object_conflict";
    evidence: AuditArchiveR2ConflictEvidence;
    nextAttemptAt: null;
  })
  | (FailAuditArchiveLeaseBase & {
    errorCode: "r2_readback_mismatch";
    evidence: AuditArchiveR2Evidence;
    nextAttemptAt: null;
  });

export interface ExpireAuditArchiveLeaseInput {
  completedAt: string;
  lease: AuditArchiveLease;
  nextAttemptAt: string | null;
}

export type AuditArchiveTerminalMutationResult =
  | "applied"
  | "conflict"
  | "duplicate";

export interface ReplayAuditArchiveBatchInput {
  auditEventId: string;
  batchKey: string;
  dispatchGeneration: number;
  nextAttemptAt: string;
  replayedAt: string;
}

export type AuditArchiveRepositoryErrorCode =
  | "counter_exhausted"
  | "invalid_input"
  | "key_mismatch"
  | "key_unavailable"
  | "source_invalid"
  | "source_unavailable"
  | "write_failed";

export class AuditArchiveRepositoryError extends Error {
  readonly code: AuditArchiveRepositoryErrorCode;

  constructor(code: AuditArchiveRepositoryErrorCode) {
    super(`Audit archive repository failed (${code})`);
    this.name = "AuditArchiveRepositoryError";
    this.code = code;
  }
}

type UnknownRecord = Record<string, unknown>;

interface CanonicalTimestamp {
  iso: string;
  time: number;
}

interface ValidatedBatchCandidate {
  batchKey: string;
  checkpoint: AuditArchiveCheckpoint;
  envelope: Uint8Array<ArrayBuffer>;
  manifest: AuditArchiveManifestV1;
  manifestJson: string;
  plaintextBytes: number;
  recordArrayJson: string;
  recordJson: readonly string[];
  records: readonly AuditArchiveRecordV1[];
}

function fail(code: AuditArchiveRepositoryErrorCode): never {
  throw new AuditArchiveRepositoryError(code);
}

function isRepositoryErrorCode(
  value: unknown,
): value is AuditArchiveRepositoryErrorCode {
  return (
    value === "counter_exhausted" ||
    value === "invalid_input" ||
    value === "key_mismatch" ||
    value === "key_unavailable" ||
    value === "source_invalid" ||
    value === "source_unavailable" ||
    value === "write_failed"
  );
}

function exactLocalRepositoryErrorCode(
  error: unknown,
): AuditArchiveRepositoryErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (Object.getPrototypeOf(error) !== AuditArchiveRepositoryError.prototype) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !isRepositoryErrorCode(descriptor.value)
    ) {
      return undefined;
    }
    return descriptor.value;
  } catch {
    return undefined;
  }
}

function redactedRepositoryError(
  error: unknown,
  fallback: AuditArchiveRepositoryErrorCode,
): AuditArchiveRepositoryError {
  return new AuditArchiveRepositoryError(
    exactLocalRepositoryErrorCode(error) ?? fallback,
  );
}

function recordValue(value: unknown): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_input");
  }
  return value as UnknownRecord;
}

function exactRecord(value: unknown, keys: readonly string[]): UnknownRecord {
  const record = recordValue(value);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    fail("invalid_input");
  }
  return record;
}

function canonicalTimestamp(value: unknown): CanonicalTimestamp {
  if (typeof value !== "string" || !ISO_TIMESTAMP_PATTERN.test(value)) {
    fail("invalid_input");
  }
  const time = new Date(value).getTime();
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    fail("invalid_input");
  }
  return { iso: value, time };
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail("invalid_input");
  }
  return value;
}

function nullableCanonicalTimestamp(value: unknown): string | null {
  return value === null ? null : canonicalTimestamp(value).iso;
}

function canonicalReference(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_REFERENCE_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
}

function nullableCanonicalReference(value: unknown): string | null {
  return value === null ? null : canonicalReference(value);
}

function keyVersion(value: unknown): string {
  if (typeof value !== "string" || !KEY_VERSION_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
}

function sha256HexValue(value: unknown): string {
  if (typeof value !== "string" || !SHA256_HEX_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
}

function safeIdentifier(value: unknown, nullable: true): string | null;
function safeIdentifier(value: unknown, nullable?: false): string;
function safeIdentifier(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (
    typeof value !== "string" ||
    !SAFE_IDENTIFIER_PATTERN.test(value) ||
    FORBIDDEN_CREDENTIAL_MARKERS.some((marker) => value.includes(marker))
  ) {
    fail("invalid_input");
  }
  return value;
}

function safeHash(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
}

function exactBooleanInteger(value: unknown): boolean {
  if (value !== 0 && value !== 1) fail("source_invalid");
  return value === 1;
}

function resultChanges(result: D1Result | undefined): number {
  const changes = result?.meta.changes;
  if (
    typeof changes !== "number" ||
    !Number.isSafeInteger(changes) ||
    changes < 0
  ) {
    fail("source_invalid");
  }
  return changes;
}

function exactRows(
  result: D1Result | undefined,
  maximum: number,
): readonly UnknownRecord[] {
  if (!result || !Array.isArray(result.results) || result.results.length > maximum) {
    fail("source_invalid");
  }
  return result.results.map(recordValue);
}

function bytesValue(value: unknown): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array)) fail("invalid_input");
  if (value.byteLength === 0 || value.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
    fail("invalid_input");
  }
  return new Uint8Array(value);
}

function persistedBytesValue(value: unknown): Uint8Array<ArrayBuffer> {
  if (Array.isArray(value)) {
    if (value.length === 0 || value.length > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
      fail("source_invalid");
    }
    for (let index = 0; index < value.length; index += 1) {
      const byte: unknown = value[index];
      if (
        !Object.hasOwn(value, index) ||
        typeof byte !== "number" ||
        !Number.isInteger(byte) ||
        byte < 0 ||
        byte > 255
      ) {
        fail("source_invalid");
      }
    }
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    if (value.byteLength === 0 || value.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
      fail("source_invalid");
    }
    return new Uint8Array(value.slice(0));
  }
  if (value instanceof Uint8Array) {
    if (value.byteLength === 0 || value.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
      fail("source_invalid");
    }
    return new Uint8Array(value);
  }
  fail("source_invalid");
}

function bytesToHex(bytes: Uint8Array<ArrayBuffer>): string {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  try {
    return bytesToHex(digest);
  } finally {
    digest.fill(0);
  }
}

function parseCheckpoint(value: unknown): AuditArchiveCheckpoint {
  const row = exactRecord(value, CHECKPOINT_KEYS);
  const revision = boundedInteger(row.revision, 0, MAX_CHECKPOINT_REVISION);
  const lastSequence = boundedInteger(row.lastSequence, 0, MAX_SEQUENCE);
  const lastBatchKey = nullableCanonicalReference(row.lastBatchKey);
  const lastArchivedAt = nullableCanonicalTimestamp(row.lastArchivedAt);
  if (
    (revision === 0 &&
      (lastSequence !== 0 || lastBatchKey !== null || lastArchivedAt !== null)) ||
    (revision > 0 &&
      (lastSequence === 0 || lastBatchKey === null || lastArchivedAt === null))
  ) {
    fail("invalid_input");
  }
  return { lastArchivedAt, lastBatchKey, lastSequence, revision };
}

function parseCheckpointRow(value: unknown): AuditArchiveCheckpoint {
  const row = exactRecord(value, CHECKPOINT_ROW_KEYS);
  try {
    return parseCheckpoint({
      lastArchivedAt: row.last_archived_at,
      lastBatchKey: row.last_batch_key,
      lastSequence: row.last_sequence,
      revision: row.revision,
    });
  } catch {
    fail("source_invalid");
  }
}

function parseSourceRow(value: unknown): AuditArchiveRecordV1 {
  const row = exactRecord(value, SOURCE_ROW_KEYS);
  const eventType = row.event_type;
  const outcome = row.outcome;
  if (
    typeof eventType !== "string" ||
    eventType.length > 128 ||
    !EVENT_TYPE_PATTERN.test(eventType) ||
    (outcome !== "success" && outcome !== "denied" && outcome !== "failure")
  ) {
    fail("source_invalid");
  }
  const actorRef = row.actor_ref === null
    ? null
    : canonicalReference(row.actor_ref);
  const actorRefHashVersion = row.actor_ref_hash_version;
  if (
    (actorRef === null && actorRefHashVersion !== null) ||
    (actorRef !== null && actorRefHashVersion !== 1)
  ) {
    fail("source_invalid");
  }
  const metadataJson = row.metadata_json;
  if (metadataJson !== null && typeof metadataJson !== "string") {
    fail("source_invalid");
  }
  try {
    return {
      actorRef,
      actorRefHashVersion: actorRef === null ? null : 1,
      actorUserId: safeIdentifier(row.actor_user_id, true),
      clientId: safeIdentifier(row.client_id, true),
      eventId: safeIdentifier(row.event_id),
      eventType,
      ipHash: safeHash(row.ip_hash),
      metadataJson,
      occurredAt: canonicalTimestamp(row.occurred_at).iso,
      outcome: outcome as AuditArchiveOutcome,
      sequence: boundedInteger(row.sequence, 1, MAX_SEQUENCE),
      sessionId: safeIdentifier(row.session_id, true),
      subjectId: safeIdentifier(row.subject_id, true),
      userAgentHash: safeHash(row.user_agent_hash),
    };
  } catch {
    fail("source_invalid");
  }
}

function validateRecordSet(
  value: unknown,
  invalidCode: "invalid_input" | "source_invalid",
): {
  bytes: Uint8Array<ArrayBuffer>;
  records: readonly AuditArchiveRecordV1[];
} {
  if (!Array.isArray(value) || value.length === 0 || value.length > AUDIT_ARCHIVE_MAX_RECORDS) {
    fail(invalidCode);
  }
  try {
    const records = value.map((record) => {
      const row = exactRecord(record, [
        "actorRef",
        "actorRefHashVersion",
        "actorUserId",
        "clientId",
        "eventId",
        "eventType",
        "ipHash",
        "metadataJson",
        "occurredAt",
        "outcome",
        "sequence",
        "sessionId",
        "subjectId",
        "userAgentHash",
      ]);
      return {
        actorRef: row.actorRef,
        actorRefHashVersion: row.actorRefHashVersion,
        actorUserId: row.actorUserId,
        clientId: row.clientId,
        eventId: row.eventId,
        eventType: row.eventType,
        ipHash: row.ipHash,
        metadataJson: row.metadataJson,
        occurredAt: row.occurredAt,
        outcome: row.outcome,
        sequence: row.sequence,
        sessionId: row.sessionId,
        subjectId: row.subjectId,
        userAgentHash: row.userAgentHash,
      } as AuditArchiveRecordV1;
    });
    const bytes = encodeCanonicalAuditRecordsV1(records);
    return { bytes, records };
  } catch {
    fail(invalidCode);
  }
}

function parseManifest(value: unknown): AuditArchiveManifestV1 {
  const row = exactRecord(value, MANIFEST_KEYS);
  if (
    row.contentType !== AUDIT_ARCHIVE_CONTENT_TYPE ||
    row.contract !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
    row.schemaVersion !== 1
  ) {
    fail("invalid_input");
  }
  const firstSequence = boundedInteger(row.firstSequence, 1, MAX_SEQUENCE);
  const lastSequence = boundedInteger(row.lastSequence, firstSequence, MAX_SEQUENCE);
  const checkpointFromSequence = boundedInteger(
    row.checkpointFromSequence,
    0,
    MAX_SEQUENCE,
  );
  const eventCount = boundedInteger(row.eventCount, 1, AUDIT_ARCHIVE_MAX_RECORDS);
  const objectBytes = boundedInteger(row.objectBytes, 1, AUDIT_ARCHIVE_MAX_OBJECT_BYTES);
  if (checkpointFromSequence >= firstSequence || typeof row.objectKey !== "string") {
    fail("invalid_input");
  }
  return {
    batchGeneration: boundedInteger(row.batchGeneration, 1, MAX_SEQUENCE),
    checkpointFromSequence,
    contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
    createdAt: canonicalTimestamp(row.createdAt).iso,
    eventCount,
    firstSequence,
    keyVersion: keyVersion(row.keyVersion),
    lastSequence,
    objectBytes,
    objectKey: row.objectKey,
    objectSha256: sha256HexValue(row.objectSha256),
    plaintextSha256: sha256HexValue(row.plaintextSha256),
    schemaVersion: 1,
  };
}

function expectedObjectKey(
  firstSequence: number,
  lastSequence: number,
  digest: string,
): string {
  return `audit/v1/${String(firstSequence).padStart(16, "0")}-${String(
    lastSequence,
  ).padStart(16, "0")}/${digest}.pgid-audit`;
}

async function validatedBatchCandidate(
  value: QueueAuditArchiveBatchInput,
): Promise<ValidatedBatchCandidate> {
  const input = exactRecord(value, [
    "batchKey",
    "checkpoint",
    "encryptedEnvelope",
    "manifest",
    "records",
  ]);
  const batchKey = canonicalReference(input.batchKey);
  const checkpoint = parseCheckpoint(input.checkpoint);
  if (checkpoint.revision >= MAX_CHECKPOINT_REVISION) fail("counter_exhausted");
  const manifest = parseManifest(input.manifest);
  const envelope = bytesValue(input.encryptedEnvelope);
  let canonical: ReturnType<typeof validateRecordSet> | undefined;
  try {
    canonical = validateRecordSet(input.records, "invalid_input");
    if (canonical.bytes.byteLength > AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES) {
      fail("invalid_input");
    }
    const first = canonical.records[0];
    const last = canonical.records.at(-1);
    if (
      !first ||
      !last ||
      manifest.batchGeneration !== checkpoint.revision + 1 ||
      manifest.checkpointFromSequence !== checkpoint.lastSequence ||
      manifest.eventCount !== canonical.records.length ||
      manifest.firstSequence !== first.sequence ||
      manifest.lastSequence !== last.sequence ||
      manifest.objectBytes !== envelope.byteLength ||
      manifest.objectKey !== expectedObjectKey(
        manifest.firstSequence,
        manifest.lastSequence,
        manifest.objectSha256,
      )
    ) {
      fail("invalid_input");
    }
    const [plaintextSha256, objectSha256] = await Promise.all([
      sha256Hex(canonical.bytes),
      sha256Hex(envelope),
    ]);
    if (
      plaintextSha256 !== manifest.plaintextSha256 ||
      objectSha256 !== manifest.objectSha256
    ) {
      fail("invalid_input");
    }
    const records = canonical.records;
    const recordJson = records.map((record) => JSON.stringify(record));
    return {
      batchKey,
      checkpoint,
      envelope,
      manifest,
      manifestJson: JSON.stringify(manifest),
      plaintextBytes: canonical.bytes.byteLength,
      recordArrayJson: `[${recordJson.join(",")}]`,
      recordJson,
      records,
    };
  } catch (error) {
    envelope.fill(0);
    throw error;
  } finally {
    canonical?.bytes.fill(0);
  }
}

const KEY_SENTINEL_ROW_KEYS = [
  "created_at",
  "domain",
  "fingerprint_hash_version",
  "fingerprint_matches",
  "key_version",
  "key_version_matches",
] as const;

export async function initializeOrVerifyAuditArchiveKey(
  database: D1Database,
  value: InitializeAuditArchiveKeyInput,
): Promise<AuditArchiveKeyInitializationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["createdAt", "fingerprintRef", "keyVersion"]);
    const createdAt = canonicalTimestamp(input.createdAt).iso;
    const fingerprintRef = canonicalReference(input.fingerprintRef);
    const version = keyVersion(input.keyVersion);
    const results = await database.batch([
      database.prepare(
        `INSERT INTO audit_archive_key_sentinel
          (key_version, domain, fingerprint_ref, fingerprint_hash_version,
           created_at)
         SELECT ?, ?, ?, 1, ?
          WHERE NOT EXISTS (
            SELECT 1 FROM audit_archive_key_sentinel
             WHERE key_version = ? OR fingerprint_ref = ?
          )`,
      ).bind(
        version,
        ARCHIVE_KEY_FINGERPRINT_DOMAIN,
        fingerprintRef,
        createdAt,
        version,
        fingerprintRef,
      ),
      database.prepare(
        `SELECT key_version, domain, fingerprint_hash_version, created_at,
                fingerprint_ref = ? AS fingerprint_matches,
                key_version = ? AS key_version_matches
           FROM audit_archive_key_sentinel
          WHERE key_version = ? OR fingerprint_ref = ?
          ORDER BY key_version
          LIMIT 2`,
      ).bind(fingerprintRef, version, version, fingerprintRef),
    ]);
    const inserted = resultChanges(results[0]);
    if (inserted !== 0 && inserted !== 1) fail("source_invalid");
    const rows = exactRows(results[1], 2);
    if (rows.length !== 1) fail("key_mismatch");
    const row = exactRecord(rows[0], KEY_SENTINEL_ROW_KEYS);
    if (
      row.domain !== ARCHIVE_KEY_FINGERPRINT_DOMAIN ||
      row.fingerprint_hash_version !== 1 ||
      !exactBooleanInteger(row.fingerprint_matches) ||
      !exactBooleanInteger(row.key_version_matches) ||
      keyVersion(row.key_version) !== version
    ) {
      fail("key_mismatch");
    }
    const persistedCreatedAt = canonicalTimestamp(row.created_at).iso;
    if (inserted === 1 && persistedCreatedAt !== createdAt) fail("source_invalid");
    return {
      createdAt: persistedCreatedAt,
      initialized: inserted === 1,
      keyVersion: version,
    };
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function selectAuditArchiveSource(
  database: D1Database,
): Promise<AuditArchiveSourceSelection> {
  try {
    if (arguments.length !== 1) fail("invalid_input");
    const results = await database.batch([
      database.prepare(
        `SELECT revision, last_sequence, last_batch_key, last_archived_at
           FROM audit_archive_checkpoint
          WHERE id = 1`,
      ),
      database.prepare(
        `SELECT source.sequence, event.id AS event_id, event.event_type,
                event.actor_user_id, event.actor_ref,
                event.actor_ref_hash_version, event.subject_id,
                event.client_id, event.session_id, event.outcome,
                event.ip_hash, event.user_agent_hash, event.metadata_json,
                event.occurred_at
           FROM audit_archive_source AS source
           JOIN audit_event AS event ON event.id = source.event_id
          WHERE source.sequence > (
            SELECT last_sequence FROM audit_archive_checkpoint WHERE id = 1
          )
          ORDER BY source.sequence
          LIMIT 101`,
      ),
    ]);
    const checkpointRows = exactRows(results[0], 2);
    if (checkpointRows.length !== 1) fail("source_invalid");
    let checkpoint: AuditArchiveCheckpoint;
    let available: AuditArchiveRecordV1[];
    try {
      checkpoint = parseCheckpointRow(checkpointRows[0]);
      available = exactRows(results[1], 101).map(parseSourceRow);
    } catch {
      fail("source_invalid");
    }
    let previousSequence = checkpoint.lastSequence;
    for (const record of available) {
      if (record.sequence <= previousSequence) fail("source_invalid");
      previousSequence = record.sequence;
      const single = validateRecordSet([record], "source_invalid");
      single.bytes.fill(0);
    }

    const records: AuditArchiveRecordV1[] = [];
    for (const record of available.slice(0, AUDIT_ARCHIVE_MAX_RECORDS)) {
      let canonical: ReturnType<typeof validateRecordSet> | undefined;
      try {
        canonical = validateRecordSet([...records, record], "source_invalid");
        if (canonical.bytes.byteLength > AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES) break;
        records.push(record);
      } catch (error) {
        if (records.length === 0) throw error;
        break;
      } finally {
        canonical?.bytes.fill(0);
      }
    }
    if (available.length > 0 && records.length === 0) fail("source_invalid");
    return {
      checkpoint,
      hasMore: available.length > records.length,
      records,
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
}

const ITEM_INSERT_SQL = `INSERT INTO audit_archive_batch_item
  (batch_key, ordinal, source_sequence, event_id, event_type,
   actor_user_id, actor_ref, actor_ref_hash_version, subject_id,
   client_id, session_id, outcome, ip_hash, user_agent_hash,
   metadata_json, occurred_at, canonical_record_json, canonical_record_bytes)
 SELECT ?, CAST(entry.key AS INTEGER) + 1,
        json_extract(entry.value, '$.sequence'),
        json_extract(entry.value, '$.eventId'),
        json_extract(entry.value, '$.eventType'),
        json_extract(entry.value, '$.actorUserId'),
        json_extract(entry.value, '$.actorRef'),
        json_extract(entry.value, '$.actorRefHashVersion'),
        json_extract(entry.value, '$.subjectId'),
        json_extract(entry.value, '$.clientId'),
        json_extract(entry.value, '$.sessionId'),
        json_extract(entry.value, '$.outcome'),
        json_extract(entry.value, '$.ipHash'),
        json_extract(entry.value, '$.userAgentHash'),
        json_extract(entry.value, '$.metadataJson'),
        json_extract(entry.value, '$.occurredAt'),
        entry.value,
        length(CAST(entry.value AS blob))
   FROM json_each(?) AS entry
  WHERE EXISTS (
    SELECT 1 FROM audit_archive_checkpoint
     WHERE id = 1 AND revision = ? AND last_sequence = ?
       AND last_batch_key IS ? AND last_archived_at IS ?
  )
    AND EXISTS (
      SELECT 1 FROM audit_archive_key_sentinel WHERE key_version = ?
    )
    AND NOT EXISTS (
      SELECT 1 FROM audit_archive_batch
       WHERE batch_key = ? OR checkpoint_revision = ?
    )`;

const PARENT_INSERT_SQL = `INSERT INTO audit_archive_batch
  (batch_key, batch_generation, checkpoint_revision,
   checkpoint_from_sequence, schema_version, contract, manifest_json,
   first_sequence, last_sequence, event_count, plaintext_bytes,
   plaintext_sha256, key_version, content_type, object_key, object_bytes,
   object_sha256, encrypted_envelope, status, dispatch_generation, attempts,
   next_attempt_at, lease_id, lease_expires_at, r2_version, r2_etag,
   r2_readback_sha256, r2_readback_at, archived_at, envelope_gc_at,
   last_error_code, manual_replay_audit_id, created_at, updated_at)
 SELECT ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        'pending', 1, 0, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, ?, ?
  WHERE changes() = ?`;

const QUEUED_BATCH_ROW_KEYS = [
  "batch_generation",
  "batch_key",
  "checkpoint_from_sequence",
  "checkpoint_revision",
  "content_type",
  "contract",
  "created_at",
  "envelope_cleared",
  "envelope_matches",
  "event_count",
  "first_sequence",
  "key_version",
  "last_sequence",
  "manifest_json",
  "object_bytes",
  "object_key",
  "object_sha256",
  "plaintext_bytes",
  "plaintext_sha256",
  "schema_version",
  "status",
] as const;

function queuedBatchMatches(
  value: unknown,
  candidate: ValidatedBatchCandidate,
): boolean {
  let row: UnknownRecord;
  try {
    row = exactRecord(value, QUEUED_BATCH_ROW_KEYS);
    const status = row.status;
    if (
      status !== "pending" &&
      status !== "processing" &&
      status !== "retry" &&
      status !== "archived" &&
      status !== "dead" &&
      status !== "corrupt"
    ) {
      return false;
    }
    const envelopeCleared = exactBooleanInteger(row.envelope_cleared);
    const envelopeMatches = row.envelope_matches === null
      ? null
      : exactBooleanInteger(row.envelope_matches);
    if (
      (status === "archived" && (!envelopeCleared || envelopeMatches !== null)) ||
      (status !== "archived" && (envelopeCleared || envelopeMatches !== true))
    ) {
      return false;
    }
    return (
      canonicalReference(row.batch_key) === candidate.batchKey &&
      boundedInteger(row.batch_generation, 1, MAX_SEQUENCE) ===
        candidate.manifest.batchGeneration &&
      boundedInteger(row.checkpoint_revision, 0, MAX_CHECKPOINT_REVISION) ===
        candidate.checkpoint.revision &&
      boundedInteger(row.checkpoint_from_sequence, 0, MAX_SEQUENCE) ===
        candidate.checkpoint.lastSequence &&
      row.schema_version === 1 &&
      row.contract === AUDIT_ARCHIVE_ENVELOPE_CONTRACT &&
      row.manifest_json === candidate.manifestJson &&
      boundedInteger(row.first_sequence, 1, MAX_SEQUENCE) ===
        candidate.manifest.firstSequence &&
      boundedInteger(row.last_sequence, 1, MAX_SEQUENCE) ===
        candidate.manifest.lastSequence &&
      boundedInteger(row.event_count, 1, AUDIT_ARCHIVE_MAX_RECORDS) ===
        candidate.records.length &&
      boundedInteger(row.plaintext_bytes, 1, AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES) ===
        candidate.plaintextBytes &&
      sha256HexValue(row.plaintext_sha256) ===
        candidate.manifest.plaintextSha256 &&
      keyVersion(row.key_version) === candidate.manifest.keyVersion &&
      row.content_type === AUDIT_ARCHIVE_CONTENT_TYPE &&
      row.object_key === candidate.manifest.objectKey &&
      boundedInteger(row.object_bytes, 1, AUDIT_ARCHIVE_MAX_OBJECT_BYTES) ===
        candidate.manifest.objectBytes &&
      sha256HexValue(row.object_sha256) === candidate.manifest.objectSha256 &&
      canonicalTimestamp(row.created_at).iso === candidate.manifest.createdAt
    );
  } catch {
    fail("source_invalid");
  }
}

function queuedItemsMatch(
  rows: readonly UnknownRecord[],
  candidate: ValidatedBatchCandidate,
): boolean {
  if (rows.length !== candidate.recordJson.length) return false;
  try {
    return rows.every((value, index) => {
      const row = exactRecord(value, ["canonical_record_json", "ordinal"]);
      return (
        boundedInteger(row.ordinal, 1, AUDIT_ARCHIVE_MAX_RECORDS) === index + 1 &&
        row.canonical_record_json === candidate.recordJson[index]
      );
    });
  } catch {
    fail("source_invalid");
  }
}

export async function queueAuditArchiveBatch(
  database: D1Database,
  value: QueueAuditArchiveBatchInput,
): Promise<QueueAuditArchiveBatchResult> {
  let candidate: ValidatedBatchCandidate | undefined;
  try {
    if (arguments.length !== 2) fail("invalid_input");
    candidate = await validatedBatchCandidate(value);
    const { checkpoint, manifest } = candidate;
    const results = await database.batch([
      database.prepare(ITEM_INSERT_SQL).bind(
        candidate.batchKey,
        candidate.recordArrayJson,
        checkpoint.revision,
        checkpoint.lastSequence,
        checkpoint.lastBatchKey,
        checkpoint.lastArchivedAt,
        manifest.keyVersion,
        candidate.batchKey,
        checkpoint.revision,
      ),
      database.prepare(PARENT_INSERT_SQL).bind(
        candidate.batchKey,
        manifest.batchGeneration,
        checkpoint.revision,
        checkpoint.lastSequence,
        AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
        candidate.manifestJson,
        manifest.firstSequence,
        manifest.lastSequence,
        manifest.eventCount,
        candidate.plaintextBytes,
        manifest.plaintextSha256,
        manifest.keyVersion,
        AUDIT_ARCHIVE_CONTENT_TYPE,
        manifest.objectKey,
        manifest.objectBytes,
        manifest.objectSha256,
        candidate.envelope,
        manifest.createdAt,
        manifest.createdAt,
        manifest.createdAt,
        manifest.eventCount,
      ),
      database.prepare(
        `SELECT batch_key, batch_generation, checkpoint_revision,
                checkpoint_from_sequence, schema_version, contract,
                manifest_json, first_sequence, last_sequence, event_count,
                plaintext_bytes, plaintext_sha256, key_version, content_type,
                object_key, object_bytes, object_sha256, status, created_at,
                encrypted_envelope IS NULL AS envelope_cleared,
                CASE WHEN encrypted_envelope IS NULL THEN NULL
                     ELSE encrypted_envelope = ? END AS envelope_matches
           FROM audit_archive_batch
          WHERE batch_key = ?`,
      ).bind(candidate.envelope, candidate.batchKey),
      database.prepare(
        `SELECT ordinal, canonical_record_json
           FROM audit_archive_batch_item
          WHERE batch_key = ?
          ORDER BY ordinal
          LIMIT 101`,
      ).bind(candidate.batchKey),
      database.prepare(
        `SELECT count(*) AS conflict_count
           FROM audit_archive_batch
          WHERE checkpoint_revision = ? AND batch_key <> ?`,
      ).bind(checkpoint.revision, candidate.batchKey),
      database.prepare(
        `SELECT count(*) AS sentinel_count
           FROM audit_archive_key_sentinel
          WHERE key_version = ?`,
      ).bind(manifest.keyVersion),
    ]);
    const itemChanges = resultChanges(results[0]);
    const parentChanges = resultChanges(results[1]);
    const applied = itemChanges === candidate.records.length && parentChanges === 1;
    const noOp = itemChanges === 0 && parentChanges === 0;
    if (!applied && !noOp) fail("write_failed");

    const batchRows = exactRows(results[2], 2);
    const itemRows = exactRows(results[3], 101);
    const conflictRows = exactRows(results[4], 1);
    const sentinelRows = exactRows(results[5], 1);
    if (conflictRows.length !== 1 || sentinelRows.length !== 1) {
      fail("source_invalid");
    }
    const conflictCount = boundedInteger(
      exactRecord(conflictRows[0], ["conflict_count"]).conflict_count,
      0,
      1,
    );
    const sentinelCount = boundedInteger(
      exactRecord(sentinelRows[0], ["sentinel_count"]).sentinel_count,
      0,
      1,
    );
    if (sentinelCount !== 1) fail("key_unavailable");
    const exactPersisted =
      batchRows.length === 1 &&
      queuedBatchMatches(batchRows[0], candidate) &&
      queuedItemsMatch(itemRows, candidate);
    if (applied) {
      if (!exactPersisted || conflictCount !== 0) fail("write_failed");
      return "queued";
    }
    if (exactPersisted) return "duplicate";
    return "conflict";
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  } finally {
    candidate?.envelope.fill(0);
  }
}

const LEASE_KEYS = [
  "attemptNumber",
  "batchKey",
  "dispatchGeneration",
  "leaseExpiresAt",
  "leaseId",
  "startedAt",
  "updatedAt",
] as const;
const LEASE_ROW_KEYS = [
  "attempt_number",
  "batch_key",
  "dispatch_generation",
  "lease_expires_at",
  "lease_id",
  "outcome",
  "started_at",
  "updated_at",
] as const;

function parseLease(value: unknown): AuditArchiveLease {
  const row = exactRecord(value, LEASE_KEYS);
  const startedAt = canonicalTimestamp(row.startedAt);
  const updatedAt = canonicalTimestamp(row.updatedAt);
  const leaseExpiresAt = canonicalTimestamp(row.leaseExpiresAt);
  if (
    updatedAt.time < startedAt.time ||
    leaseExpiresAt.time <= updatedAt.time
  ) {
    fail("invalid_input");
  }
  return {
    attemptNumber: boundedInteger(row.attemptNumber, 1, MAX_ATTEMPTS),
    batchKey: canonicalReference(row.batchKey),
    dispatchGeneration: boundedInteger(
      row.dispatchGeneration,
      1,
      MAX_DISPATCH_GENERATION,
    ),
    leaseExpiresAt: leaseExpiresAt.iso,
    leaseId: canonicalReference(row.leaseId),
    startedAt: startedAt.iso,
    updatedAt: updatedAt.iso,
  };
}

function parseLeaseRow(value: unknown): AuditArchiveLease {
  const row = exactRecord(value, LEASE_ROW_KEYS);
  if (row.outcome !== "in_flight") fail("source_invalid");
  try {
    return parseLease({
      attemptNumber: row.attempt_number,
      batchKey: row.batch_key,
      dispatchGeneration: row.dispatch_generation,
      leaseExpiresAt: row.lease_expires_at,
      leaseId: row.lease_id,
      startedAt: row.started_at,
      updatedAt: row.updated_at,
    });
  } catch {
    fail("source_invalid");
  }
}

function sameLease(left: AuditArchiveLease, right: AuditArchiveLease): boolean {
  return (
    left.attemptNumber === right.attemptNumber &&
    left.batchKey === right.batchKey &&
    left.dispatchGeneration === right.dispatchGeneration &&
    left.leaseExpiresAt === right.leaseExpiresAt &&
    left.leaseId === right.leaseId &&
    left.startedAt === right.startedAt &&
    left.updatedAt === right.updatedAt
  );
}

function sameLeaseFence(left: AuditArchiveLease, right: AuditArchiveLease): boolean {
  return (
    left.attemptNumber === right.attemptNumber &&
    left.batchKey === right.batchKey &&
    left.dispatchGeneration === right.dispatchGeneration &&
    left.leaseId === right.leaseId &&
    left.startedAt === right.startedAt
  );
}

function leaseProjectionStatement(
  database: D1Database,
  batchKey: string,
  dispatchGeneration: number,
  leaseId: string,
  changesGated: boolean,
): D1PreparedStatement {
  return database.prepare(
    `SELECT batch.batch_key, batch.dispatch_generation,
            batch.attempts AS attempt_number, batch.lease_id,
            batch.lease_expires_at, attempt.started_at,
            batch.updated_at, attempt.outcome
       FROM audit_archive_batch AS batch
       JOIN audit_archive_attempt AS attempt
         ON attempt.batch_key = batch.batch_key
        AND attempt.dispatch_generation = batch.dispatch_generation
        AND attempt.attempt_number = batch.attempts
        AND attempt.lease_id = batch.lease_id
      WHERE batch.status = 'processing'
        AND batch.batch_key = ?
        AND batch.dispatch_generation = ?
        AND attempt.id = ?
        AND attempt.outcome = 'in_flight'
        ${changesGated ? "AND changes() = 1" : ""}`,
  ).bind(batchKey, dispatchGeneration, leaseId);
}

function leaseFromResult(
  result: D1Result | undefined,
): AuditArchiveLease | null {
  const rows = exactRows(result, 1);
  return rows.length === 0 ? null : parseLeaseRow(rows[0]);
}

function validateLeaseWindow(
  startedAt: CanonicalTimestamp,
  expiresAt: CanonicalTimestamp,
): void {
  if (
    expiresAt.time <= startedAt.time ||
    expiresAt.time - startedAt.time > MAX_LEASE_SECONDS * 1_000
  ) {
    fail("invalid_input");
  }
}

export async function acquireAuditArchiveLease(
  database: D1Database,
  value: AcquireAuditArchiveLeaseInput,
): Promise<AuditArchiveLeaseMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, [
      "batchKey",
      "claimedAt",
      "dispatchGeneration",
      "leaseExpiresAt",
      "leaseId",
    ]);
    const batchKey = canonicalReference(input.batchKey);
    const dispatchGeneration = boundedInteger(
      input.dispatchGeneration,
      1,
      MAX_DISPATCH_GENERATION,
    );
    const leaseId = canonicalReference(input.leaseId);
    const claimedAt = canonicalTimestamp(input.claimedAt);
    const leaseExpiresAt = canonicalTimestamp(input.leaseExpiresAt);
    validateLeaseWindow(claimedAt, leaseExpiresAt);
    const results = await database.batch([
      database.prepare(
        `UPDATE audit_archive_batch
            SET status = 'processing', attempts = attempts + 1,
                next_attempt_at = NULL, lease_id = ?, lease_expires_at = ?,
                last_error_code = NULL, updated_at = ?
          WHERE batch_key = ?
            AND dispatch_generation = ?
            AND status IN ('pending', 'retry')
            AND attempts < 5
            AND next_attempt_at IS NOT NULL
            AND next_attempt_at <= ?
            AND updated_at < ?`,
      ).bind(
        leaseId,
        leaseExpiresAt.iso,
        claimedAt.iso,
        batchKey,
        dispatchGeneration,
        claimedAt.iso,
        claimedAt.iso,
      ),
      leaseProjectionStatement(
        database,
        batchKey,
        dispatchGeneration,
        leaseId,
        true,
      ),
      leaseProjectionStatement(
        database,
        batchKey,
        dispatchGeneration,
        leaseId,
        false,
      ),
    ]);
    const gated = leaseFromResult(results[1]);
    const persisted = leaseFromResult(results[2]);
    if (gated !== null) {
      if (persisted === null || !sameLease(gated, persisted)) fail("source_invalid");
      if (
        gated.batchKey !== batchKey ||
        gated.dispatchGeneration !== dispatchGeneration ||
        gated.leaseId !== leaseId ||
        gated.startedAt !== claimedAt.iso ||
        gated.updatedAt !== claimedAt.iso ||
        gated.leaseExpiresAt !== leaseExpiresAt.iso
      ) {
        fail("source_invalid");
      }
      return { lease: gated, status: "acquired" };
    }
    if (
      persisted !== null &&
      persisted.batchKey === batchKey &&
      persisted.dispatchGeneration === dispatchGeneration &&
      persisted.leaseId === leaseId &&
      persisted.startedAt === claimedAt.iso &&
      persisted.updatedAt === claimedAt.iso &&
      persisted.leaseExpiresAt === leaseExpiresAt.iso
    ) {
      return { lease: persisted, status: "duplicate" };
    }
    return { lease: null, status: "conflict" };
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

const CLAIMED_BATCH_ROW_KEYS = [
  "attempt_number",
  "batch_generation",
  "batch_key",
  "checkpoint_from_sequence",
  "checkpoint_revision",
  "content_type",
  "contract",
  "created_at",
  "dispatch_generation",
  "encrypted_envelope",
  "envelope_bytes",
  "event_count",
  "first_sequence",
  "key_version",
  "last_sequence",
  "lease_expires_at",
  "lease_id",
  "manifest_json",
  "object_bytes",
  "object_key",
  "object_sha256",
  "outcome",
  "plaintext_sha256",
  "schema_version",
  "started_at",
  "updated_at",
] as const;

export async function readClaimedAuditArchiveBatch(
  database: D1Database,
  value: ReadClaimedAuditArchiveBatchInput,
): Promise<AuditArchiveClaimedBatch | null> {
  let envelope: Uint8Array<ArrayBuffer> | undefined;
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["lease"]);
    const lease = parseLease(input.lease);
    const result = await database.prepare(
      `SELECT batch.batch_key, batch.batch_generation,
              batch.checkpoint_revision, batch.checkpoint_from_sequence,
              batch.schema_version, batch.contract, batch.manifest_json,
              batch.first_sequence, batch.last_sequence, batch.event_count,
              batch.plaintext_sha256, batch.key_version, batch.content_type,
              batch.object_key, batch.object_bytes, batch.object_sha256,
              batch.encrypted_envelope,
              length(batch.encrypted_envelope) AS envelope_bytes,
              batch.dispatch_generation, batch.attempts AS attempt_number,
              batch.lease_id, batch.lease_expires_at, batch.created_at,
              batch.updated_at, attempt.started_at, attempt.outcome
         FROM audit_archive_batch AS batch
         JOIN audit_archive_attempt AS attempt
           ON attempt.batch_key = batch.batch_key
          AND attempt.dispatch_generation = batch.dispatch_generation
          AND attempt.attempt_number = batch.attempts
          AND attempt.lease_id = batch.lease_id
        WHERE batch.status = 'processing'
          AND batch.batch_key = ?
          AND batch.dispatch_generation = ?
          AND batch.attempts = ?
          AND batch.lease_id = ?
          AND batch.lease_expires_at = ?
          AND batch.updated_at = ?
          AND attempt.started_at = ?
          AND attempt.outcome = 'in_flight'
        LIMIT 2`,
    ).bind(
      lease.batchKey,
      lease.dispatchGeneration,
      lease.attemptNumber,
      lease.leaseId,
      lease.leaseExpiresAt,
      lease.updatedAt,
      lease.startedAt,
    ).all();
    const rows = exactRows(result, 2);
    if (rows.length === 0) return null;
    if (rows.length !== 1) fail("source_invalid");
    try {
      const row = exactRecord(rows[0], CLAIMED_BATCH_ROW_KEYS);
      if (row.outcome !== "in_flight") fail("source_invalid");
      const projectedLease = parseLease({
        attemptNumber: row.attempt_number,
        batchKey: row.batch_key,
        dispatchGeneration: row.dispatch_generation,
        leaseExpiresAt: row.lease_expires_at,
        leaseId: row.lease_id,
        startedAt: row.started_at,
        updatedAt: row.updated_at,
      });
      if (!sameLease(projectedLease, lease)) fail("source_invalid");

      if (typeof row.manifest_json !== "string") fail("source_invalid");
      const parsedManifest: unknown = JSON.parse(row.manifest_json);
      const manifest = parseManifest(parsedManifest);
      const checkpointRevision = boundedInteger(
        row.checkpoint_revision,
        0,
        MAX_CHECKPOINT_REVISION,
      );
      const checkpointFromSequence = boundedInteger(
        row.checkpoint_from_sequence,
        0,
        MAX_SEQUENCE,
      );
      const objectBytes = boundedInteger(
        row.object_bytes,
        1,
        AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
      );
      envelope = persistedBytesValue(row.encrypted_envelope);
      if (
        row.contract !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
        row.schema_version !== 1 ||
        row.content_type !== AUDIT_ARCHIVE_CONTENT_TYPE ||
        JSON.stringify(manifest) !== row.manifest_json ||
        manifest.batchGeneration !==
          boundedInteger(row.batch_generation, 1, MAX_SEQUENCE) ||
        manifest.batchGeneration !== checkpointRevision + 1 ||
        manifest.checkpointFromSequence !== checkpointFromSequence ||
        manifest.createdAt !== canonicalTimestamp(row.created_at).iso ||
        manifest.eventCount !==
          boundedInteger(row.event_count, 1, AUDIT_ARCHIVE_MAX_RECORDS) ||
        manifest.firstSequence !==
          boundedInteger(row.first_sequence, 1, MAX_SEQUENCE) ||
        manifest.lastSequence !==
          boundedInteger(row.last_sequence, manifest.firstSequence, MAX_SEQUENCE) ||
        manifest.plaintextSha256 !== sha256HexValue(row.plaintext_sha256) ||
        manifest.keyVersion !== keyVersion(row.key_version) ||
        manifest.contentType !== row.content_type ||
        manifest.objectKey !== row.object_key ||
        manifest.objectKey !== expectedObjectKey(
          manifest.firstSequence,
          manifest.lastSequence,
          manifest.objectSha256,
        ) ||
        manifest.objectBytes !== objectBytes ||
        manifest.objectSha256 !== sha256HexValue(row.object_sha256) ||
        boundedInteger(row.envelope_bytes, 1, AUDIT_ARCHIVE_MAX_OBJECT_BYTES) !==
          objectBytes ||
        envelope.byteLength !== objectBytes ||
        await sha256Hex(envelope) !== manifest.objectSha256
      ) {
        fail("source_invalid");
      }
      const claimed = {
        batchKey: lease.batchKey,
        checkpointFromSequence,
        checkpointRevision,
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
        encryptedEnvelope: envelope,
        keyVersion: manifest.keyVersion,
        manifest,
        objectBytes,
        objectKey: manifest.objectKey,
        objectSha256: manifest.objectSha256,
      } satisfies AuditArchiveClaimedBatch;
      envelope = undefined;
      return claimed;
    } catch {
      return fail("source_invalid");
    }
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  } finally {
    envelope?.fill(0);
  }
}

const RUNTIME_DUE_ROW_KEYS = [
  "batch_key",
  "dispatch_generation",
  "next_attempt_at",
  "status",
] as const;
const RUNTIME_CHECKPOINT_ROW_KEYS = [
  "batch_key",
  "checkpoint_id",
  "status",
] as const;

function runtimeBatchStatus(value: unknown): AuditArchiveRuntimeBatchStatus {
  if (
    value !== "corrupt" &&
    value !== "dead" &&
    value !== "pending" &&
    value !== "processing" &&
    value !== "retry"
  ) {
    fail("source_invalid");
  }
  return value;
}

function parseRuntimeReference(value: unknown): AuditArchiveRuntimeBatchReference {
  const row = exactRecord(value, RUNTIME_DUE_ROW_KEYS);
  if (row.status !== "pending" && row.status !== "retry") {
    fail("source_invalid");
  }
  canonicalTimestamp(row.next_attempt_at);
  return {
    batchKey: canonicalReference(row.batch_key),
    dispatchGeneration: boundedInteger(
      row.dispatch_generation,
      1,
      MAX_DISPATCH_GENERATION,
    ),
  };
}

export async function selectAuditArchiveRuntimeWork(
  database: D1Database,
  value: SelectAuditArchiveRuntimeWorkInput,
): Promise<AuditArchiveRuntimeWork> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["asOf", "limit"]);
    const asOf = canonicalTimestamp(input.asOf);
    const limit = boundedInteger(input.limit, 1, MAX_RUNTIME_WORK_ITEMS);
    const results = await database.batch([
      database.prepare(
        `SELECT batch_key, dispatch_generation, status, next_attempt_at
           FROM audit_archive_batch
          WHERE status IN ('pending', 'retry')
            AND next_attempt_at <= ?
          ORDER BY status, next_attempt_at, batch_key
          LIMIT ?`,
      ).bind(asOf.iso, limit + 1),
      database.prepare(
        `SELECT batch.batch_key, batch.dispatch_generation,
                batch.attempts AS attempt_number, batch.lease_id,
                batch.lease_expires_at, attempt.started_at,
                batch.updated_at, attempt.outcome
           FROM audit_archive_batch AS batch
           JOIN audit_archive_attempt AS attempt
             ON attempt.batch_key = batch.batch_key
            AND attempt.dispatch_generation = batch.dispatch_generation
            AND attempt.attempt_number = batch.attempts
            AND attempt.lease_id = batch.lease_id
          WHERE batch.status = 'processing'
            AND batch.lease_expires_at <= ?
            AND attempt.outcome = 'in_flight'
          ORDER BY batch.lease_expires_at, batch.batch_key
          LIMIT ?`,
      ).bind(asOf.iso, limit + 1),
      database.prepare(
        `SELECT checkpoint.id AS checkpoint_id,
                batch.batch_key, batch.status
           FROM audit_archive_checkpoint AS checkpoint
           LEFT JOIN audit_archive_batch AS batch
             ON batch.checkpoint_revision = checkpoint.revision
          WHERE checkpoint.id = 1
          LIMIT 2`,
      ),
    ]);
    const dueRows = exactRows(results[0], limit + 1);
    const expiredRows = exactRows(results[1], limit + 1);
    const checkpointRows = exactRows(results[2], 2);
    if (checkpointRows.length !== 1) fail("source_invalid");

    const parsedDue = dueRows.map((row) => {
      const parsed = parseRuntimeReference(row);
      const raw = exactRecord(row, RUNTIME_DUE_ROW_KEYS);
      if (canonicalTimestamp(raw.next_attempt_at).time > asOf.time) {
        fail("source_invalid");
      }
      return parsed;
    });
    const parsedExpired = expiredRows.map((row) => {
      const lease = parseLeaseRow(row);
      if (canonicalTimestamp(lease.leaseExpiresAt).time > asOf.time) {
        fail("source_invalid");
      }
      return lease;
    });
    if (
      new Set(parsedDue.map(({ batchKey }) => batchKey)).size !== parsedDue.length ||
      new Set(parsedExpired.map(({ batchKey }) => batchKey)).size !==
        parsedExpired.length
    ) {
      fail("source_invalid");
    }

    const checkpointRow = exactRecord(
      checkpointRows[0],
      RUNTIME_CHECKPOINT_ROW_KEYS,
    );
    if (checkpointRow.checkpoint_id !== 1) fail("source_invalid");
    let checkpointBatch: AuditArchiveRuntimeCheckpointBatch | null;
    if (checkpointRow.batch_key === null && checkpointRow.status === null) {
      checkpointBatch = null;
    } else if (checkpointRow.batch_key !== null && checkpointRow.status !== null) {
      checkpointBatch = {
        batchKey: canonicalReference(checkpointRow.batch_key),
        status: runtimeBatchStatus(checkpointRow.status),
      };
    } else {
      fail("source_invalid");
    }
    return {
      checkpointBatch,
      due: parsedDue.slice(0, limit),
      dueHasMore: parsedDue.length > limit,
      expired: parsedExpired.slice(0, limit),
      expiredHasMore: parsedExpired.length > limit,
    };
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
}

export async function renewAuditArchiveLease(
  database: D1Database,
  value: RenewAuditArchiveLeaseInput,
): Promise<AuditArchiveLeaseMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["lease", "leaseExpiresAt", "renewedAt"]);
    const current = parseLease(input.lease);
    const renewedAt = canonicalTimestamp(input.renewedAt);
    const leaseExpiresAt = canonicalTimestamp(input.leaseExpiresAt);
    const currentExpiry = canonicalTimestamp(current.leaseExpiresAt);
    if (
      renewedAt.time <= new Date(current.updatedAt).getTime() ||
      renewedAt.time >= currentExpiry.time ||
      leaseExpiresAt.time <= currentExpiry.time
    ) {
      fail("invalid_input");
    }
    validateLeaseWindow(renewedAt, leaseExpiresAt);
    const results = await database.batch([
      database.prepare(
        `UPDATE audit_archive_batch
            SET lease_expires_at = ?, updated_at = ?
          WHERE batch_key = ? AND status = 'processing'
            AND dispatch_generation = ? AND attempts = ?
            AND lease_id = ? AND lease_expires_at = ? AND updated_at = ?
            AND ? < lease_expires_at
            AND EXISTS (
              SELECT 1 FROM audit_archive_attempt AS attempt
               WHERE attempt.batch_key = audit_archive_batch.batch_key
                 AND attempt.dispatch_generation = ?
                 AND attempt.attempt_number = ?
                 AND attempt.lease_id = ?
                 AND attempt.started_at = ?
                 AND attempt.outcome = 'in_flight'
            )`,
      ).bind(
        leaseExpiresAt.iso,
        renewedAt.iso,
        current.batchKey,
        current.dispatchGeneration,
        current.attemptNumber,
        current.leaseId,
        current.leaseExpiresAt,
        current.updatedAt,
        renewedAt.iso,
        current.dispatchGeneration,
        current.attemptNumber,
        current.leaseId,
        current.startedAt,
      ),
      leaseProjectionStatement(
        database,
        current.batchKey,
        current.dispatchGeneration,
        current.leaseId,
        true,
      ),
      leaseProjectionStatement(
        database,
        current.batchKey,
        current.dispatchGeneration,
        current.leaseId,
        false,
      ),
    ]);
    const target: AuditArchiveLease = {
      ...current,
      leaseExpiresAt: leaseExpiresAt.iso,
      updatedAt: renewedAt.iso,
    };
    const gated = leaseFromResult(results[1]);
    const persisted = leaseFromResult(results[2]);
    if (gated !== null) {
      if (!sameLease(gated, target) || persisted === null || !sameLease(gated, persisted)) {
        fail("source_invalid");
      }
      return { lease: gated, status: "renewed" };
    }
    if (persisted !== null && sameLease(persisted, target)) {
      return { lease: persisted, status: "duplicate" };
    }
    return { lease: null, status: "conflict" };
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function adoptAuditArchiveLease(
  database: D1Database,
  value: AdoptAuditArchiveLeaseInput,
): Promise<AuditArchiveLeaseAdoptionResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["asOf", "lease"]);
    const asOf = canonicalTimestamp(input.asOf);
    const supplied = parseLease(input.lease);
    const persisted = leaseFromResult(
      await leaseProjectionStatement(
        database,
        supplied.batchKey,
        supplied.dispatchGeneration,
        supplied.leaseId,
        false,
      ).all(),
    );
    if (persisted === null || !sameLeaseFence(persisted, supplied)) {
      return { lease: null, status: "conflict" };
    }
    if (sameLease(persisted, supplied)) {
      return { lease: persisted, status: "current" };
    }
    if (
      canonicalTimestamp(persisted.updatedAt).time <=
        canonicalTimestamp(supplied.updatedAt).time ||
      canonicalTimestamp(persisted.leaseExpiresAt).time <=
        canonicalTimestamp(supplied.leaseExpiresAt).time ||
      canonicalTimestamp(persisted.updatedAt).time > asOf.time ||
      canonicalTimestamp(persisted.leaseExpiresAt).time <= asOf.time
    ) {
      return { lease: null, status: "conflict" };
    }
    return { lease: persisted, status: "adopted" };
  } catch (error) {
    throw redactedRepositoryError(error, "source_unavailable");
  }
}

type TerminalOutcome =
  | "archived"
  | "corrupt"
  | "dead"
  | "lease_expired"
  | "retry";
type TerminalStatus = "archived" | "corrupt" | "dead" | "retry";

interface TerminalIntent {
  completedAt: string;
  errorCode:
    | AuditArchiveIntegrityErrorCode
    | AuditArchiveTransientErrorCode
    | "lease_expired"
    | null;
  evidence: AuditArchiveR2ConflictEvidence | AuditArchiveR2Evidence | null;
  lease: AuditArchiveLease;
  nextAttemptAt: string | null;
  outcome: TerminalOutcome;
  resultingStatus: TerminalStatus;
}

const TRANSIENT_ERROR_CODES = new Set<string>([
  "internal_error",
  "key_unavailable",
  "queue_unavailable",
  "r2_transient",
]);
const INTEGRITY_ERROR_CODES = new Set<string>([
  "crypto_integrity",
  "r2_object_conflict",
  "r2_readback_mismatch",
]);

function safeR2Text(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    /[\u0000\n\r]/.test(value)
  ) {
    fail("invalid_input");
  }
  return value;
}

function parseR2Observation(
  value: unknown,
  requireFullReadback: boolean,
): AuditArchiveR2ConflictEvidence | AuditArchiveR2Evidence {
  const row = exactRecord(value, [
    "etag",
    "observedBytes",
    "readbackAt",
    "readbackSha256",
    "storedSha256",
    "version",
  ]);
  const readbackSha256 = nullableSha256(row.readbackSha256);
  if (requireFullReadback && readbackSha256 === null) fail("invalid_input");
  return {
    etag: safeR2Text(row.etag),
    observedBytes: boundedInteger(row.observedBytes, 0, MAX_SEQUENCE),
    readbackAt: canonicalTimestamp(row.readbackAt).iso,
    readbackSha256,
    storedSha256: nullableSha256(row.storedSha256),
    version: safeR2Text(row.version),
  };
}

function parseR2Evidence(value: unknown): AuditArchiveR2Evidence {
  const evidence = parseR2Observation(value, true);
  if (evidence.readbackSha256 === null) fail("invalid_input");
  return { ...evidence, readbackSha256: evidence.readbackSha256 };
}

function parseR2ConflictEvidence(value: unknown): AuditArchiveR2ConflictEvidence {
  return parseR2Observation(value, false);
}

function validateNormalCompletion(
  lease: AuditArchiveLease,
  completedAt: CanonicalTimestamp,
): void {
  if (
    completedAt.time <= new Date(lease.updatedAt).getTime() ||
    completedAt.time >= new Date(lease.leaseExpiresAt).getTime()
  ) {
    fail("invalid_input");
  }
}

const TERMINAL_RECEIPT_KEYS = [
  "attempt_number",
  "batch_key",
  "completed_at",
  "dispatch_generation",
  "error_code",
  "lease_id",
  "next_attempt_at",
  "outcome",
  "r2_etag",
  "r2_conflict_evidence_format",
  "r2_observed_bytes",
  "r2_readback_at",
  "r2_readback_sha256",
  "r2_stored_sha256",
  "r2_version",
  "resulting_status",
  "started_at",
] as const;

function nullableR2Text(value: unknown): string | null {
  return value === null ? null : safeR2Text(value);
}

function nullableSha256(value: unknown): string | null {
  return value === null ? null : sha256HexValue(value);
}

function nullableObservedBytes(value: unknown): number | null {
  return value === null ? null : boundedInteger(value, 0, MAX_SEQUENCE);
}

function terminalReceiptMatches(value: unknown, intent: TerminalIntent): boolean {
  try {
    const row = exactRecord(value, TERMINAL_RECEIPT_KEYS);
    return (
      canonicalReference(row.batch_key) === intent.lease.batchKey &&
      boundedInteger(row.dispatch_generation, 1, MAX_DISPATCH_GENERATION) ===
        intent.lease.dispatchGeneration &&
      boundedInteger(row.attempt_number, 1, MAX_ATTEMPTS) ===
        intent.lease.attemptNumber &&
      canonicalReference(row.lease_id) === intent.lease.leaseId &&
      canonicalTimestamp(row.started_at).iso === intent.lease.startedAt &&
      row.outcome === intent.outcome &&
      row.resulting_status === intent.resultingStatus &&
      nullableCanonicalTimestamp(row.next_attempt_at) === intent.nextAttemptAt &&
      nullableR2Text(row.r2_version) === (intent.evidence?.version ?? null) &&
      nullableR2Text(row.r2_etag) === (intent.evidence?.etag ?? null) &&
      row.r2_conflict_evidence_format ===
        (intent.errorCode === "r2_object_conflict"
          ? CURRENT_R2_CONFLICT_EVIDENCE_FORMAT
          : null) &&
      nullableObservedBytes(row.r2_observed_bytes) ===
        (intent.evidence?.observedBytes ?? null) &&
      nullableSha256(row.r2_readback_sha256) ===
        (intent.evidence?.readbackSha256 ?? null) &&
      nullableSha256(row.r2_stored_sha256) ===
        (intent.evidence?.storedSha256 ?? null) &&
      nullableCanonicalTimestamp(row.r2_readback_at) ===
        (intent.evidence?.readbackAt ?? null) &&
      row.error_code === intent.errorCode &&
      canonicalTimestamp(row.completed_at).iso === intent.completedAt
    );
  } catch {
    fail("source_invalid");
  }
}

function terminalReceiptStatement(
  database: D1Database,
  leaseId: string,
  changesGated: boolean,
): D1PreparedStatement {
  return database.prepare(
    `SELECT batch_key, dispatch_generation, attempt_number, lease_id,
            outcome, resulting_status, next_attempt_at, r2_version, r2_etag,
            r2_observed_bytes, r2_stored_sha256, r2_readback_sha256,
            r2_readback_at, r2_conflict_evidence_format, error_code,
            started_at, completed_at
       FROM audit_archive_attempt
      WHERE id = ?
        ${changesGated ? "AND changes() = 1" : ""}`,
  ).bind(leaseId);
}

const TERMINAL_BATCH_KEYS = [
  "archived_at",
  "attempts",
  "batch_generation",
  "batch_key",
  "dispatch_generation",
  "envelope_cleared",
  "envelope_gc_at",
  "last_error_code",
  "last_sequence",
  "lease_expires_at",
  "lease_id",
  "next_attempt_at",
  "r2_etag",
  "r2_readback_at",
  "r2_readback_sha256",
  "r2_version",
  "status",
  "updated_at",
] as const;

function terminalBatchMatches(value: unknown, intent: TerminalIntent): boolean {
  try {
    const row = exactRecord(value, TERMINAL_BATCH_KEYS);
    const archived = intent.outcome === "archived";
    return (
      canonicalReference(row.batch_key) === intent.lease.batchKey &&
      boundedInteger(row.dispatch_generation, 1, MAX_DISPATCH_GENERATION) ===
        intent.lease.dispatchGeneration &&
      boundedInteger(row.attempts, 1, MAX_ATTEMPTS) ===
        intent.lease.attemptNumber &&
      boundedInteger(row.batch_generation, 1, MAX_SEQUENCE) >= 1 &&
      boundedInteger(row.last_sequence, 1, MAX_SEQUENCE) >= 1 &&
      row.status === intent.resultingStatus &&
      nullableCanonicalTimestamp(row.next_attempt_at) === intent.nextAttemptAt &&
      row.lease_id === null &&
      row.lease_expires_at === null &&
      nullableR2Text(row.r2_version) ===
        (archived ? intent.evidence?.version ?? null : null) &&
      nullableR2Text(row.r2_etag) ===
        (archived ? intent.evidence?.etag ?? null : null) &&
      nullableSha256(row.r2_readback_sha256) ===
        (archived ? intent.evidence?.readbackSha256 ?? null : null) &&
      nullableCanonicalTimestamp(row.r2_readback_at) ===
        (archived ? intent.evidence?.readbackAt ?? null : null) &&
      nullableCanonicalTimestamp(row.archived_at) ===
        (archived ? intent.completedAt : null) &&
      nullableCanonicalTimestamp(row.envelope_gc_at) ===
        (archived ? intent.completedAt : null) &&
      row.last_error_code === intent.errorCode &&
      exactBooleanInteger(row.envelope_cleared) === archived &&
      canonicalTimestamp(row.updated_at).iso === intent.completedAt
    );
  } catch {
    fail("source_invalid");
  }
}

async function terminalizeAuditArchiveAttempt(
  database: D1Database,
  intent: TerminalIntent,
): Promise<AuditArchiveTerminalMutationResult> {
  const evidence = intent.evidence;
  let results: D1Result[];
  try {
    results = await database.batch([
      database.prepare(
        `UPDATE audit_archive_attempt
            SET outcome = ?, resulting_status = ?, next_attempt_at = ?,
                r2_version = ?, r2_etag = ?, r2_observed_bytes = ?,
                r2_stored_sha256 = ?, r2_readback_sha256 = ?,
                r2_readback_at = ?, r2_conflict_evidence_format = ?,
                error_code = ?, completed_at = ?
          WHERE id = ? AND batch_key = ? AND dispatch_generation = ?
            AND attempt_number = ? AND lease_id = ? AND started_at = ?
            AND outcome = 'in_flight'
            AND EXISTS (
              SELECT 1 FROM audit_archive_batch AS batch
               WHERE batch.batch_key = audit_archive_attempt.batch_key
                 AND batch.status = 'processing'
                 AND batch.dispatch_generation = ?
                 AND batch.attempts = ?
                 AND batch.lease_id = ?
                 AND batch.lease_expires_at = ?
                 AND batch.updated_at = ?
                 AND (? <> 'archived' OR (
                   batch.object_bytes = ?
                   AND batch.object_sha256 = ?
                   AND batch.object_sha256 = ?
                 ))
            )`,
      ).bind(
        intent.outcome,
        intent.resultingStatus,
        intent.nextAttemptAt,
        evidence?.version ?? null,
        evidence?.etag ?? null,
        evidence?.observedBytes ?? null,
        evidence?.storedSha256 ?? null,
        evidence?.readbackSha256 ?? null,
        evidence?.readbackAt ?? null,
        intent.errorCode === "r2_object_conflict"
          ? CURRENT_R2_CONFLICT_EVIDENCE_FORMAT
          : null,
        intent.errorCode,
        intent.completedAt,
        intent.lease.leaseId,
        intent.lease.batchKey,
        intent.lease.dispatchGeneration,
        intent.lease.attemptNumber,
        intent.lease.leaseId,
        intent.lease.startedAt,
        intent.lease.dispatchGeneration,
        intent.lease.attemptNumber,
        intent.lease.leaseId,
        intent.lease.leaseExpiresAt,
        intent.lease.updatedAt,
        intent.outcome,
        evidence?.observedBytes ?? null,
        evidence?.storedSha256 ?? null,
        evidence?.readbackSha256 ?? null,
      ),
      terminalReceiptStatement(database, intent.lease.leaseId, true),
      terminalReceiptStatement(database, intent.lease.leaseId, false),
      database.prepare(
        `SELECT batch_key, batch_generation, last_sequence,
                dispatch_generation, attempts, status, next_attempt_at,
                lease_id, lease_expires_at, r2_version, r2_etag,
                r2_readback_sha256, r2_readback_at, archived_at,
                envelope_gc_at, last_error_code, updated_at,
                encrypted_envelope IS NULL AS envelope_cleared
           FROM audit_archive_batch
          WHERE batch_key = ?`,
      ).bind(intent.lease.batchKey),
      database.prepare(
        `SELECT revision, last_sequence, last_batch_key, last_archived_at
           FROM audit_archive_checkpoint WHERE id = 1`,
      ),
    ]);
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
  const gatedRows = exactRows(results[1], 1);
  const receiptRows = exactRows(results[2], 1);
  const batchRows = exactRows(results[3], 1);
  const checkpointRows = exactRows(results[4], 1);
  const gated = gatedRows.length === 1 && terminalReceiptMatches(gatedRows[0], intent);
  const receipt =
    receiptRows.length === 1 && terminalReceiptMatches(receiptRows[0], intent);
  if (gated) {
    if (!receipt || batchRows.length !== 1 || !terminalBatchMatches(batchRows[0], intent)) {
      fail("source_invalid");
    }
    if (intent.outcome === "archived") {
      if (checkpointRows.length !== 1) fail("source_invalid");
      const checkpoint = parseCheckpointRow(checkpointRows[0]);
      const batch = exactRecord(batchRows[0], TERMINAL_BATCH_KEYS);
      if (
        checkpoint.revision !== batch.batch_generation ||
        checkpoint.lastSequence !== batch.last_sequence ||
        checkpoint.lastBatchKey !== intent.lease.batchKey ||
        checkpoint.lastArchivedAt !== intent.completedAt
      ) {
        fail("source_invalid");
      }
    }
    return "applied";
  }
  if (receipt) return "duplicate";
  return "conflict";
}

export async function finalizeAuditArchiveLease(
  database: D1Database,
  value: FinalizeAuditArchiveLeaseInput,
): Promise<AuditArchiveTerminalMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["completedAt", "evidence", "lease"]);
    const lease = parseLease(input.lease);
    const completedAt = canonicalTimestamp(input.completedAt);
    validateNormalCompletion(lease, completedAt);
    const evidence = parseR2Evidence(input.evidence);
    if (
      evidence.readbackAt !== completedAt.iso ||
      evidence.storedSha256 === null
    ) {
      fail("invalid_input");
    }
    return await terminalizeAuditArchiveAttempt(database, {
      completedAt: completedAt.iso,
      errorCode: null,
      evidence,
      lease,
      nextAttemptAt: null,
      outcome: "archived",
      resultingStatus: "archived",
    });
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function failAuditArchiveLease(
  database: D1Database,
  value: FailAuditArchiveLeaseInput,
): Promise<AuditArchiveTerminalMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, [
      "completedAt",
      "errorCode",
      "evidence",
      "lease",
      "nextAttemptAt",
    ]);
    const lease = parseLease(input.lease);
    const completedAt = canonicalTimestamp(input.completedAt);
    validateNormalCompletion(lease, completedAt);
    const errorCode = input.errorCode;
    if (typeof errorCode !== "string") fail("invalid_input");
    const integrity = INTEGRITY_ERROR_CODES.has(String(errorCode));
    const transient = TRANSIENT_ERROR_CODES.has(String(errorCode));
    if (!integrity && !transient) fail("invalid_input");
    if (integrity) {
      if (input.nextAttemptAt !== null) fail("invalid_input");
      let evidence: AuditArchiveR2ConflictEvidence | AuditArchiveR2Evidence | null;
      if (errorCode === "crypto_integrity") {
        evidence = input.evidence === null ? null : parseR2Evidence(input.evidence);
      } else if (errorCode === "r2_object_conflict") {
        if (input.evidence === null) fail("invalid_input");
        evidence = parseR2ConflictEvidence(input.evidence);
      } else if (errorCode === "r2_readback_mismatch") {
        if (input.evidence === null) fail("invalid_input");
        evidence = parseR2Evidence(input.evidence);
      } else {
        fail("invalid_input");
      }
      if (evidence !== null && evidence.readbackAt !== completedAt.iso) {
        fail("invalid_input");
      }
      return await terminalizeAuditArchiveAttempt(database, {
        completedAt: completedAt.iso,
        errorCode: errorCode as AuditArchiveIntegrityErrorCode,
        evidence,
        lease,
        nextAttemptAt: null,
        outcome: "corrupt",
        resultingStatus: "corrupt",
      });
    }
    if (input.evidence !== null) fail("invalid_input");
    const nextAttemptAt = input.nextAttemptAt === null
      ? null
      : canonicalTimestamp(input.nextAttemptAt);
    if (
      (lease.attemptNumber < MAX_ATTEMPTS &&
        (nextAttemptAt === null || nextAttemptAt.time < completedAt.time)) ||
      (lease.attemptNumber === MAX_ATTEMPTS && nextAttemptAt !== null)
    ) {
      fail("invalid_input");
    }
    const exhausted = lease.attemptNumber === MAX_ATTEMPTS;
    return await terminalizeAuditArchiveAttempt(database, {
      completedAt: completedAt.iso,
      errorCode: errorCode as AuditArchiveTransientErrorCode,
      evidence: null,
      lease,
      nextAttemptAt: nextAttemptAt?.iso ?? null,
      outcome: exhausted ? "dead" : "retry",
      resultingStatus: exhausted ? "dead" : "retry",
    });
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

export async function expireAuditArchiveLease(
  database: D1Database,
  value: ExpireAuditArchiveLeaseInput,
): Promise<AuditArchiveTerminalMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, ["completedAt", "lease", "nextAttemptAt"]);
    const lease = parseLease(input.lease);
    const completedAt = canonicalTimestamp(input.completedAt);
    if (completedAt.time < new Date(lease.leaseExpiresAt).getTime()) {
      fail("invalid_input");
    }
    const nextAttemptAt = input.nextAttemptAt === null
      ? null
      : canonicalTimestamp(input.nextAttemptAt);
    if (
      (lease.attemptNumber < MAX_ATTEMPTS &&
        (nextAttemptAt === null || nextAttemptAt.time < completedAt.time)) ||
      (lease.attemptNumber === MAX_ATTEMPTS && nextAttemptAt !== null)
    ) {
      fail("invalid_input");
    }
    const exhausted = lease.attemptNumber === MAX_ATTEMPTS;
    return await terminalizeAuditArchiveAttempt(database, {
      completedAt: completedAt.iso,
      errorCode: "lease_expired",
      evidence: null,
      lease,
      nextAttemptAt: nextAttemptAt?.iso ?? null,
      outcome: "lease_expired",
      resultingStatus: exhausted ? "dead" : "retry",
    });
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}

const REPLAY_PROJECTION_KEYS = [
  "attempts",
  "audit_event_id",
  "audit_event_type",
  "audit_metadata_json",
  "audit_occurred_at",
  "audit_outcome",
  "audit_subject_id",
  "batch_key",
  "dispatch_generation",
  "manual_replay_audit_id",
  "next_attempt_at",
  "status",
  "updated_at",
] as const;

function replayProjectionStatement(
  database: D1Database,
  auditEventId: string,
  batchKey: string,
  changesGated: boolean,
): D1PreparedStatement {
  return database.prepare(
    `SELECT batch.batch_key, batch.status, batch.dispatch_generation,
            batch.attempts, batch.next_attempt_at,
            batch.manual_replay_audit_id, batch.updated_at,
            event.id AS audit_event_id, event.event_type AS audit_event_type,
            event.subject_id AS audit_subject_id,
            event.outcome AS audit_outcome,
            event.metadata_json AS audit_metadata_json,
            event.occurred_at AS audit_occurred_at
       FROM audit_archive_batch AS batch
       JOIN audit_event AS event ON event.id = ?
      WHERE batch.batch_key = ?
        ${changesGated ? "AND changes() = 1" : ""}`,
  ).bind(auditEventId, batchKey);
}

function replayProjectionMatches(
  value: unknown,
  input: {
    auditEventId: string;
    batchKey: string;
    dispatchGeneration: number;
    nextAttemptAt: string;
    replayedAt: string;
  },
): boolean {
  try {
    const row = exactRecord(value, REPLAY_PROJECTION_KEYS);
    const status = row.status;
    if (
      status !== "pending" &&
      status !== "processing" &&
      status !== "retry" &&
      status !== "archived" &&
      status !== "dead" &&
      status !== "corrupt"
    ) {
      return false;
    }
    const generation = boundedInteger(
      row.dispatch_generation,
      1,
      MAX_DISPATCH_GENERATION,
    );
    if (
      canonicalReference(row.batch_key) !== input.batchKey ||
      generation !== input.dispatchGeneration + 1 ||
      safeIdentifier(row.manual_replay_audit_id) !== input.auditEventId ||
      safeIdentifier(row.audit_event_id) !== input.auditEventId ||
      row.audit_event_type !== "audit.archive.manual_replay" ||
      canonicalReference(row.audit_subject_id) !== input.batchKey ||
      row.audit_outcome !== "success" ||
      row.audit_metadata_json !== JSON.stringify({ dispatchGeneration: generation }) ||
      canonicalTimestamp(row.audit_occurred_at).iso !== input.replayedAt
    ) {
      return false;
    }
    if (status === "pending") {
      return (
        row.attempts === 0 &&
        canonicalTimestamp(row.next_attempt_at).iso === input.nextAttemptAt &&
        canonicalTimestamp(row.updated_at).iso === input.replayedAt
      );
    }
    boundedInteger(row.attempts, 0, MAX_ATTEMPTS);
    nullableCanonicalTimestamp(row.next_attempt_at);
    canonicalTimestamp(row.updated_at);
    return true;
  } catch {
    fail("source_invalid");
  }
}

export async function replayDeadAuditArchiveBatch(
  database: D1Database,
  value: ReplayAuditArchiveBatchInput,
): Promise<AuditArchiveTerminalMutationResult> {
  try {
    if (arguments.length !== 2) fail("invalid_input");
    const input = exactRecord(value, [
      "auditEventId",
      "batchKey",
      "dispatchGeneration",
      "nextAttemptAt",
      "replayedAt",
    ]);
    const auditEventId = safeIdentifier(input.auditEventId);
    const batchKey = canonicalReference(input.batchKey);
    const generation = boundedInteger(
      input.dispatchGeneration,
      1,
      MAX_DISPATCH_GENERATION,
    );
    if (generation >= MAX_DISPATCH_GENERATION) fail("counter_exhausted");
    const replayedAt = canonicalTimestamp(input.replayedAt);
    const nextAttemptAt = canonicalTimestamp(input.nextAttemptAt);
    if (nextAttemptAt.time < replayedAt.time) fail("invalid_input");
    const nextGeneration = generation + 1;
    const metadataJson = JSON.stringify({ dispatchGeneration: nextGeneration });
    const results = await database.batch([
      database.prepare(
        `INSERT INTO audit_event
          (id, event_type, subject_id, outcome, metadata_json, occurred_at)
         SELECT ?, 'audit.archive.manual_replay', ?, 'success', ?, ?
          WHERE NOT EXISTS (SELECT 1 FROM audit_event WHERE id = ?)
            AND EXISTS (
              SELECT 1 FROM audit_archive_batch
               WHERE batch_key = ? AND status = 'dead'
                 AND dispatch_generation = ? AND attempts = 5
                 AND updated_at < ?
            )`,
      ).bind(
        auditEventId,
        batchKey,
        metadataJson,
        replayedAt.iso,
        auditEventId,
        batchKey,
        generation,
        replayedAt.iso,
      ),
      database.prepare(
        `UPDATE audit_archive_batch
            SET status = 'pending', dispatch_generation = ?, attempts = 0,
                next_attempt_at = ?, lease_id = NULL,
                lease_expires_at = NULL, r2_version = NULL,
                archived_at = NULL, envelope_gc_at = NULL,
                last_error_code = NULL, manual_replay_audit_id = ?,
                updated_at = ?
          WHERE batch_key = ? AND status = 'dead'
            AND dispatch_generation = ? AND attempts = 5
            AND updated_at < ? AND changes() = 1
            AND EXISTS (
              SELECT 1 FROM audit_event
               WHERE id = ? AND event_type = 'audit.archive.manual_replay'
                 AND subject_id = ? AND outcome = 'success'
                 AND metadata_json = ? AND occurred_at = ?
            )`,
      ).bind(
        nextGeneration,
        nextAttemptAt.iso,
        auditEventId,
        replayedAt.iso,
        batchKey,
        generation,
        replayedAt.iso,
        auditEventId,
        batchKey,
        metadataJson,
        replayedAt.iso,
      ),
      replayProjectionStatement(database, auditEventId, batchKey, true),
      replayProjectionStatement(database, auditEventId, batchKey, false),
    ]);
    const target = {
      auditEventId,
      batchKey,
      dispatchGeneration: generation,
      nextAttemptAt: nextAttemptAt.iso,
      replayedAt: replayedAt.iso,
    };
    const gatedRows = exactRows(results[2], 1);
    const projectionRows = exactRows(results[3], 1);
    const gated =
      gatedRows.length === 1 && replayProjectionMatches(gatedRows[0], target);
    const persisted =
      projectionRows.length === 1 && replayProjectionMatches(projectionRows[0], target);
    if (gated) {
      if (!persisted) fail("source_invalid");
      return "applied";
    }
    if (persisted) return "duplicate";
    return "conflict";
  } catch (error) {
    throw redactedRepositoryError(error, "write_failed");
  }
}
