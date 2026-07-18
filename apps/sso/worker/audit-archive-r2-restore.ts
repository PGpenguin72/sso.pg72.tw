import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  AUDIT_ARCHIVE_MAX_RECORDS,
  AUDIT_ARCHIVE_RECORDS_CONTRACT,
  encodeCanonicalAuditRecordsV1,
  type AuditArchiveManifestV1,
  type AuditArchiveRecordV1,
} from "./audit-archive-crypto";

const ARCHIVE_MANIFEST_METADATA_KEY = "pgid-manifest-v1";
const ARCHIVE_MAX_CUSTOM_METADATA_BYTES = 2 * 1024;
const KEY_VERSION_PATTERN = /^v[1-9][0-9]{0,5}$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
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
const INPUT_KEYS = ["bucket", "expected", "opener"] as const;
const OPENED_RESULT_KEYS = ["outcome", "records"] as const;
const CLOSED_RESULT_KEYS = ["outcome"] as const;
const PLAINTEXT_KEYS = ["contract", "records", "schemaVersion"] as const;

export interface AuditArchiveCustodyOpenInput {
  keyVersion: string;
  manifest: AuditArchiveManifestV1;
  // Borrowed module-owned copy. The verifier clears it after open settles.
  objectBytes: Uint8Array<ArrayBuffer>;
}

export type AuditArchiveCustodyOpenResult =
  | { outcome: "crypto_integrity" }
  | { outcome: "key_unavailable" }
  | {
    outcome: "opened";
    records: readonly AuditArchiveRecordV1[];
  };

export interface AuditArchiveCustodyOpener {
  open(
    input: AuditArchiveCustodyOpenInput,
  ): Promise<AuditArchiveCustodyOpenResult>;
}

// A real R2Bucket structurally satisfies this deliberately narrow read surface.
export interface AuditArchiveRestoreStore {
  get(key: string): Promise<R2ObjectBody | null>;
}

export interface VerifyAndOpenAuditArchiveObjectInput {
  bucket: AuditArchiveRestoreStore;
  expected: AuditArchiveManifestV1;
  opener: AuditArchiveCustodyOpener;
}

export type AuditArchiveRestoreErrorCode =
  | "bounds_exceeded"
  | "checksum_mismatch"
  | "crypto_integrity"
  | "custody_unavailable"
  | "internal_error"
  | "invalid_input"
  | "metadata_mismatch"
  | "object_identity_mismatch"
  | "object_missing"
  | "object_unavailable"
  | "record_mismatch"
  | "size_mismatch"
  | "stream_failed";

export class AuditArchiveRestoreError extends Error {
  readonly code: AuditArchiveRestoreErrorCode;

  constructor(code: AuditArchiveRestoreErrorCode) {
    super(`Audit archive restore verification failed (${code})`);
    this.name = "AuditArchiveRestoreError";
    this.code = code;
  }
}

type UnknownRecord = Record<string, unknown>;
type RestoredAuditArchiveRecord = Readonly<AuditArchiveRecordV1>;

function fail(code: AuditArchiveRestoreErrorCode): never {
  throw new AuditArchiveRestoreError(code);
}

function isRestoreErrorCode(value: unknown): value is AuditArchiveRestoreErrorCode {
  return (
    value === "bounds_exceeded" ||
    value === "checksum_mismatch" ||
    value === "crypto_integrity" ||
    value === "custody_unavailable" ||
    value === "internal_error" ||
    value === "invalid_input" ||
    value === "metadata_mismatch" ||
    value === "object_identity_mismatch" ||
    value === "object_missing" ||
    value === "object_unavailable" ||
    value === "record_mismatch" ||
    value === "size_mismatch" ||
    value === "stream_failed"
  );
}

function exactLocalRestoreErrorCode(
  error: unknown,
): AuditArchiveRestoreErrorCode | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  try {
    if (Object.getPrototypeOf(error) !== AuditArchiveRestoreError.prototype) {
      return undefined;
    }
    const descriptor = Object.getOwnPropertyDescriptor(error, "code");
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !isRestoreErrorCode(descriptor.value)
    ) {
      return undefined;
    }
    return descriptor.value;
  } catch {
    return undefined;
  }
}

function redactedRestoreError(error: unknown): AuditArchiveRestoreError {
  return new AuditArchiveRestoreError(
    exactLocalRestoreErrorCode(error) ?? "internal_error",
  );
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  code: AuditArchiveRestoreErrorCode,
): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code);
  }
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  ) {
    fail(code);
  }
  return value as UnknownRecord;
}

function recordValue(
  value: unknown,
  code: AuditArchiveRestoreErrorCode,
): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(code);
  }
  return value as UnknownRecord;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
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

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string" || !ISO_TIMESTAMP_PATTERN.test(value)) {
    fail("invalid_input");
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
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

function keyVersion(value: unknown): string {
  if (typeof value !== "string" || !KEY_VERSION_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
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

function canonicalManifest(value: unknown): AuditArchiveManifestV1 {
  const manifest = exactRecord(value, MANIFEST_KEYS, "invalid_input");
  if (
    manifest.contentType !== AUDIT_ARCHIVE_CONTENT_TYPE ||
    manifest.contract !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
    manifest.schemaVersion !== 1
  ) {
    fail("invalid_input");
  }
  const firstSequence = boundedInteger(
    manifest.firstSequence,
    1,
    Number.MAX_SAFE_INTEGER,
  );
  const lastSequence = boundedInteger(
    manifest.lastSequence,
    firstSequence,
    Number.MAX_SAFE_INTEGER,
  );
  const checkpointFromSequence = boundedInteger(
    manifest.checkpointFromSequence,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const objectBytes = boundedInteger(
    manifest.objectBytes,
    1,
    AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  );
  const objectSha256 = sha256HexValue(manifest.objectSha256);
  const objectKey = manifest.objectKey;
  if (
    checkpointFromSequence >= firstSequence ||
    objectKey !==
      expectedObjectKey(firstSequence, lastSequence, objectSha256)
  ) {
    fail("invalid_input");
  }
  return {
    batchGeneration: boundedInteger(
      manifest.batchGeneration,
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    checkpointFromSequence,
    contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
    createdAt: canonicalTimestamp(manifest.createdAt),
    eventCount: boundedInteger(
      manifest.eventCount,
      1,
      AUDIT_ARCHIVE_MAX_RECORDS,
    ),
    firstSequence,
    keyVersion: keyVersion(manifest.keyVersion),
    lastSequence,
    objectBytes,
    objectKey,
    objectSha256,
    plaintextSha256: sha256HexValue(manifest.plaintextSha256),
    schemaVersion: 1,
  };
}

function utf8ByteLength(value: string): number {
  const bytes = new TextEncoder().encode(value);
  try {
    return bytes.byteLength;
  } finally {
    bytes.fill(0);
  }
}

function bytesToHex(bytes: Uint8Array<ArrayBuffer>): string {
  let value = "";
  for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
  return value;
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  try {
    return bytesToHex(digest);
  } finally {
    digest.fill(0);
  }
}

function storedSha256(object: R2Object): string {
  let digest: ArrayBuffer | undefined;
  try {
    digest = object.checksums.sha256;
  } catch {
    return fail("object_unavailable");
  }
  if (!(digest instanceof ArrayBuffer) || digest.byteLength !== 32) {
    fail("checksum_mismatch");
  }
  const bytes = new Uint8Array(digest.slice(0));
  try {
    return bytesToHex(bytes);
  } finally {
    bytes.fill(0);
  }
}

function validateMetadata(object: R2Object, manifestJson: string): void {
  const httpMetadataValue = object.httpMetadata;
  const customMetadataValue = object.customMetadata;
  const httpMetadata = recordValue(
    httpMetadataValue,
    "metadata_mismatch",
  );
  const customMetadata = exactRecord(
    customMetadataValue,
    [ARCHIVE_MANIFEST_METADATA_KEY],
    "metadata_mismatch",
  );
  const allowedHttpKeys = new Set([
    "cacheControl",
    "cacheExpiry",
    "contentDisposition",
    "contentEncoding",
    "contentLanguage",
    "contentType",
  ]);
  const httpKeys = Object.keys(httpMetadata);
  if (
    httpKeys.some((key) => !allowedHttpKeys.has(key)) ||
    httpKeys.some(
      (key) =>
        key !== "cacheControl" &&
        key !== "contentType" &&
        httpMetadata[key] !== undefined,
    ) ||
    httpMetadata.cacheControl !== "no-store" ||
    httpMetadata.contentType !== AUDIT_ARCHIVE_CONTENT_TYPE ||
    customMetadata[ARCHIVE_MANIFEST_METADATA_KEY] !== manifestJson
  ) {
    fail("metadata_mismatch");
  }
}

async function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>>,
): Promise<void> {
  try {
    await reader.cancel();
  } catch {
    // Cancellation is best-effort after the bounded read has already failed.
  }
}

function releaseReader(
  reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>>,
): void {
  try {
    reader.releaseLock();
  } catch {
    // The verified result does not depend on releasing an already failed reader.
  }
}

async function boundedObjectRead(
  object: R2ObjectBody,
  expectedBytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const output = new Uint8Array(new ArrayBuffer(expectedBytes));
  let reader:
    | ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>>
    | undefined;
  let streamDone = false;
  let transferred = false;
  let offset = 0;
  try {
    if (object.bodyUsed) fail("stream_failed");
    const stream = object.body;
    if (typeof stream?.getReader !== "function") fail("stream_failed");
    reader = stream.getReader();
    while (true) {
      const result = await reader.read();
      if (result.done) {
        streamDone = true;
        if (result.value !== undefined) fail("bounds_exceeded");
        if (offset !== expectedBytes) fail("size_mismatch");
        transferred = true;
        return output;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
        fail("stream_failed");
      }
      if (chunk.byteLength > expectedBytes - offset) {
        fail("bounds_exceeded");
      }
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
  } catch (error) {
    if (reader && !streamDone) await cancelReader(reader);
    if (exactLocalRestoreErrorCode(error) !== undefined) throw error;
    return fail("stream_failed");
  } finally {
    if (!transferred) output.fill(0);
    if (reader) releaseReader(reader);
  }
}

function custodyResult(value: unknown): AuditArchiveCustodyOpenResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("internal_error");
  }
  let outcome: unknown;
  try {
    outcome = (value as UnknownRecord).outcome;
  } catch {
    return fail("internal_error");
  }
  if (outcome === "crypto_integrity" || outcome === "key_unavailable") {
    exactRecord(value, CLOSED_RESULT_KEYS, "internal_error");
    return { outcome };
  }
  if (outcome === "opened") {
    const result = exactRecord(value, OPENED_RESULT_KEYS, "internal_error");
    try {
      return {
        outcome,
        records: result.records as readonly AuditArchiveRecordV1[],
      };
    } catch {
      return fail("record_mismatch");
    }
  }
  return fail("internal_error");
}

async function detachedCanonicalRecords(
  value: readonly AuditArchiveRecordV1[],
  manifest: AuditArchiveManifestV1,
): Promise<readonly RestoredAuditArchiveRecord[]> {
  let plaintext: Uint8Array<ArrayBuffer> | undefined;
  try {
    try {
      plaintext = encodeCanonicalAuditRecordsV1(value);
    } catch {
      return fail("record_mismatch");
    }
    if (
      (await sha256Hex(plaintext)) !== manifest.plaintextSha256
    ) {
      fail("record_mismatch");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
      );
    } catch {
      return fail("record_mismatch");
    }
    const wrapper = exactRecord(decoded, PLAINTEXT_KEYS, "record_mismatch");
    if (
      wrapper.contract !== AUDIT_ARCHIVE_RECORDS_CONTRACT ||
      wrapper.schemaVersion !== 1 ||
      !Array.isArray(wrapper.records)
    ) {
      fail("record_mismatch");
    }
    const records = wrapper.records as AuditArchiveRecordV1[];
    if (
      records.length !== manifest.eventCount ||
      records[0]?.sequence !== manifest.firstSequence ||
      records.at(-1)?.sequence !== manifest.lastSequence
    ) {
      fail("record_mismatch");
    }
    return Object.freeze(
      records.map((record) => Object.freeze(record)),
    ) as readonly RestoredAuditArchiveRecord[];
  } catch (error) {
    if (exactLocalRestoreErrorCode(error) !== undefined) throw error;
    return fail("record_mismatch");
  } finally {
    plaintext?.fill(0);
  }
}

export async function verifyAndOpenAuditArchiveObjectV1(
  value: VerifyAndOpenAuditArchiveObjectInput,
): Promise<readonly RestoredAuditArchiveRecord[]> {
  let objectBytes: Uint8Array<ArrayBuffer> | undefined;
  let openerBytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    if (arguments.length !== 1) fail("invalid_input");
    const input = exactRecord(value, INPUT_KEYS, "invalid_input");
    const bucket = input.bucket as AuditArchiveRestoreStore;
    const opener = input.opener as AuditArchiveCustodyOpener;
    const getObject = bucket?.get;
    const openObject = opener?.open;
    if (
      typeof getObject !== "function" ||
      typeof openObject !== "function"
    ) {
      fail("invalid_input");
    }

    // The caller manifest is validated before it can select an object.
    const manifest = canonicalManifest(input.expected);
    const manifestJson = JSON.stringify(manifest);
    if (utf8ByteLength(manifestJson) > ARCHIVE_MAX_CUSTOM_METADATA_BYTES) {
      fail("bounds_exceeded");
    }

    let object: R2ObjectBody | null;
    try {
      object = await getObject.call(bucket, manifest.objectKey);
    } catch {
      return fail("object_unavailable");
    }
    if (object === null) fail("object_missing");

    let reportedSize: number;
    let storedDigest: string;
    try {
      const objectKey = object.key;
      const objectSize = object.size;
      if (objectKey !== manifest.objectKey) {
        fail("object_identity_mismatch");
      }
      if (
        !Number.isSafeInteger(objectSize) ||
        objectSize < 1 ||
        objectSize > AUDIT_ARCHIVE_MAX_OBJECT_BYTES
      ) {
        fail("bounds_exceeded");
      }
      reportedSize = objectSize;
      if (reportedSize !== manifest.objectBytes) fail("size_mismatch");
      validateMetadata(object, manifestJson);
      storedDigest = storedSha256(object);
    } catch (error) {
      if (exactLocalRestoreErrorCode(error) !== undefined) throw error;
      return fail("object_unavailable");
    }
    if (storedDigest !== manifest.objectSha256) fail("checksum_mismatch");

    objectBytes = await boundedObjectRead(object, reportedSize);
    if (objectBytes.byteLength !== manifest.objectBytes) fail("size_mismatch");
    if ((await sha256Hex(objectBytes)) !== manifest.objectSha256) {
      fail("checksum_mismatch");
    }

    openerBytes = objectBytes.slice();
    let opened: AuditArchiveCustodyOpenResult;
    try {
      opened = custodyResult(
        await openObject.call(opener, {
          keyVersion: manifest.keyVersion,
          manifest: { ...manifest },
          objectBytes: openerBytes,
        }),
      );
    } catch (error) {
      if (exactLocalRestoreErrorCode(error) !== undefined) throw error;
      return fail("internal_error");
    }
    if (opened.outcome === "key_unavailable") fail("custody_unavailable");
    if (opened.outcome === "crypto_integrity") fail("crypto_integrity");
    return await detachedCanonicalRecords(opened.records, manifest);
  } catch (error) {
    throw redactedRestoreError(error);
  } finally {
    openerBytes?.fill(0);
    objectBytes?.fill(0);
  }
}
