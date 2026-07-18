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
const CLOSED_RESULT_KEYS = ["outcome"] as const;
const OPENED_RESULT_KEYS = ["outcome", "records"] as const;
const PLAINTEXT_KEYS = ["contract", "records", "schemaVersion"] as const;
const STREAM_RESULT_KEYS = ["done", "value"] as const;
const AUDIT_RECORD_KEYS = [
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
] as const;
const HTTP_METADATA_REQUIRED_KEYS = ["cacheControl", "contentType"] as const;
const HTTP_METADATA_OPTIONAL_KEYS = [
  "cacheExpiry",
  "contentDisposition",
  "contentEncoding",
  "contentLanguage",
] as const;

// Capture the intrinsics used after an injected callback has run.
const REFLECT_APPLY = Reflect.apply;
const REFLECT_OWN_KEYS = Reflect.ownKeys;
const ARRAY_IS_ARRAY = Array.isArray;
const OBJECT_CREATE = Object.create;
const OBJECT_DEFINE_PROPERTIES = Object.defineProperties;
const GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const GET_PROTOTYPE_OF = Object.getPrototypeOf;
const HAS_OWN = Object.hasOwn;
const OBJECT_FREEZE = Object.freeze;
const NUMBER_IS_FINITE = Number.isFinite;
const NUMBER_IS_SAFE_INTEGER = Number.isSafeInteger;
const NUMBER_TO_STRING = Number.prototype.toString;
const REGEXP_TEST = RegExp.prototype.test;
const DATE_CONSTRUCTOR = Date;
const DATE_PARSE = Date.parse;
const DATE_TO_ISO_STRING = Date.prototype.toISOString;
const STRING_PAD_START = String.prototype.padStart;
const JSON_PARSE = JSON.parse;
const JSON_STRINGIFY = JSON.stringify;
const ARRAY_BUFFER_CONSTRUCTOR = ArrayBuffer;
const UINT8_ARRAY_CONSTRUCTOR = Uint8Array;
const UINT8_ARRAY_FILL = Uint8Array.prototype.fill;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;
const ARRAY_BUFFER_BYTE_LENGTH = GET_OWN_PROPERTY_DESCRIPTOR(
  ArrayBuffer.prototype,
  "byteLength",
)?.get;
const TYPED_ARRAY_PROTOTYPE = GET_PROTOTYPE_OF(Uint8Array.prototype);
const TYPED_ARRAY_BYTE_LENGTH = GET_OWN_PROPERTY_DESCRIPTOR(
  TYPED_ARRAY_PROTOTYPE,
  "byteLength",
)?.get;
const TYPED_ARRAY_NAME = GET_OWN_PROPERTY_DESCRIPTOR(
  TYPED_ARRAY_PROTOTYPE,
  Symbol.toStringTag,
)?.get;
const READABLE_STREAM_CANCEL = ReadableStream.prototype.cancel;
const READABLE_STREAM_GET_READER = ReadableStream.prototype.getReader;
const READER_CANCEL = ReadableStreamDefaultReader.prototype.cancel;
const READER_READ = ReadableStreamDefaultReader.prototype.read;
const READER_RELEASE_LOCK = ReadableStreamDefaultReader.prototype.releaseLock;
const TEXT_ENCODER = new TextEncoder();
const TEXT_ENCODER_ENCODE = TextEncoder.prototype.encode;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });
const TEXT_DECODER_DECODE = TextDecoder.prototype.decode;
const SUBTLE_CRYPTO = crypto.subtle;
const SUBTLE_DIGEST = crypto.subtle.digest;
const WEAK_MAP_GET = WeakMap.prototype.get;
const WEAK_MAP_SET = WeakMap.prototype.set;

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

function dataPropertyDescriptor(
  value: unknown,
  enumerable: boolean,
): PropertyDescriptor {
  const descriptor = OBJECT_CREATE(null) as PropertyDescriptor;
  descriptor.configurable = true;
  descriptor.enumerable = enumerable;
  descriptor.value = value;
  descriptor.writable = true;
  return descriptor;
}

export class AuditArchiveRestoreError extends Error {
  declare readonly code: AuditArchiveRestoreErrorCode;

  constructor(code: AuditArchiveRestoreErrorCode) {
    const message = `Audit archive restore verification failed (${code})`;
    super(message);
    const descriptors = OBJECT_CREATE(null) as PropertyDescriptorMap;
    descriptors.name = dataPropertyDescriptor(
      "AuditArchiveRestoreError",
      true,
    );
    descriptors.code = dataPropertyDescriptor(code, true);
    descriptors.message = dataPropertyDescriptor(message, false);
    OBJECT_DEFINE_PROPERTIES(this, descriptors);
  }
}
OBJECT_FREEZE(AuditArchiveRestoreError);

type RestoredAuditArchiveRecord = Readonly<AuditArchiveRecordV1>;

interface OwnDataSnapshot {
  keys: string[];
  values: unknown[];
}

// This map is provenance, not request state. Only fail() can populate it.
const LOCAL_FAILURES = new WeakMap<object, AuditArchiveRestoreErrorCode>();

function fail(code: AuditArchiveRestoreErrorCode): never {
  const error = new AuditArchiveRestoreError(code);
  REFLECT_APPLY(WEAK_MAP_SET, LOCAL_FAILURES, [error, code]);
  throw error;
}

function localFailureCode(
  value: unknown,
): AuditArchiveRestoreErrorCode | undefined {
  if (
    (typeof value !== "object" && typeof value !== "function") ||
    value === null
  ) {
    return undefined;
  }
  try {
    return REFLECT_APPLY(WEAK_MAP_GET, LOCAL_FAILURES, [value]) as
      | AuditArchiveRestoreErrorCode
      | undefined;
  } catch {
    return undefined;
  }
}

function reconstructedRestoreError(error: unknown): AuditArchiveRestoreError {
  return new AuditArchiveRestoreError(localFailureCode(error) ?? "internal_error");
}

function ownDataSnapshot(
  value: unknown,
  expectArray = false,
): OwnDataSnapshot | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  let isArray: boolean;
  let ownKeys: (string | symbol)[];
  try {
    isArray = ARRAY_IS_ARRAY(value);
    ownKeys = REFLECT_OWN_KEYS(value);
  } catch {
    return undefined;
  }
  if (isArray !== expectArray) return undefined;

  const keys: string[] = [];
  const values: unknown[] = [];
  for (let index = 0; index < ownKeys.length; index += 1) {
    const key = ownKeys[index];
    if (typeof key !== "string") return undefined;
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = GET_OWN_PROPERTY_DESCRIPTOR(value, key);
    } catch {
      return undefined;
    }
    if (!descriptor || !HAS_OWN(descriptor, "value")) return undefined;
    keys[index] = key;
    values[index] = descriptor.value;
  }
  return { keys, values };
}

function snapshotKeyIndex(snapshot: OwnDataSnapshot, key: string): number {
  for (let index = 0; index < snapshot.keys.length; index += 1) {
    if (snapshot.keys[index] === key) return index;
  }
  return -1;
}

function exactSnapshotValues(
  snapshot: OwnDataSnapshot,
  keys: readonly string[],
): unknown[] | undefined {
  if (snapshot.keys.length !== keys.length) return undefined;
  const values: unknown[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const sourceIndex = snapshotKeyIndex(snapshot, keys[index]!);
    if (sourceIndex < 0) return undefined;
    values[index] = snapshot.values[sourceIndex];
  }
  return values;
}

function exactDataValues(
  value: unknown,
  keys: readonly string[],
): unknown[] | undefined {
  const snapshot = ownDataSnapshot(value);
  return snapshot ? exactSnapshotValues(snapshot, keys) : undefined;
}

function isInterfaceObject(value: unknown): value is object {
  if (typeof value !== "object" || value === null) return false;
  try {
    return !ARRAY_IS_ARRAY(value);
  } catch {
    return false;
  }
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !NUMBER_IS_SAFE_INTEGER(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail("invalid_input");
  }
  return value;
}

function canonicalTimestamp(value: unknown): string {
  if (
    typeof value !== "string" ||
    !REFLECT_APPLY(REGEXP_TEST, ISO_TIMESTAMP_PATTERN, [value])
  ) {
    fail("invalid_input");
  }
  const time = DATE_PARSE(value);
  if (
    !NUMBER_IS_FINITE(time) ||
    REFLECT_APPLY(DATE_TO_ISO_STRING, new DATE_CONSTRUCTOR(time), []) !== value
  ) {
    fail("invalid_input");
  }
  return value;
}

function sha256HexValue(value: unknown): string {
  if (
    typeof value !== "string" ||
    !REFLECT_APPLY(REGEXP_TEST, SHA256_HEX_PATTERN, [value])
  ) {
    fail("invalid_input");
  }
  return value;
}

function keyVersion(value: unknown): string {
  if (
    typeof value !== "string" ||
    !REFLECT_APPLY(REGEXP_TEST, KEY_VERSION_PATTERN, [value])
  ) {
    fail("invalid_input");
  }
  return value;
}

function paddedSequence(value: number): string {
  return REFLECT_APPLY(STRING_PAD_START, `${value}`, [16, "0"]);
}

function expectedObjectKey(
  firstSequence: number,
  lastSequence: number,
  digest: string,
): string {
  return `audit/v1/${paddedSequence(firstSequence)}-${paddedSequence(
    lastSequence,
  )}/${digest}.pgid-audit`;
}

function canonicalManifest(value: unknown): AuditArchiveManifestV1 {
  const values = exactDataValues(value, MANIFEST_KEYS);
  if (!values) fail("invalid_input");
  if (
    values[2] !== AUDIT_ARCHIVE_CONTENT_TYPE ||
    values[3] !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
    values[13] !== 1
  ) {
    fail("invalid_input");
  }
  const firstSequence = boundedInteger(values[6], 1, Number.MAX_SAFE_INTEGER);
  const lastSequence = boundedInteger(
    values[8],
    firstSequence,
    Number.MAX_SAFE_INTEGER,
  );
  const checkpointFromSequence = boundedInteger(
    values[1],
    0,
    Number.MAX_SAFE_INTEGER,
  );
  const objectBytes = boundedInteger(
    values[9],
    1,
    AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  );
  const objectSha256 = sha256HexValue(values[11]);
  const objectKey = values[10];
  if (
    typeof objectKey !== "string" ||
    checkpointFromSequence >= firstSequence ||
    objectKey !==
      expectedObjectKey(firstSequence, lastSequence, objectSha256)
  ) {
    fail("invalid_input");
  }
  return {
    batchGeneration: boundedInteger(values[0], 1, Number.MAX_SAFE_INTEGER),
    checkpointFromSequence,
    contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
    createdAt: canonicalTimestamp(values[4]),
    eventCount: boundedInteger(values[5], 1, AUDIT_ARCHIVE_MAX_RECORDS),
    firstSequence,
    keyVersion: keyVersion(values[7]),
    lastSequence,
    objectBytes,
    objectKey,
    objectSha256,
    plaintextSha256: sha256HexValue(values[12]),
    schemaVersion: 1,
  };
}

function wipeOwnedBytes(
  bytes: Uint8Array<ArrayBufferLike> | undefined,
): void {
  if (!bytes) return;
  try {
    REFLECT_APPLY(UINT8_ARRAY_FILL, bytes, [0]);
  } catch {
    // A detached or provider-mutated owned view cannot replace the result.
  }
}

function typedArrayByteLength(value: unknown): number | undefined {
  if (!TYPED_ARRAY_BYTE_LENGTH || !TYPED_ARRAY_NAME) return undefined;
  try {
    if (REFLECT_APPLY(TYPED_ARRAY_NAME, value, []) !== "Uint8Array") {
      return undefined;
    }
    const length = REFLECT_APPLY(TYPED_ARRAY_BYTE_LENGTH, value, []);
    return typeof length === "number" && NUMBER_IS_SAFE_INTEGER(length)
      ? length
      : undefined;
  } catch {
    return undefined;
  }
}

function arrayBufferByteLength(value: unknown): number | undefined {
  if (!ARRAY_BUFFER_BYTE_LENGTH) return undefined;
  try {
    const length = REFLECT_APPLY(ARRAY_BUFFER_BYTE_LENGTH, value, []);
    return typeof length === "number" && NUMBER_IS_SAFE_INTEGER(length)
      ? length
      : undefined;
  } catch {
    return undefined;
  }
}

function copyOwnedBytes(
  source: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBuffer> | undefined {
  const byteLength = typedArrayByteLength(source);
  if (byteLength === undefined) return undefined;
  let copy: Uint8Array<ArrayBuffer> | undefined;
  try {
    copy = new UINT8_ARRAY_CONSTRUCTOR(
      new ARRAY_BUFFER_CONSTRUCTOR(byteLength),
    );
    REFLECT_APPLY(UINT8_ARRAY_SET, copy, [source]);
    return copy;
  } catch {
    wipeOwnedBytes(copy);
    return undefined;
  }
}

function copyBorrowedChecksum(
  value: unknown,
): Uint8Array<ArrayBuffer> | undefined {
  if (arrayBufferByteLength(value) !== 32) return undefined;
  let copy: Uint8Array<ArrayBuffer> | undefined;
  try {
    const source = new UINT8_ARRAY_CONSTRUCTOR(value as ArrayBuffer);
    copy = new UINT8_ARRAY_CONSTRUCTOR(new ARRAY_BUFFER_CONSTRUCTOR(32));
    REFLECT_APPLY(UINT8_ARRAY_SET, copy, [source]);
    return copy;
  } catch {
    wipeOwnedBytes(copy);
    return undefined;
  }
}

function utf8ByteLength(value: string): number {
  const bytes = REFLECT_APPLY(TEXT_ENCODER_ENCODE, TEXT_ENCODER, [
    value,
  ]) as Uint8Array<ArrayBuffer>;
  try {
    return typedArrayByteLength(bytes) ?? fail("internal_error");
  } finally {
    wipeOwnedBytes(bytes);
  }
}

function bytesToHex(bytes: Uint8Array<ArrayBufferLike>): string {
  const byteLength = typedArrayByteLength(bytes);
  if (byteLength === undefined) fail("internal_error");
  let value = "";
  for (let index = 0; index < byteLength; index += 1) {
    const encoded = REFLECT_APPLY(NUMBER_TO_STRING, bytes[index], [16]);
    value += REFLECT_APPLY(STRING_PAD_START, encoded, [2, "0"]);
  }
  return value;
}

async function sha256Hex(
  bytes: Uint8Array<ArrayBufferLike>,
): Promise<string> {
  const digestBuffer = await REFLECT_APPLY(
    SUBTLE_DIGEST,
    SUBTLE_CRYPTO,
    ["SHA-256", bytes],
  );
  const digest = new UINT8_ARRAY_CONSTRUCTOR(digestBuffer as ArrayBuffer);
  try {
    return bytesToHex(digest);
  } finally {
    wipeOwnedBytes(digest);
  }
}

function storedSha256(value: unknown): string | undefined {
  const bytes = copyBorrowedChecksum(value);
  if (!bytes) return undefined;
  try {
    return bytesToHex(bytes);
  } catch {
    return undefined;
  } finally {
    wipeOwnedBytes(bytes);
  }
}

function exactMetadata(
  httpMetadataValue: unknown,
  customMetadataValue: unknown,
  manifestJson: string,
): boolean {
  const httpMetadata = ownDataSnapshot(httpMetadataValue);
  const customMetadata = ownDataSnapshot(customMetadataValue);
  if (!httpMetadata || !customMetadata) return false;

  const customValues = exactSnapshotValues(customMetadata, [
    ARCHIVE_MANIFEST_METADATA_KEY,
  ]);
  if (!customValues || customValues[0] !== manifestJson) return false;

  if (
    httpMetadata.keys.length < HTTP_METADATA_REQUIRED_KEYS.length ||
    httpMetadata.keys.length >
      HTTP_METADATA_REQUIRED_KEYS.length + HTTP_METADATA_OPTIONAL_KEYS.length
  ) {
    return false;
  }
  for (let index = 0; index < httpMetadata.keys.length; index += 1) {
    const key = httpMetadata.keys[index]!;
    let required = false;
    for (
      let requiredIndex = 0;
      requiredIndex < HTTP_METADATA_REQUIRED_KEYS.length;
      requiredIndex += 1
    ) {
      if (key === HTTP_METADATA_REQUIRED_KEYS[requiredIndex]) required = true;
    }
    let optional = false;
    for (
      let optionalIndex = 0;
      optionalIndex < HTTP_METADATA_OPTIONAL_KEYS.length;
      optionalIndex += 1
    ) {
      if (key === HTTP_METADATA_OPTIONAL_KEYS[optionalIndex]) optional = true;
    }
    if (!required && !optional) return false;
    if (optional && httpMetadata.values[index] !== undefined) return false;
  }
  const cacheControlIndex = snapshotKeyIndex(httpMetadata, "cacheControl");
  const contentTypeIndex = snapshotKeyIndex(httpMetadata, "contentType");
  return (
    cacheControlIndex >= 0 &&
    contentTypeIndex >= 0 &&
    httpMetadata.values[cacheControlIndex] === "no-store" &&
    httpMetadata.values[contentTypeIndex] === AUDIT_ARCHIVE_CONTENT_TYPE
  );
}

async function cancelStreamBestEffort(stream: unknown): Promise<void> {
  try {
    await REFLECT_APPLY(READABLE_STREAM_CANCEL, stream, []);
  } catch {
    // Cancellation cannot replace the selected restore classification.
  }
}

async function cancelUnusedBody(object: R2ObjectBody): Promise<void> {
  let stream: unknown;
  try {
    stream = object.body;
  } catch {
    return;
  }
  await cancelStreamBestEffort(stream);
}

async function rejectUnusedObject(
  object: R2ObjectBody,
  code: AuditArchiveRestoreErrorCode,
): Promise<never> {
  await cancelUnusedBody(object);
  return fail(code);
}

async function cancelReaderBestEffort(reader: unknown): Promise<void> {
  try {
    await REFLECT_APPLY(READER_CANCEL, reader, []);
  } catch {
    // Reader cleanup cannot replace the selected restore classification.
  }
}

function releaseReaderBestEffort(reader: unknown): void {
  try {
    REFLECT_APPLY(READER_RELEASE_LOCK, reader, []);
  } catch {
    // Release is independent from cancellation and the primary result.
  }
}

async function boundedObjectRead(
  object: R2ObjectBody,
  expectedBytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const output = new UINT8_ARRAY_CONSTRUCTOR(
    new ARRAY_BUFFER_CONSTRUCTOR(expectedBytes),
  );
  let bodyUsed: unknown;
  let stream: unknown;
  try {
    bodyUsed = object.bodyUsed;
    if (bodyUsed !== false) {
      wipeOwnedBytes(output);
      return fail("stream_failed");
    }
    stream = object.body;
  } catch {
    wipeOwnedBytes(output);
    return fail("stream_failed");
  }

  let reader: unknown;
  try {
    reader = REFLECT_APPLY(READABLE_STREAM_GET_READER, stream, []);
  } catch {
    await cancelStreamBestEffort(stream);
    wipeOwnedBytes(output);
    return fail("stream_failed");
  }

  let offset = 0;
  let selectedCode: AuditArchiveRestoreErrorCode | undefined;
  while (!selectedCode) {
    let result: unknown;
    try {
      result = await REFLECT_APPLY(READER_READ, reader, []);
    } catch {
      selectedCode = "stream_failed";
      break;
    }
    const values = exactDataValues(result, STREAM_RESULT_KEYS);
    if (!values || typeof values[0] !== "boolean") {
      selectedCode = "stream_failed";
      break;
    }
    if (values[0]) {
      if (values[1] !== undefined) {
        selectedCode = "bounds_exceeded";
      } else if (offset !== expectedBytes) {
        selectedCode = "size_mismatch";
      }
      break;
    }

    const chunk = values[1];
    const chunkBytes = typedArrayByteLength(chunk);
    if (chunkBytes === undefined || chunkBytes === 0) {
      selectedCode = "stream_failed";
      break;
    }
    if (chunkBytes > expectedBytes - offset) {
      selectedCode = "bounds_exceeded";
      break;
    }
    try {
      REFLECT_APPLY(UINT8_ARRAY_SET, output, [chunk, offset]);
    } catch {
      selectedCode = "stream_failed";
      break;
    }
    offset += chunkBytes;
  }

  if (selectedCode) {
    await cancelReaderBestEffort(reader);
    releaseReaderBestEffort(reader);
    wipeOwnedBytes(output);
    return fail(selectedCode);
  }
  releaseReaderBestEffort(reader);
  return output;
}

function snapshotAuditRecord(value: unknown): AuditArchiveRecordV1 | undefined {
  const values = exactDataValues(value, AUDIT_RECORD_KEYS);
  if (!values) return undefined;
  return {
    actorRef: values[0],
    actorRefHashVersion: values[1],
    actorUserId: values[2],
    clientId: values[3],
    eventId: values[4],
    eventType: values[5],
    ipHash: values[6],
    metadataJson: values[7],
    occurredAt: values[8],
    outcome: values[9],
    sequence: values[10],
    sessionId: values[11],
    subjectId: values[12],
    userAgentHash: values[13],
  } as AuditArchiveRecordV1;
}

function snapshotAuditRecordArray(
  value: unknown,
): AuditArchiveRecordV1[] | undefined {
  const snapshot = ownDataSnapshot(value, true);
  if (!snapshot) return undefined;
  const lengthIndex = snapshotKeyIndex(snapshot, "length");
  if (lengthIndex < 0) return undefined;
  const length = snapshot.values[lengthIndex];
  if (
    typeof length !== "number" ||
    !NUMBER_IS_SAFE_INTEGER(length) ||
    length < 0 ||
    length > AUDIT_ARCHIVE_MAX_RECORDS ||
    snapshot.keys.length !== length + 1
  ) {
    return undefined;
  }

  for (let keyIndex = 0; keyIndex < snapshot.keys.length; keyIndex += 1) {
    const key = snapshot.keys[keyIndex]!;
    if (key === "length") continue;
    let matched = false;
    for (let index = 0; index < length; index += 1) {
      if (key === `${index}`) matched = true;
    }
    if (!matched) return undefined;
  }

  const records: AuditArchiveRecordV1[] = [];
  for (let index = 0; index < length; index += 1) {
    const valueIndex = snapshotKeyIndex(snapshot, `${index}`);
    if (valueIndex < 0) return undefined;
    const record = snapshotAuditRecord(snapshot.values[valueIndex]);
    if (!record) return undefined;
    records[index] = record;
  }
  return records;
}

function custodyResult(value: unknown): AuditArchiveCustodyOpenResult {
  const snapshot = ownDataSnapshot(value);
  if (!snapshot) fail("internal_error");
  const outcomeIndex = snapshotKeyIndex(snapshot, "outcome");
  if (outcomeIndex < 0) fail("internal_error");
  const outcome = snapshot.values[outcomeIndex];

  if (outcome === "crypto_integrity" || outcome === "key_unavailable") {
    if (!exactSnapshotValues(snapshot, CLOSED_RESULT_KEYS)) {
      fail("internal_error");
    }
    return { outcome };
  }
  if (outcome !== "opened") fail("internal_error");

  const values = exactSnapshotValues(snapshot, OPENED_RESULT_KEYS);
  if (!values) fail("internal_error");
  const records = snapshotAuditRecordArray(values[1]);
  if (!records) fail("record_mismatch");
  return { outcome, records };
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
    if ((await sha256Hex(plaintext)) !== manifest.plaintextSha256) {
      fail("record_mismatch");
    }

    let decoded: unknown;
    try {
      const text = REFLECT_APPLY(TEXT_DECODER_DECODE, TEXT_DECODER, [plaintext]);
      decoded = JSON_PARSE(text);
    } catch {
      return fail("record_mismatch");
    }
    const wrapper = exactDataValues(decoded, PLAINTEXT_KEYS);
    if (
      !wrapper ||
      wrapper[0] !== AUDIT_ARCHIVE_RECORDS_CONTRACT ||
      wrapper[2] !== 1
    ) {
      fail("record_mismatch");
    }
    const records = snapshotAuditRecordArray(wrapper[1]);
    if (
      !records ||
      records.length !== manifest.eventCount ||
      records[0]?.sequence !== manifest.firstSequence ||
      records[records.length - 1]?.sequence !== manifest.lastSequence
    ) {
      fail("record_mismatch");
    }
    for (let index = 0; index < records.length; index += 1) {
      OBJECT_FREEZE(records[index]!);
    }
    return OBJECT_FREEZE(records) as readonly RestoredAuditArchiveRecord[];
  } catch (error) {
    const code = localFailureCode(error);
    return fail(code === "record_mismatch" ? code : "record_mismatch");
  } finally {
    wipeOwnedBytes(plaintext);
  }
}

export async function verifyAndOpenAuditArchiveObjectV1(
  value: VerifyAndOpenAuditArchiveObjectInput,
): Promise<readonly RestoredAuditArchiveRecord[]> {
  let objectBytes: Uint8Array<ArrayBuffer> | undefined;
  let openerBytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    if (arguments.length !== 1) fail("invalid_input");
    const input = exactDataValues(value, INPUT_KEYS);
    if (!input) fail("invalid_input");

    // Validate and snapshot trusted evidence before resolving either interface.
    const manifest = canonicalManifest(input[1]);
    const manifestJson = JSON_STRINGIFY(manifest);
    if (typeof manifestJson !== "string") fail("internal_error");
    if (utf8ByteLength(manifestJson) > ARCHIVE_MAX_CUSTOM_METADATA_BYTES) {
      fail("bounds_exceeded");
    }

    const bucket = input[0];
    if (!isInterfaceObject(bucket)) fail("invalid_input");
    let getObject: unknown;
    try {
      getObject = (bucket as AuditArchiveRestoreStore).get;
    } catch {
      return fail("object_unavailable");
    }
    if (typeof getObject !== "function") fail("invalid_input");

    let objectValue: unknown;
    try {
      objectValue = await REFLECT_APPLY(getObject, bucket, [manifest.objectKey]);
    } catch {
      return fail("object_unavailable");
    }
    if (objectValue === null) fail("object_missing");
    if (!isInterfaceObject(objectValue)) fail("object_unavailable");
    const object = objectValue as R2ObjectBody;

    let reportedKey: unknown;
    try {
      reportedKey = object.key;
    } catch {
      return await rejectUnusedObject(object, "object_unavailable");
    }
    if (reportedKey !== manifest.objectKey) {
      return await rejectUnusedObject(object, "object_identity_mismatch");
    }

    let reportedSize: unknown;
    try {
      reportedSize = object.size;
    } catch {
      return await rejectUnusedObject(object, "object_unavailable");
    }
    if (
      typeof reportedSize !== "number" ||
      !NUMBER_IS_SAFE_INTEGER(reportedSize) ||
      reportedSize < 1 ||
      reportedSize > AUDIT_ARCHIVE_MAX_OBJECT_BYTES
    ) {
      return await rejectUnusedObject(object, "bounds_exceeded");
    }
    if (reportedSize !== manifest.objectBytes) {
      return await rejectUnusedObject(object, "size_mismatch");
    }

    let httpMetadata: unknown;
    let customMetadata: unknown;
    try {
      httpMetadata = object.httpMetadata;
      customMetadata = object.customMetadata;
    } catch {
      return await rejectUnusedObject(object, "object_unavailable");
    }
    if (!exactMetadata(httpMetadata, customMetadata, manifestJson)) {
      return await rejectUnusedObject(object, "metadata_mismatch");
    }

    let checksums: unknown;
    try {
      checksums = object.checksums;
    } catch {
      return await rejectUnusedObject(object, "object_unavailable");
    }
    let checksumValue: unknown;
    try {
      checksumValue = (checksums as R2Checksums | null)?.sha256;
    } catch {
      return await rejectUnusedObject(object, "checksum_mismatch");
    }
    const storedDigest = storedSha256(checksumValue);
    if (!storedDigest || storedDigest !== manifest.objectSha256) {
      return await rejectUnusedObject(object, "checksum_mismatch");
    }

    objectBytes = await boundedObjectRead(object, reportedSize);
    if (typedArrayByteLength(objectBytes) !== manifest.objectBytes) {
      fail("size_mismatch");
    }
    if ((await sha256Hex(objectBytes)) !== manifest.objectSha256) {
      fail("checksum_mismatch");
    }

    const opener = input[2];
    if (!isInterfaceObject(opener)) fail("invalid_input");
    let openObject: unknown;
    try {
      openObject = (opener as AuditArchiveCustodyOpener).open;
    } catch {
      return fail("internal_error");
    }
    if (typeof openObject !== "function") fail("invalid_input");

    openerBytes = copyOwnedBytes(objectBytes);
    if (!openerBytes) fail("internal_error");
    let openedValue: unknown;
    try {
      openedValue = await REFLECT_APPLY(openObject, opener, [
        {
          keyVersion: manifest.keyVersion,
          manifest: { ...manifest },
          objectBytes: openerBytes,
        },
      ]);
    } catch {
      return fail("internal_error");
    }
    const opened = custodyResult(openedValue);
    if (opened.outcome === "key_unavailable") fail("custody_unavailable");
    if (opened.outcome === "crypto_integrity") fail("crypto_integrity");
    return await detachedCanonicalRecords(opened.records, manifest);
  } catch (error) {
    throw reconstructedRestoreError(error);
  } finally {
    wipeOwnedBytes(openerBytes);
    wipeOwnedBytes(objectBytes);
  }
}
