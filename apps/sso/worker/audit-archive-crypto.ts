export const AUDIT_ARCHIVE_ENVELOPE_CONTRACT = "pgid-audit-archive-v1";
export const AUDIT_ARCHIVE_RECORDS_CONTRACT = "pgid-audit-records-v1";
export const AUDIT_ARCHIVE_CONTENT_TYPE =
  "application/vnd.pg72.pgid-audit-archive+json";
export const AUDIT_ARCHIVE_MAX_RECORDS = 100;
export const AUDIT_ARCHIVE_MAX_RECORD_BYTES = 64 * 1024;
export const AUDIT_ARCHIVE_MAX_OBJECT_BYTES = 512 * 1024;
export const AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES = 384 * 1024;

const AUDIT_ARCHIVE_MAX_METADATA_BYTES = 16 * 1024;
const AES_256_BYTES = 32;
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BITS = 128;
const AES_KW_WRAPPED_256_BYTES = 40;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const KEY_VERSION_PATTERN = /^v[1-9][0-9]{0,5}$/;
const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,256}$/;
const EVENT_TYPE_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const HASH_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const CANONICAL_KEK_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const FORBIDDEN_CREDENTIAL_MARKERS = [
  `pg72_${"at"}_`,
  `pg72_${"rt"}_`,
  `pg72_${"cs"}_`,
  `PGID${"R1"}`,
] as const;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const RECORD_KEYS = [
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
const SEAL_INPUT_KEYS = [
  "batchGeneration",
  "createdAt",
  "kek",
  "keyVersion",
  "records",
] as const;
const HEADER_KEYS = [
  "batchGeneration",
  "contract",
  "createdAt",
  "encryption",
  "eventCount",
  "firstSequence",
  "keyVersion",
  "keyWrap",
  "lastSequence",
  "plaintextSha256",
  "schemaVersion",
] as const;
const ENVELOPE_KEYS = ["ciphertext", "header", "nonce", "wrappedDek"] as const;
const MANIFEST_KEYS = [
  "batchGeneration",
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
const OPEN_INPUT_KEYS = ["expected", "kek", "objectBytes"] as const;
const PLAINTEXT_KEYS = ["contract", "records", "schemaVersion"] as const;

export type AuditArchiveOutcome = "success" | "denied" | "failure";

export interface AuditArchiveRecordV1 {
  actorUserId: string | null;
  clientId: string | null;
  eventId: string;
  eventType: string;
  ipHash: string | null;
  metadataJson: string | null;
  occurredAt: string;
  outcome: AuditArchiveOutcome;
  sequence: number;
  sessionId: string | null;
  subjectId: string | null;
  userAgentHash: string | null;
}

export interface AuditArchiveSealInputV1 {
  batchGeneration: number;
  createdAt: string;
  kek: string;
  keyVersion: string;
  records: readonly AuditArchiveRecordV1[];
}

export interface AuditArchiveManifestV1 {
  batchGeneration: number;
  contentType: typeof AUDIT_ARCHIVE_CONTENT_TYPE;
  contract: typeof AUDIT_ARCHIVE_ENVELOPE_CONTRACT;
  createdAt: string;
  eventCount: number;
  firstSequence: number;
  keyVersion: string;
  lastSequence: number;
  objectBytes: number;
  objectKey: string;
  objectSha256: string;
  plaintextSha256: string;
  schemaVersion: 1;
}

export interface SealedAuditArchiveV1 {
  manifest: AuditArchiveManifestV1;
  objectBytes: Uint8Array<ArrayBuffer>;
}

export interface AuditArchiveOpenInputV1 {
  expected: AuditArchiveManifestV1;
  kek: string;
  objectBytes: Uint8Array<ArrayBuffer>;
}

export interface AuditArchiveCryptoProvider {
  getRandomValues(bytes: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
  readonly subtle: SubtleCrypto;
}

export type AuditArchiveCryptoErrorCode =
  | "bounds_exceeded"
  | "decryption_failed"
  | "encryption_failed"
  | "integrity_mismatch"
  | "invalid_input"
  | "invalid_kek";

export class AuditArchiveCryptoError extends Error {
  readonly code: AuditArchiveCryptoErrorCode;

  constructor(code: AuditArchiveCryptoErrorCode) {
    super(`Audit archive crypto failed (${code})`);
    this.name = "AuditArchiveCryptoError";
    this.code = code;
  }
}

interface ArchiveHeaderV1 {
  batchGeneration: number;
  contract: typeof AUDIT_ARCHIVE_ENVELOPE_CONTRACT;
  createdAt: string;
  encryption: "A256GCM";
  eventCount: number;
  firstSequence: number;
  keyVersion: string;
  keyWrap: "A256KW";
  lastSequence: number;
  plaintextSha256: string;
  schemaVersion: 1;
}

interface ArchiveEnvelopeV1 {
  ciphertext: string;
  header: ArchiveHeaderV1;
  nonce: string;
  wrappedDek: string;
}

interface CanonicalRecordSet {
  bytes: Uint8Array<ArrayBuffer>;
  records: AuditArchiveRecordV1[];
}

function fail(code: AuditArchiveCryptoErrorCode): never {
  throw new AuditArchiveCryptoError(code);
}

function providerOrDefault(
  provider?: AuditArchiveCryptoProvider,
): AuditArchiveCryptoProvider {
  return provider ?? {
    getRandomValues(bytes) {
      return crypto.getRandomValues(bytes);
    },
    subtle: crypto.subtle,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!isPlainObject(value)) fail("invalid_input");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail("invalid_input");
  }
  return value;
}

function safeInteger(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) {
    fail("invalid_input");
  }
  return Number(value);
}

function canonicalTimestamp(value: unknown): string {
  const timestamp = typeof value === "string" ? new Date(value) : null;
  if (
    typeof value !== "string" ||
    !ISO_TIMESTAMP_PATTERN.test(value) ||
    !timestamp ||
    !Number.isFinite(timestamp.getTime()) ||
    timestamp.toISOString() !== value
  ) {
    fail("invalid_input");
  }
  return value;
}

function containsCredentialMaterial(value: string): boolean {
  return FORBIDDEN_CREDENTIAL_MARKERS.some((marker) => value.includes(marker));
}

function safeIdentifier(value: unknown, nullable: true): string | null;
function safeIdentifier(value: unknown, nullable?: false): string;
function safeIdentifier(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (
    typeof value !== "string" ||
    !SAFE_IDENTIFIER_PATTERN.test(value) ||
    containsCredentialMaterial(value)
  ) {
    fail("invalid_input");
  }
  return value;
}

function safeHash(value: unknown): string | null {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    !HASH_PATTERN.test(value) ||
    containsCredentialMaterial(value)
  ) {
    fail("invalid_input");
  }
  return value;
}

function safeRedactedText(value: string): boolean {
  return (
    value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    !value.includes("@") &&
    !value.includes("://") &&
    !containsCredentialMaterial(value) &&
    !/(?:^|\D)(?:\d{1,3}\.){3}\d{1,3}(?:\D|$)/.test(value) &&
    !/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(value) &&
    !/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value)
  );
}

function validateMetadataJson(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string") fail("invalid_input");
  if (new TextEncoder().encode(value).byteLength > AUDIT_ARCHIVE_MAX_METADATA_BYTES) {
    fail("bounds_exceeded");
  }
  let metadata: unknown;
  try {
    metadata = JSON.parse(value);
  } catch {
    fail("invalid_input");
  }
  if (!isPlainObject(metadata) || Object.keys(metadata).length > 32) {
    fail("invalid_input");
  }
  for (const [key, child] of Object.entries(metadata)) {
    if (
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) ||
      containsCredentialMaterial(key)
    ) {
      fail("invalid_input");
    }
    if (typeof child === "string") {
      if (!safeRedactedText(child)) fail("invalid_input");
    } else if (typeof child === "number") {
      if (!Number.isSafeInteger(child)) fail("invalid_input");
    } else if (typeof child !== "boolean") {
      fail("invalid_input");
    }
  }
  return value;
}

function validatedRecord(value: unknown): AuditArchiveRecordV1 {
  const record = exactObject(value, RECORD_KEYS);
  const eventType = record.eventType;
  if (
    typeof eventType !== "string" ||
    eventType.length > 128 ||
    !EVENT_TYPE_PATTERN.test(eventType) ||
    containsCredentialMaterial(eventType)
  ) {
    fail("invalid_input");
  }
  const outcome = record.outcome;
  if (outcome !== "success" && outcome !== "denied" && outcome !== "failure") {
    fail("invalid_input");
  }
  return {
    actorUserId: safeIdentifier(record.actorUserId, true),
    clientId: safeIdentifier(record.clientId, true),
    eventId: safeIdentifier(record.eventId),
    eventType,
    ipHash: safeHash(record.ipHash),
    metadataJson: validateMetadataJson(record.metadataJson),
    occurredAt: canonicalTimestamp(record.occurredAt),
    outcome,
    sequence: safeInteger(record.sequence, 1),
    sessionId: safeIdentifier(record.sessionId, true),
    subjectId: safeIdentifier(record.subjectId, true),
    userAgentHash: safeHash(record.userAgentHash),
  };
}

function canonicalRecordSet(value: unknown): CanonicalRecordSet {
  if (!Array.isArray(value) || value.length === 0) fail("invalid_input");
  if (value.length > AUDIT_ARCHIVE_MAX_RECORDS) fail("bounds_exceeded");
  const records = value.map(validatedRecord);
  const eventIds = new Set<string>();
  let previousSequence = 0;
  let cumulativeBytes = 0;
  for (const record of records) {
    if (record.sequence <= previousSequence || eventIds.has(record.eventId)) {
      fail("invalid_input");
    }
    previousSequence = record.sequence;
    eventIds.add(record.eventId);
    const recordBytes = new TextEncoder().encode(JSON.stringify(record)).byteLength;
    if (recordBytes > AUDIT_ARCHIVE_MAX_RECORD_BYTES) fail("bounds_exceeded");
    cumulativeBytes += recordBytes;
    if (cumulativeBytes > AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES) {
      fail("bounds_exceeded");
    }
  }
  const bytes = new TextEncoder().encode(
    JSON.stringify({
      contract: AUDIT_ARCHIVE_RECORDS_CONTRACT,
      records,
      schemaVersion: 1,
    }),
  );
  if (bytes.byteLength > AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES) {
    fail("bounds_exceeded");
  }
  return { bytes, records };
}

export function encodeCanonicalAuditRecordsV1(
  records: readonly AuditArchiveRecordV1[],
): Uint8Array<ArrayBuffer> {
  return canonicalRecordSet(records).bytes;
}

function bytesToBase64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function base64UrlToBytes(
  value: unknown,
  expectedLength?: number,
): Uint8Array<ArrayBuffer> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value)
  ) {
    fail("invalid_input");
  }
  let binary: string;
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(
      normalized.padEnd(
        normalized.length + ((4 - (normalized.length % 4)) % 4),
        "=",
      ),
    );
  } catch {
    fail("invalid_input");
  }
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  if (
    (expectedLength !== undefined && bytes.byteLength !== expectedLength) ||
    bytesToBase64Url(bytes) !== value
  ) {
    fail("invalid_input");
  }
  return bytes;
}

function parseKek(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !CANONICAL_KEK_PATTERN.test(value)) {
    fail("invalid_kek");
  }
  try {
    return base64UrlToBytes(value, AES_256_BYTES);
  } catch {
    fail("invalid_kek");
  }
}

function bytesToHex(bytes: Uint8Array<ArrayBuffer>): string {
  let value = "";
  for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
  return value;
}

async function sha256Hex(
  subtle: SubtleCrypto,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<string> {
  return bytesToHex(new Uint8Array(await subtle.digest("SHA-256", bytes)));
}

function canonicalHeader(value: {
  batchGeneration: number;
  createdAt: string;
  eventCount: number;
  firstSequence: number;
  keyVersion: string;
  lastSequence: number;
  plaintextSha256: string;
}): ArchiveHeaderV1 {
  return {
    batchGeneration: value.batchGeneration,
    contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
    createdAt: value.createdAt,
    encryption: "A256GCM",
    eventCount: value.eventCount,
    firstSequence: value.firstSequence,
    keyVersion: value.keyVersion,
    keyWrap: "A256KW",
    lastSequence: value.lastSequence,
    plaintextSha256: value.plaintextSha256,
    schemaVersion: 1,
  };
}

function headerBytes(header: ArchiveHeaderV1): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(header));
}

function objectKey(firstSequence: number, lastSequence: number, digest: string): string {
  if (!SHA256_HEX_PATTERN.test(digest)) fail("integrity_mismatch");
  return `audit/v1/${String(firstSequence).padStart(16, "0")}-${String(
    lastSequence,
  ).padStart(16, "0")}/${digest}.pgid-audit`;
}

function randomBytes(
  length: number,
  provider: AuditArchiveCryptoProvider,
): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(length));
  const result = provider.getRandomValues(bytes);
  if (result !== bytes || result.byteLength !== length) fail("invalid_input");
  return bytes;
}

function canonicalEnvelopeBytes(
  envelope: ArchiveEnvelopeV1,
): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    JSON.stringify({
      ciphertext: envelope.ciphertext,
      header: envelope.header,
      nonce: envelope.nonce,
      wrappedDek: envelope.wrappedDek,
    }),
  );
}

function validatedKeyVersion(value: unknown): string {
  if (typeof value !== "string" || !KEY_VERSION_PATTERN.test(value)) {
    fail("invalid_input");
  }
  return value;
}

function validatedHeader(value: unknown): ArchiveHeaderV1 {
  const header = exactObject(value, HEADER_KEYS);
  if (
    header.contract !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
    header.schemaVersion !== 1 ||
    header.encryption !== "A256GCM" ||
    header.keyWrap !== "A256KW" ||
    typeof header.plaintextSha256 !== "string" ||
    !SHA256_HEX_PATTERN.test(header.plaintextSha256)
  ) {
    fail("invalid_input");
  }
  const firstSequence = safeInteger(header.firstSequence, 1);
  const lastSequence = safeInteger(header.lastSequence, 1);
  const eventCount = safeInteger(header.eventCount, 1);
  if (lastSequence < firstSequence || eventCount > AUDIT_ARCHIVE_MAX_RECORDS) {
    fail("invalid_input");
  }
  return canonicalHeader({
    batchGeneration: safeInteger(header.batchGeneration, 1),
    createdAt: canonicalTimestamp(header.createdAt),
    eventCount,
    firstSequence,
    keyVersion: validatedKeyVersion(header.keyVersion),
    lastSequence,
    plaintextSha256: header.plaintextSha256,
  });
}

function validatedManifest(value: unknown): AuditArchiveManifestV1 {
  const manifest = exactObject(value, MANIFEST_KEYS);
  if (
    manifest.contract !== AUDIT_ARCHIVE_ENVELOPE_CONTRACT ||
    manifest.schemaVersion !== 1 ||
    manifest.contentType !== AUDIT_ARCHIVE_CONTENT_TYPE ||
    typeof manifest.objectSha256 !== "string" ||
    !SHA256_HEX_PATTERN.test(manifest.objectSha256) ||
    typeof manifest.plaintextSha256 !== "string" ||
    !SHA256_HEX_PATTERN.test(manifest.plaintextSha256) ||
    typeof manifest.objectKey !== "string"
  ) {
    fail("invalid_input");
  }
  const firstSequence = safeInteger(manifest.firstSequence, 1);
  const lastSequence = safeInteger(manifest.lastSequence, 1);
  const eventCount = safeInteger(manifest.eventCount, 1);
  const objectBytes = safeInteger(manifest.objectBytes, 1);
  if (
    lastSequence < firstSequence ||
    eventCount > AUDIT_ARCHIVE_MAX_RECORDS ||
    objectBytes > AUDIT_ARCHIVE_MAX_OBJECT_BYTES
  ) {
    fail("invalid_input");
  }
  return {
    batchGeneration: safeInteger(manifest.batchGeneration, 1),
    contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
    createdAt: canonicalTimestamp(manifest.createdAt),
    eventCount,
    firstSequence,
    keyVersion: validatedKeyVersion(manifest.keyVersion),
    lastSequence,
    objectBytes,
    objectKey: manifest.objectKey,
    objectSha256: manifest.objectSha256,
    plaintextSha256: manifest.plaintextSha256,
    schemaVersion: 1,
  };
}

function bytesEqual(
  left: Uint8Array<ArrayBuffer>,
  right: Uint8Array<ArrayBuffer>,
): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export async function sealAuditArchiveV1(
  value: AuditArchiveSealInputV1,
  cryptoProvider?: AuditArchiveCryptoProvider,
): Promise<SealedAuditArchiveV1> {
  const input = exactObject(value, SEAL_INPUT_KEYS);
  const batchGeneration = safeInteger(input.batchGeneration, 1);
  const createdAt = canonicalTimestamp(input.createdAt);
  const keyVersion = validatedKeyVersion(input.keyVersion);
  const canonical = canonicalRecordSet(input.records);
  const firstSequence = canonical.records[0]?.sequence;
  const lastSequence = canonical.records.at(-1)?.sequence;
  if (firstSequence === undefined || lastSequence === undefined) {
    fail("invalid_input");
  }
  const provider = providerOrDefault(cryptoProvider);
  const kekBytes = parseKek(input.kek);
  const dekBytes = randomBytes(AES_256_BYTES, provider);
  const nonce = randomBytes(AES_GCM_NONCE_BYTES, provider);
  try {
    const plaintextSha256 = await sha256Hex(provider.subtle, canonical.bytes);
    const header = canonicalHeader({
      batchGeneration,
      createdAt,
      eventCount: canonical.records.length,
      firstSequence,
      keyVersion,
      lastSequence,
      plaintextSha256,
    });
    const [kek, dek] = await Promise.all([
      provider.subtle.importKey(
        "raw",
        kekBytes,
        { name: "AES-KW" },
        false,
        ["wrapKey", "unwrapKey"],
      ),
      provider.subtle.importKey(
        "raw",
        dekBytes,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"],
      ),
    ]);
    const [wrappedDekBuffer, ciphertextBuffer] = await Promise.all([
      provider.subtle.wrapKey("raw", dek, kek, { name: "AES-KW" }),
      provider.subtle.encrypt(
        {
          additionalData: headerBytes(header),
          iv: nonce,
          name: "AES-GCM",
          tagLength: AES_GCM_TAG_BITS,
        },
        dek,
        canonical.bytes,
      ),
    ]);
    const wrappedDek = new Uint8Array(wrappedDekBuffer);
    if (wrappedDek.byteLength !== AES_KW_WRAPPED_256_BYTES) {
      fail("integrity_mismatch");
    }
    const objectBytes = canonicalEnvelopeBytes({
      ciphertext: bytesToBase64Url(new Uint8Array(ciphertextBuffer)),
      header,
      nonce: bytesToBase64Url(nonce),
      wrappedDek: bytesToBase64Url(wrappedDek),
    });
    if (objectBytes.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
      fail("bounds_exceeded");
    }
    const objectSha256 = await sha256Hex(provider.subtle, objectBytes);
    const manifest: AuditArchiveManifestV1 = {
      batchGeneration,
      contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
      createdAt,
      eventCount: canonical.records.length,
      firstSequence,
      keyVersion,
      lastSequence,
      objectBytes: objectBytes.byteLength,
      objectKey: objectKey(firstSequence, lastSequence, objectSha256),
      objectSha256,
      plaintextSha256,
      schemaVersion: 1,
    };
    return { manifest, objectBytes };
  } catch (error) {
    if (error instanceof AuditArchiveCryptoError) throw error;
    fail("encryption_failed");
  } finally {
    canonical.bytes.fill(0);
    dekBytes.fill(0);
    kekBytes.fill(0);
  }
}

function decodeObjectBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array)) fail("invalid_input");
  if (value.byteLength === 0 || value.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES) {
    fail("bounds_exceeded");
  }
  return new Uint8Array(value);
}

function parseJsonBytes(bytes: Uint8Array<ArrayBuffer>): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail("invalid_input");
  }
}

function validatedEnvelope(value: unknown): ArchiveEnvelopeV1 {
  const envelope = exactObject(value, ENVELOPE_KEYS);
  const header = validatedHeader(envelope.header);
  const nonce = base64UrlToBytes(envelope.nonce, AES_GCM_NONCE_BYTES);
  const wrappedDek = base64UrlToBytes(
    envelope.wrappedDek,
    AES_KW_WRAPPED_256_BYTES,
  );
  const ciphertext = base64UrlToBytes(envelope.ciphertext);
  if (ciphertext.byteLength <= AES_GCM_TAG_BITS / 8) fail("invalid_input");
  return {
    ciphertext: bytesToBase64Url(ciphertext),
    header,
    nonce: bytesToBase64Url(nonce),
    wrappedDek: bytesToBase64Url(wrappedDek),
  };
}

function manifestMatchesHeader(
  manifest: AuditArchiveManifestV1,
  header: ArchiveHeaderV1,
): boolean {
  return (
    manifest.batchGeneration === header.batchGeneration &&
    manifest.contract === header.contract &&
    manifest.createdAt === header.createdAt &&
    manifest.eventCount === header.eventCount &&
    manifest.firstSequence === header.firstSequence &&
    manifest.keyVersion === header.keyVersion &&
    manifest.lastSequence === header.lastSequence &&
    manifest.plaintextSha256 === header.plaintextSha256 &&
    manifest.schemaVersion === header.schemaVersion
  );
}

export async function openAuditArchiveV1(
  value: AuditArchiveOpenInputV1,
  cryptoProvider?: AuditArchiveCryptoProvider,
): Promise<readonly AuditArchiveRecordV1[]> {
  const input = exactObject(value, OPEN_INPUT_KEYS);
  const objectBytes = decodeObjectBytes(input.objectBytes);
  const manifest = validatedManifest(input.expected);
  const provider = providerOrDefault(cryptoProvider);
  const objectSha256 = await sha256Hex(provider.subtle, objectBytes);
  if (
    objectBytes.byteLength !== manifest.objectBytes ||
    objectSha256 !== manifest.objectSha256 ||
    objectKey(manifest.firstSequence, manifest.lastSequence, objectSha256) !==
      manifest.objectKey
  ) {
    fail("integrity_mismatch");
  }
  const envelope = validatedEnvelope(parseJsonBytes(objectBytes));
  if (
    !bytesEqual(canonicalEnvelopeBytes(envelope), objectBytes) ||
    !manifestMatchesHeader(manifest, envelope.header)
  ) {
    fail("integrity_mismatch");
  }
  const kekBytes = parseKek(input.kek);
  const nonce = base64UrlToBytes(envelope.nonce, AES_GCM_NONCE_BYTES);
  const wrappedDek = base64UrlToBytes(
    envelope.wrappedDek,
    AES_KW_WRAPPED_256_BYTES,
  );
  const ciphertext = base64UrlToBytes(envelope.ciphertext);
  let plaintext: Uint8Array<ArrayBuffer> | undefined;
  try {
    const kek = await provider.subtle.importKey(
      "raw",
      kekBytes,
      { name: "AES-KW" },
      false,
      ["unwrapKey"],
    );
    const dek = await provider.subtle.unwrapKey(
      "raw",
      wrappedDek,
      kek,
      { name: "AES-KW" },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    plaintext = new Uint8Array(
      await provider.subtle.decrypt(
        {
          additionalData: headerBytes(envelope.header),
          iv: nonce,
          name: "AES-GCM",
          tagLength: AES_GCM_TAG_BITS,
        },
        dek,
        ciphertext,
      ),
    );
  } catch {
    fail("decryption_failed");
  } finally {
    kekBytes.fill(0);
  }
  try {
    if (
      plaintext.byteLength > AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES ||
      (await sha256Hex(provider.subtle, plaintext)) !== manifest.plaintextSha256
    ) {
      fail("integrity_mismatch");
    }
    const parsed = exactObject(parseJsonBytes(plaintext), PLAINTEXT_KEYS);
    if (
      parsed.contract !== AUDIT_ARCHIVE_RECORDS_CONTRACT ||
      parsed.schemaVersion !== 1
    ) {
      fail("invalid_input");
    }
    const canonical = canonicalRecordSet(parsed.records);
    try {
      if (
        !bytesEqual(canonical.bytes, plaintext) ||
        canonical.records.length !== manifest.eventCount ||
        canonical.records[0]?.sequence !== manifest.firstSequence ||
        canonical.records.at(-1)?.sequence !== manifest.lastSequence
      ) {
        fail("integrity_mismatch");
      }
      return canonical.records;
    } finally {
      canonical.bytes.fill(0);
    }
  } finally {
    plaintext.fill(0);
  }
}
