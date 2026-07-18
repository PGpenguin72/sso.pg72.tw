import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  type AuditArchiveManifestV1,
} from "./audit-archive-crypto";
import {
  AuditArchiveRepositoryError,
  expireAuditArchiveLease,
  failAuditArchiveLease,
  finalizeAuditArchiveLease,
  readClaimedAuditArchiveBatch,
  renewAuditArchiveLease,
  type AuditArchiveLease,
  type AuditArchiveR2ConflictEvidence,
  type AuditArchiveR2Evidence,
  type AuditArchiveTerminalMutationResult,
  type AuditArchiveTransientErrorCode,
} from "./audit-archive-repository";

const ARCHIVE_MANIFEST_METADATA_KEY = "pgid-manifest-v1";
const ARCHIVE_MAX_CUSTOM_METADATA_BYTES = 2 * 1024;
const LEASE_RENEWAL_THRESHOLD_MS = 60 * 1_000;
const MAX_LEASE_MS = 300 * 1_000;
const RETRY_DELAY_SECONDS = [30, 120, 480, 900] as const;
const SAFE_R2_TEXT_PATTERN = /^[^\u0000\n\r]{1,256}$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export type AuditArchiveEnvelopeVerification =
  | "crypto_integrity"
  | "key_unavailable"
  | "verified";

export interface AuditArchiveEnvelopeVerificationInput {
  keyVersion: string;
  manifest: AuditArchiveManifestV1;
  objectBytes: Uint8Array<ArrayBuffer>;
}

export interface AuditArchiveEnvelopeVerifier {
  verify(
    input: AuditArchiveEnvelopeVerificationInput,
  ): Promise<AuditArchiveEnvelopeVerification>;
}

// A real R2Bucket structurally satisfies this deliberately narrow binding surface.
export interface AuditArchiveR2Store {
  get(key: string): Promise<R2ObjectBody | null>;
  put(
    key: string,
    value: Uint8Array<ArrayBuffer>,
    options: R2PutOptions & { onlyIf: Headers },
  ): Promise<R2Object | null>;
}

export interface WriteClaimedAuditArchiveInput {
  bucket: AuditArchiveR2Store;
  database: D1Database;
  lease: AuditArchiveLease;
  now: () => string;
  verifier: AuditArchiveEnvelopeVerifier;
}

export type AuditArchiveR2PutOutcome =
  | "created"
  | "precondition_failed"
  | "response_uncertain";

export type AuditArchiveR2WriterOutcome =
  | "archived"
  | "corrupt"
  | "dead"
  | "lease_expired"
  | "lease_lost"
  | "retry";

export interface AuditArchiveR2WriterResult {
  errorCode:
    | AuditArchiveTransientErrorCode
    | "crypto_integrity"
    | "lease_expired"
    | "r2_object_conflict"
    | "r2_readback_mismatch"
    | null;
  mutation: AuditArchiveTerminalMutationResult | null;
  outcome: AuditArchiveR2WriterOutcome;
  putOutcome: AuditArchiveR2PutOutcome | null;
}

export class AuditArchiveR2WriterError extends Error {
  readonly code: "invalid_input";

  constructor() {
    super("Audit archive R2 writer failed (invalid_input)");
    this.name = "AuditArchiveR2WriterError";
    this.code = "invalid_input";
  }
}

interface CanonicalTimestamp {
  iso: string;
  time: number;
}

interface WriterExecutionInput extends WriteClaimedAuditArchiveInput {
  readNow: () => CanonicalTimestamp;
}

type R2EvidenceWithoutTime = Omit<AuditArchiveR2Evidence, "readbackAt">;
type R2ConflictEvidenceWithoutTime = Omit<
  AuditArchiveR2ConflictEvidence,
  "readbackAt"
>;

interface FullR2Observation {
  body: Uint8Array<ArrayBuffer>;
  evidence: R2EvidenceWithoutTime;
  metadataMatches: boolean;
}

interface PartialR2Observation {
  evidence: R2ConflictEvidenceWithoutTime;
}

type R2Observation =
  | { kind: "full"; value: FullR2Observation }
  | { kind: "partial"; value: PartialR2Observation }
  | { kind: "transient" };

type LeaseReadiness =
  | { input: WriterExecutionInput; kind: "ready" }
  | { kind: "terminal"; result: AuditArchiveR2WriterResult };

function invalidInput(): never {
  throw new AuditArchiveR2WriterError();
}

function canonicalTimestamp(value: unknown): CanonicalTimestamp {
  if (typeof value !== "string" || !ISO_TIMESTAMP_PATTERN.test(value)) {
    return invalidInput();
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    return invalidInput();
  }
  return { iso: value, time };
}

function canonicalNow(now: () => string): CanonicalTimestamp {
  if (typeof now !== "function") return invalidInput();
  try {
    return canonicalTimestamp(now());
  } catch (error) {
    if (error instanceof AuditArchiveR2WriterError) throw error;
    return invalidInput();
  }
}

function safeR2Text(value: unknown): string | null {
  return typeof value === "string" && SAFE_R2_TEXT_PATTERN.test(value)
    ? value
    : null;
}

function bytesToHex(bytes: Uint8Array<ArrayBuffer>): string {
  let value = "";
  for (const byte of bytes) value += byte.toString(16).padStart(2, "0");
  return value;
}

function sha256BytesFromHex(value: string): Uint8Array<ArrayBuffer> {
  if (!SHA256_HEX_PATTERN.test(value)) return invalidInput();
  const bytes = new Uint8Array(new ArrayBuffer(32));
  for (let index = 0; index < bytes.byteLength; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesEqual(
  left: Uint8Array<ArrayBuffer>,
  right: Uint8Array<ArrayBuffer>,
): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function storedSha256(checksums: R2Checksums): {
  valid: boolean;
  value: string | null;
} {
  const digest = checksums.sha256;
  if (digest === undefined) return { valid: true, value: null };
  if (!(digest instanceof ArrayBuffer) || digest.byteLength !== 32) {
    return { valid: false, value: null };
  }
  return {
    valid: true,
    value: bytesToHex(new Uint8Array(digest)),
  };
}

function exactMetadata(
  object: R2Object,
  manifestJson: string,
): boolean {
  const httpMetadata = object.httpMetadata;
  const customMetadata = object.customMetadata;
  if (httpMetadata === undefined || customMetadata === undefined) return false;
  const allowedHttpKeys = new Set([
    "cacheControl",
    "cacheExpiry",
    "contentDisposition",
    "contentEncoding",
    "contentLanguage",
    "contentType",
  ]);
  const httpKeys = Object.keys(httpMetadata);
  const customKeys = Object.keys(customMetadata).toSorted();
  return (
    httpKeys.every((key) => allowedHttpKeys.has(key)) &&
    httpKeys.every(
      (key) =>
        key === "cacheControl" ||
        key === "contentType" ||
        httpMetadata[key as keyof R2HTTPMetadata] === undefined,
    ) &&
    httpMetadata.cacheControl === "no-store" &&
    httpMetadata.contentType === AUDIT_ARCHIVE_CONTENT_TYPE &&
    customKeys.length === 1 &&
    customKeys[0] === ARCHIVE_MANIFEST_METADATA_KEY &&
    customMetadata[ARCHIVE_MANIFEST_METADATA_KEY] === manifestJson
  );
}

async function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>>,
): Promise<void> {
  try {
    await reader.cancel();
  } catch {
    // Cancellation is best-effort after a bounded read has already failed.
  }
}

async function abortDigestWriter(
  writer: WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>,
): Promise<void> {
  try {
    await writer.abort();
  } catch {
    // Digest cleanup is best-effort after the bounded observation has failed.
  }
}

function createDigestStream(): DigestStream {
  // Wrangler emits Crypto.DigestStream, but lib.webworker's global Crypto type
  // does not merge that runtime member into the `crypto` value.
  const constructor: unknown = Reflect.get(crypto, "DigestStream");
  if (typeof constructor !== "function") throw new Error("digest_unavailable");
  return new (constructor as typeof DigestStream)("SHA-256");
}

async function boundedRead(
  object: R2ObjectBody,
): Promise<
  | { bytes: Uint8Array<ArrayBuffer>; sha256: string }
  | "partial"
  | "transient"
> {
  if (
    !Number.isSafeInteger(object.size) ||
    object.size < 1 ||
    object.size > AUDIT_ARCHIVE_MAX_OBJECT_BYTES ||
    object.bodyUsed
  ) {
    return "partial";
  }
  const output = new Uint8Array(new ArrayBuffer(object.size));
  const stream: ReadableStream<Uint8Array<ArrayBufferLike>> = object.body;
  const reader = stream.getReader();
  const digestStream = createDigestStream();
  const digestWriter = digestStream.getWriter();
  const digestPromise = digestStream.digest;
  let offset = 0;
  let completed = false;
  let digestClosed = false;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        completed = true;
        break;
      }
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array) || chunk.byteLength === 0) {
        await cancelReader(reader);
        await abortDigestWriter(digestWriter);
        return "transient";
      }
      if (
        offset + chunk.byteLength > object.size ||
        offset + chunk.byteLength > AUDIT_ARCHIVE_MAX_OBJECT_BYTES
      ) {
        await cancelReader(reader);
        await abortDigestWriter(digestWriter);
        return "partial";
      }
      await digestWriter.write(chunk);
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (offset !== object.size) {
      await abortDigestWriter(digestWriter);
      return "transient";
    }
    await digestWriter.close();
    digestClosed = true;
    const completeBody = output.slice(0, offset);
    let digest: Uint8Array<ArrayBuffer> | undefined;
    try {
      digest = new Uint8Array(await digestPromise);
      return {
        bytes: completeBody,
        sha256: bytesToHex(digest),
      };
    } catch {
      completeBody.fill(0);
      return "transient";
    } finally {
      digest?.fill(0);
    }
  } catch {
    await cancelReader(reader);
    await abortDigestWriter(digestWriter);
    return "transient";
  } finally {
    output.fill(0);
    if (!completed) await cancelReader(reader);
    if (!digestClosed) {
      await abortDigestWriter(digestWriter);
      try {
        await digestPromise;
      } catch {
        // The digest promise rejects when its writer is deliberately aborted.
      }
    }
    reader.releaseLock();
  }
}

async function observeR2Object(
  object: R2ObjectBody,
  manifest: AuditArchiveManifestV1,
  manifestJson: string,
): Promise<R2Observation> {
  const etag = safeR2Text(object.etag);
  const version = safeR2Text(object.version);
  if (
    etag === null ||
    version === null ||
    !Number.isSafeInteger(object.size) ||
    object.size < 0
  ) {
    return { kind: "transient" };
  }
  const checksum = storedSha256(object.checksums);
  const base = {
    etag,
    observedBytes: object.size,
    storedSha256: checksum.value,
    version,
  };
  if (
    object.size < 1 ||
    object.size > AUDIT_ARCHIVE_MAX_OBJECT_BYTES ||
    !checksum.valid
  ) {
    return {
      kind: "partial",
      value: { evidence: { ...base, readbackSha256: null } },
    };
  }
  const read = await boundedRead(object);
  if (read === "transient") return { kind: "transient" };
  if (read === "partial") {
    return {
      kind: "partial",
      value: { evidence: { ...base, readbackSha256: null } },
    };
  }
  return {
    kind: "full",
    value: {
      body: read.bytes,
      evidence: { ...base, readbackSha256: read.sha256 },
      metadataMatches:
        object.key === manifest.objectKey &&
        object.size === manifest.objectBytes &&
        exactMetadata(object, manifestJson),
    },
  };
}

async function verifyEnvelope(
  verifier: AuditArchiveEnvelopeVerifier,
  value: AuditArchiveEnvelopeVerificationInput,
): Promise<AuditArchiveEnvelopeVerification | "internal_error"> {
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  try {
    bytes = new Uint8Array(value.objectBytes);
    const result = await verifier.verify({
      ...value,
      manifest: { ...value.manifest },
      objectBytes: bytes,
    });
    return result === "verified" ||
      result === "key_unavailable" ||
      result === "crypto_integrity"
      ? result
      : "internal_error";
  } catch {
    return "internal_error";
  } finally {
    bytes?.fill(0);
  }
}

function retryAt(lease: AuditArchiveLease, completedAt: CanonicalTimestamp): string | null {
  if (lease.attemptNumber >= 5) return null;
  const seconds = RETRY_DELAY_SECONDS[lease.attemptNumber - 1];
  if (seconds === undefined) return invalidInput();
  return new Date(completedAt.time + seconds * 1_000).toISOString();
}

function resultForMutation(
  mutation: AuditArchiveTerminalMutationResult,
  result: Omit<AuditArchiveR2WriterResult, "mutation" | "outcome"> & {
    outcome: Exclude<AuditArchiveR2WriterOutcome, "lease_lost">;
  },
): AuditArchiveR2WriterResult {
  return mutation === "conflict"
    ? { ...result, mutation, outcome: "lease_lost" }
    : { ...result, mutation };
}

async function expireLease(
  input: WriterExecutionInput,
  completedAt: CanonicalTimestamp,
  putOutcome: AuditArchiveR2PutOutcome | null,
): Promise<AuditArchiveR2WriterResult> {
  const mutation = await expireAuditArchiveLease(input.database, {
    completedAt: completedAt.iso,
    lease: input.lease,
    nextAttemptAt: retryAt(input.lease, completedAt),
  });
  return resultForMutation(mutation, {
    errorCode: "lease_expired",
    outcome: input.lease.attemptNumber >= 5 ? "dead" : "lease_expired",
    putOutcome,
  });
}

async function ensureLeaseForIo(
  input: WriterExecutionInput,
  asOf: CanonicalTimestamp,
  putOutcome: AuditArchiveR2PutOutcome | null,
): Promise<LeaseReadiness> {
  const expiresAt = canonicalTimestamp(input.lease.leaseExpiresAt);
  if (asOf.time >= expiresAt.time) {
    return {
      kind: "terminal",
      result: await expireLease(input, asOf, putOutcome),
    };
  }
  if (expiresAt.time - asOf.time >= LEASE_RENEWAL_THRESHOLD_MS) {
    return { input, kind: "ready" };
  }
  if (asOf.time <= canonicalTimestamp(input.lease.updatedAt).time) {
    return invalidInput();
  }
  const renewed = await renewAuditArchiveLease(input.database, {
    lease: input.lease,
    leaseExpiresAt: new Date(asOf.time + MAX_LEASE_MS).toISOString(),
    renewedAt: asOf.iso,
  });
  if (renewed.lease === null || renewed.status === "conflict") {
    return {
      kind: "terminal",
      result: {
        errorCode: null,
        mutation: null,
        outcome: "lease_lost",
        putOutcome,
      },
    };
  }
  return { input: { ...input, lease: renewed.lease }, kind: "ready" };
}

async function completedTimestamp(
  input: WriterExecutionInput,
  putOutcome: AuditArchiveR2PutOutcome | null,
): Promise<CanonicalTimestamp | AuditArchiveR2WriterResult> {
  const completedAt = input.readNow();
  const leaseExpiry = canonicalTimestamp(input.lease.leaseExpiresAt);
  if (completedAt.time >= leaseExpiry.time) {
    return await expireLease(input, completedAt, putOutcome);
  }
  if (completedAt.time <= canonicalTimestamp(input.lease.updatedAt).time) {
    return invalidInput();
  }
  return completedAt;
}

async function failTransient(
  input: WriterExecutionInput,
  errorCode: AuditArchiveTransientErrorCode,
  putOutcome: AuditArchiveR2PutOutcome | null,
): Promise<AuditArchiveR2WriterResult> {
  const completion = await completedTimestamp(input, putOutcome);
  if (!("iso" in completion)) return completion;
  const mutation = await failAuditArchiveLease(input.database, {
    completedAt: completion.iso,
    errorCode,
    evidence: null,
    lease: input.lease,
    nextAttemptAt: retryAt(input.lease, completion),
  });
  return resultForMutation(mutation, {
    errorCode,
    outcome: input.lease.attemptNumber >= 5 ? "dead" : "retry",
    putOutcome,
  });
}

async function failIntegrity(
  input: WriterExecutionInput,
  errorCode:
    | "crypto_integrity"
    | "r2_object_conflict"
    | "r2_readback_mismatch",
  evidence: R2ConflictEvidenceWithoutTime | R2EvidenceWithoutTime | null,
  putOutcome: AuditArchiveR2PutOutcome | null,
): Promise<AuditArchiveR2WriterResult> {
  const completion = await completedTimestamp(input, putOutcome);
  if (!("iso" in completion)) return completion;
  const timedEvidence = evidence === null
    ? null
    : { ...evidence, readbackAt: completion.iso };
  const mutation = errorCode === "crypto_integrity"
    ? await failAuditArchiveLease(input.database, {
      completedAt: completion.iso,
      errorCode,
      evidence: timedEvidence as AuditArchiveR2Evidence | null,
      lease: input.lease,
      nextAttemptAt: null,
    })
    : errorCode === "r2_object_conflict"
      ? await failAuditArchiveLease(input.database, {
        completedAt: completion.iso,
        errorCode,
        evidence: timedEvidence as AuditArchiveR2ConflictEvidence,
        lease: input.lease,
        nextAttemptAt: null,
      })
      : await failAuditArchiveLease(input.database, {
        completedAt: completion.iso,
        errorCode,
        evidence: timedEvidence as AuditArchiveR2Evidence,
        lease: input.lease,
        nextAttemptAt: null,
      });
  return resultForMutation(mutation, {
    errorCode,
    outcome: "corrupt",
    putOutcome,
  });
}

async function finalize(
  input: WriterExecutionInput,
  evidence: R2EvidenceWithoutTime,
  putOutcome: AuditArchiveR2PutOutcome,
): Promise<AuditArchiveR2WriterResult> {
  const completion = await completedTimestamp(input, putOutcome);
  if (!("iso" in completion)) return completion;
  const mutation = await finalizeAuditArchiveLease(input.database, {
    completedAt: completion.iso,
    evidence: { ...evidence, readbackAt: completion.iso },
    lease: input.lease,
  });
  return resultForMutation(mutation, {
    errorCode: null,
    outcome: "archived",
    putOutcome,
  });
}

function exactReadback(
  observation: FullR2Observation,
  expected: Uint8Array<ArrayBuffer>,
  manifest: AuditArchiveManifestV1,
): boolean {
  return (
    observation.metadataMatches &&
    observation.evidence.observedBytes === manifest.objectBytes &&
    observation.evidence.readbackSha256 === manifest.objectSha256 &&
    observation.evidence.storedSha256 === manifest.objectSha256 &&
    bytesEqual(observation.body, expected)
  );
}

export async function writeClaimedAuditArchive(
  input: WriteClaimedAuditArchiveInput,
): Promise<AuditArchiveR2WriterResult> {
  if (
    typeof input !== "object" ||
    input === null ||
    typeof input.bucket?.get !== "function" ||
    typeof input.bucket?.put !== "function" ||
    typeof input.database !== "object" ||
    input.database === null ||
    typeof input.lease !== "object" ||
    input.lease === null ||
    typeof input.verifier?.verify !== "function"
  ) {
    return invalidInput();
  }
  const leaseUpdatedAt = canonicalTimestamp(input.lease.updatedAt).time;
  let lastLogical = leaseUpdatedAt;
  let lastRaw = leaseUpdatedAt;
  const readNow = (): CanonicalTimestamp => {
    const observed = canonicalNow(input.now);
    const raw = observed.time;
    if (raw < lastRaw) return invalidInput();
    const time = raw > lastLogical ? raw : lastLogical + 1;
    const date = new Date(time);
    if (
      !Number.isSafeInteger(time) ||
      !Number.isFinite(date.getTime()) ||
      date.getTime() !== time
    ) {
      return invalidInput();
    }
    lastRaw = raw;
    lastLogical = time;
    return { iso: date.toISOString(), time };
  };
  let activeInput: WriterExecutionInput = { ...input, readNow };
  const initialLease = await ensureLeaseForIo(
    activeInput,
    activeInput.readNow(),
    null,
  );
  if (initialLease.kind === "terminal") return initialLease.result;
  activeInput = initialLease.input;

  let claimed: Awaited<ReturnType<typeof readClaimedAuditArchiveBatch>>;
  try {
    claimed = await readClaimedAuditArchiveBatch(activeInput.database, {
      lease: activeInput.lease,
    });
  } catch (error) {
    return error instanceof AuditArchiveRepositoryError &&
        error.code === "source_invalid"
      ? await failIntegrity(activeInput, "crypto_integrity", null, null)
      : await failTransient(activeInput, "internal_error", null);
  }
  if (claimed === null) {
    return {
      errorCode: null,
      mutation: null,
      outcome: "lease_lost",
      putOutcome: null,
    };
  }

  let readback: Uint8Array<ArrayBuffer> | undefined;
  try {
    const initialVerification = await verifyEnvelope(activeInput.verifier, {
      keyVersion: claimed.keyVersion,
      manifest: claimed.manifest,
      objectBytes: claimed.encryptedEnvelope,
    });
    if (initialVerification === "key_unavailable") {
      return await failTransient(activeInput, "key_unavailable", null);
    }
    if (initialVerification === "crypto_integrity") {
      return await failIntegrity(activeInput, "crypto_integrity", null, null);
    }
    if (initialVerification === "internal_error") {
      return await failTransient(activeInput, "internal_error", null);
    }

    const manifestJson = JSON.stringify(claimed.manifest);
    if (
      new TextEncoder().encode(manifestJson).byteLength >
      ARCHIVE_MAX_CUSTOM_METADATA_BYTES
    ) {
      return await failIntegrity(activeInput, "crypto_integrity", null, null);
    }
    const putLease = await ensureLeaseForIo(
      activeInput,
      activeInput.readNow(),
      null,
    );
    if (putLease.kind === "terminal") return putLease.result;
    activeInput = putLease.input;
    const objectSha256Bytes = sha256BytesFromHex(claimed.objectSha256);
    let putOutcome: AuditArchiveR2PutOutcome;
    try {
      const put = await activeInput.bucket.put(
        claimed.objectKey,
        claimed.encryptedEnvelope,
        {
          onlyIf: new Headers({ "If-None-Match": "*" }),
          httpMetadata: {
            cacheControl: "no-store",
            contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
          },
          customMetadata: { [ARCHIVE_MANIFEST_METADATA_KEY]: manifestJson },
          sha256: objectSha256Bytes,
        },
      );
      putOutcome = put === null ? "precondition_failed" : "created";
    } catch {
      putOutcome = "response_uncertain";
    } finally {
      objectSha256Bytes.fill(0);
    }

    const getLease = await ensureLeaseForIo(
      activeInput,
      activeInput.readNow(),
      putOutcome,
    );
    if (getLease.kind === "terminal") return getLease.result;
    activeInput = getLease.input;

    let object: R2ObjectBody | null;
    try {
      object = await activeInput.bucket.get(claimed.objectKey);
    } catch {
      return await failTransient(activeInput, "r2_transient", putOutcome);
    }
    if (object === null) {
      return await failTransient(activeInput, "r2_transient", putOutcome);
    }
    let observation: R2Observation;
    try {
      observation = await observeR2Object(
        object,
        claimed.manifest,
        manifestJson,
      );
    } catch {
      return await failTransient(activeInput, "r2_transient", putOutcome);
    }
    if (observation.kind === "transient") {
      return await failTransient(activeInput, "r2_transient", putOutcome);
    }
    if (observation.kind === "partial") {
      return putOutcome === "created"
        ? await failTransient(activeInput, "r2_transient", putOutcome)
        : await failIntegrity(
          activeInput,
          "r2_object_conflict",
          observation.value.evidence,
          putOutcome,
        );
    }
    readback = observation.value.body;
    if (!exactReadback(observation.value, claimed.encryptedEnvelope, claimed.manifest)) {
      return await failIntegrity(
        activeInput,
        putOutcome === "created"
          ? "r2_readback_mismatch"
          : "r2_object_conflict",
        observation.value.evidence,
        putOutcome,
      );
    }
    const readbackVerification = await verifyEnvelope(activeInput.verifier, {
      keyVersion: claimed.keyVersion,
      manifest: claimed.manifest,
      objectBytes: readback,
    });
    if (readbackVerification === "key_unavailable") {
      return await failTransient(activeInput, "key_unavailable", putOutcome);
    }
    if (readbackVerification === "internal_error") {
      return await failTransient(activeInput, "internal_error", putOutcome);
    }
    if (readbackVerification === "crypto_integrity") {
      return await failIntegrity(
        activeInput,
        "crypto_integrity",
        observation.value.evidence,
        putOutcome,
      );
    }
    return await finalize(activeInput, observation.value.evidence, putOutcome);
  } finally {
    readback?.fill(0);
    claimed.encryptedEnvelope.fill(0);
  }
}
