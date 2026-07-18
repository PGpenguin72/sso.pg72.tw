import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import {
  type AuditArchiveEnvelopeVerification,
  type AuditArchiveEnvelopeVerificationInput,
  type AuditArchiveEnvelopeVerifier,
  type AuditArchiveDigestStream,
  type AuditArchiveR2Store,
  writeClaimedAuditArchive,
} from "../worker/audit-archive-r2-writer";
import {
  acquireAuditArchiveLease,
  failAuditArchiveLease,
  initializeOrVerifyAuditArchiveKey,
  queueAuditArchiveBatch,
  renewAuditArchiveLease,
  selectAuditArchiveSource,
  type AuditArchiveLease,
} from "../worker/audit-archive-repository";
import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  openAuditArchiveV1,
  sealAuditArchiveV1,
  type AuditArchiveManifestV1,
} from "../worker/audit-archive-crypto";

const START = Date.parse("2026-07-18T14:00:00.000Z");
const KEY_VERSION = "v1";
const ZERO_KEK = "A".repeat(43);
const FINGERPRINT = reference(81);

interface WriterFixture {
  batchKey: string;
  encryptedEnvelope: Uint8Array<ArrayBuffer>;
  lease: AuditArchiveLease;
  manifest: AuditArchiveManifestV1;
}

interface StoredObject {
  bytes: Uint8Array<ArrayBuffer>;
  customMetadata: Record<string, string>;
  etag: string;
  httpMetadata: R2HTTPMetadata;
  key: string;
  reportedSize: number;
  sha256: ArrayBuffer | undefined;
  version: string;
  bodyUsed?: boolean;
}

type ObservationFault =
  | "body_used_getter"
  | "checksums_getter"
  | "custom_metadata_keys"
  | "http_metadata_keys"
  | "key_getter"
  | "size_getter"
  | "size_second_access";

async function dropArchiveLedger(): Promise<void> {
  const triggers = await env.PG72_ID_DB.prepare(
    `SELECT name FROM sqlite_schema
      WHERE type = 'trigger'
        AND (name GLOB 'audit_archive_*' OR name GLOB 'audit_event_archive_*')
      ORDER BY name`,
  ).all<{ name: string }>();
  for (const { name } of triggers.results) {
    if (!/^[a-z0-9_]+$/.test(name)) throw new Error("unsafe test trigger name");
    await env.PG72_ID_DB.prepare(`DROP TRIGGER "${name}"`).run();
  }
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_attempt"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_batch_item"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_batch"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_checkpoint"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_key_sentinel"),
    env.PG72_ID_DB.prepare("DROP TABLE audit_archive_source"),
  ]);
  await env.PG72_ID_DB.prepare("DELETE FROM audit_event").run();
}

async function applyArchiveMigration(migrationName: string): Promise<void> {
  const migration = env.TEST_MIGRATIONS.find(({ name }) => name === migrationName);
  if (!migration) throw new Error(`missing archive migration: ${migrationName}`);
  await env.PG72_ID_DB.batch(
    migration.queries.map((query) => env.PG72_ID_DB.prepare(query)),
  );
}

async function resetArchiveLedger(): Promise<void> {
  await dropArchiveLedger();
  await applyArchiveMigration("0021_audit_archive.sql");
  await applyArchiveMigration("0023_audit_archive_r2_evidence.sql");
  await applyArchiveMigration("0024_audit_archive_r2_evidence_guard.sql");
}

function at(milliseconds: number): string {
  return new Date(START + milliseconds).toISOString();
}

function base64Url32(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function reference(seed?: number): string {
  const bytes = seed === undefined
    ? crypto.getRandomValues(new Uint8Array(32))
    : new Uint8Array(32).fill(seed);
  return base64Url32(bytes);
}

function hexBytes(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(value.length / 2));
  for (let index = 0; index < bytes.byteLength; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function arrayBuffer(bytes: Uint8Array<ArrayBufferLike>): ArrayBuffer {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy.buffer;
}

async function insertAuditEvent(index: number): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, subject_id, outcome, metadata_json, occurred_at)
     VALUES (?, 'test.archive.r2_writer', ?, 'success', ?, ?)`,
  )
    .bind(
      `archive.r2-writer.${index}.${crypto.randomUUID()}`,
      `subject:${index}`,
      JSON.stringify({ kind: "archive_r2_writer_test", ordinal: index }),
      at(index * 100),
    )
    .run();
}

async function writerFixture(
  index = 1,
  leaseExpiresAt = at(311_000),
): Promise<WriterFixture> {
  await initializeOrVerifyAuditArchiveKey(env.PG72_ID_DB, {
    createdAt: at(1),
    fingerprintRef: FINGERPRINT,
    keyVersion: KEY_VERSION,
  });
  await insertAuditEvent(index);
  const selection = await selectAuditArchiveSource(env.PG72_ID_DB);
  const sealed = await sealAuditArchiveV1({
    batchGeneration: selection.checkpoint.revision + 1,
    checkpointFromSequence: selection.checkpoint.lastSequence,
    createdAt: at(10_000),
    kek: ZERO_KEK,
    keyVersion: KEY_VERSION,
    records: selection.records,
  });
  const batchKey = reference();
  expect(
    await queueAuditArchiveBatch(env.PG72_ID_DB, {
      batchKey,
      checkpoint: selection.checkpoint,
      encryptedEnvelope: sealed.objectBytes,
      manifest: sealed.manifest,
      records: selection.records,
    }),
  ).toBe("queued");
  const acquired = await acquireAuditArchiveLease(env.PG72_ID_DB, {
    batchKey,
    claimedAt: at(11_000),
    dispatchGeneration: 1,
    leaseExpiresAt,
    leaseId: reference(),
  });
  expect(acquired.status).toBe("acquired");
  if (acquired.lease === null) throw new Error("missing test lease");
  return {
    batchKey,
    encryptedEnvelope: sealed.objectBytes,
    lease: acquired.lease,
    manifest: sealed.manifest,
  };
}

function checksums(sha256: ArrayBuffer | undefined): R2Checksums {
  return {
    sha256,
    toJSON: () => ({
      sha256: sha256 === undefined
        ? undefined
        : [...new Uint8Array(sha256)]
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join(""),
    }),
  };
}

function r2Object(stored: StoredObject): R2Object {
  return {
    checksums: checksums(stored.sha256),
    customMetadata: { ...stored.customMetadata },
    etag: stored.etag,
    httpEtag: `"${stored.etag}"`,
    httpMetadata: { ...stored.httpMetadata },
    key: stored.key,
    size: stored.reportedSize,
    storageClass: "Standard",
    uploaded: new Date(at(12_000)),
    version: stored.version,
    writeHttpMetadata(headers: Headers) {
      if (stored.httpMetadata.cacheControl !== undefined) {
        headers.set("Cache-Control", stored.httpMetadata.cacheControl);
      }
      if (stored.httpMetadata.contentType !== undefined) {
        headers.set("Content-Type", stored.httpMetadata.contentType);
      }
    },
  } satisfies R2Object;
}

function r2ObjectBody(
  stored: StoredObject,
  onBodyAccess: () => void,
  onChunk: () => void,
  onCancel: () => void,
  onStream: (stream: ReadableStream<Uint8Array<ArrayBuffer>>) => void,
): R2ObjectBody {
  const bodyBytes = stored.bytes.slice();
  const firstChunkBytes = Math.max(1, Math.floor(bodyBytes.byteLength / 2));
  let offset = 0;
  let body: ReadableStream<Uint8Array<ArrayBuffer>> | undefined;
  const object = r2Object(stored);
  return {
    ...object,
    get body() {
      onBodyAccess();
      body ??= new ReadableStream<Uint8Array<ArrayBuffer>>(
        {
          pull(controller) {
            if (offset >= bodyBytes.byteLength) {
              controller.close();
              return;
            }
            const end = Math.min(
              bodyBytes.byteLength,
              offset === 0 ? firstChunkBytes : bodyBytes.byteLength,
            );
            const chunk = bodyBytes.slice(offset, end);
            bodyBytes.fill(0, offset, end);
            offset = end;
            onChunk();
            controller.enqueue(chunk);
          },
          cancel() {
            onCancel();
            bodyBytes.fill(0);
          },
        },
        { highWaterMark: 0 },
      );
      onStream(body);
      return body;
    },
    bodyUsed: stored.bodyUsed ?? false,
    arrayBuffer: async () => arrayBuffer(stored.bytes),
    blob: async () => new Blob([stored.bytes]),
    bytes: async () => stored.bytes.slice(),
    json: async <T>() => JSON.parse(new TextDecoder().decode(stored.bytes)) as T,
    text: async () => new TextDecoder().decode(stored.bytes),
    writeHttpMetadata: object.writeHttpMetadata.bind(object),
  } satisfies R2ObjectBody;
}

class FakeArchiveStore implements AuditArchiveR2Store {
  bodyAccesses = 0;
  cancellations = 0;
  chunksProvided = 0;
  getCalls = 0;
  getMode: "normal" | "null" | "throw" = "normal";
  lastPutChecksum: Uint8Array<ArrayBufferLike> | null = null;
  lastPutEnvelope: Uint8Array<ArrayBuffer> | null = null;
  lastPutOptions: (R2PutOptions & { onlyIf: Headers }) | null = null;
  lastBody: ReadableStream<Uint8Array<ArrayBuffer>> | null = null;
  mutateBeforeGet: ((object: StoredObject) => void) | null = null;
  object: StoredObject | null = null;
  observationAccesses = 0;
  observationFault: ObservationFault | null = null;
  putCalls = 0;
  putMode: "create" | "precondition" | "response_loss" = "create";

  seedExact(fixture: WriterFixture): void {
    this.object = {
      bytes: fixture.encryptedEnvelope.slice(),
      customMetadata: {
        "pgid-manifest-v1": JSON.stringify(fixture.manifest),
      },
      etag: "etag-existing",
      httpMetadata: {
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      },
      key: fixture.manifest.objectKey,
      reportedSize: fixture.manifest.objectBytes,
      sha256: arrayBuffer(hexBytes(fixture.manifest.objectSha256)),
      version: "version-existing",
    };
  }

  async put(
    key: string,
    value: Uint8Array<ArrayBuffer>,
    options: R2PutOptions & { onlyIf: Headers },
  ): Promise<R2Object | null> {
    this.putCalls += 1;
    this.lastPutEnvelope = value;
    this.lastPutOptions = options;
    if (!(options.sha256 instanceof Uint8Array)) {
      throw new Error("test expected Uint8Array checksum");
    }
    this.lastPutChecksum = options.sha256;
    if (this.putMode === "precondition") return null;
    if (
      options.httpMetadata instanceof Headers ||
      options.httpMetadata === undefined ||
      options.customMetadata === undefined
    ) {
      throw new Error("test expected exact metadata objects");
    }
    this.object = {
      bytes: value.slice(),
      customMetadata: { ...options.customMetadata },
      etag: "etag-created",
      httpMetadata: { ...options.httpMetadata },
      key,
      reportedSize: value.byteLength,
      sha256: arrayBuffer(options.sha256),
      version: "version-created",
    };
    if (this.putMode === "response_loss") {
      throw new Error("sensitive-r2-response-loss-detail");
    }
    return r2Object(this.object);
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    this.getCalls += 1;
    if (this.getMode === "throw") {
      throw new Error("sensitive-r2-read-detail");
    }
    if (this.getMode === "null" || this.object === null || this.object.key !== key) {
      return null;
    }
    this.mutateBeforeGet?.(this.object);
    this.mutateBeforeGet = null;
    const object = r2ObjectBody(
      this.object,
      () => {
        this.bodyAccesses += 1;
      },
      () => {
        this.chunksProvided += 1;
      },
      () => {
        this.cancellations += 1;
      },
      (body) => {
        this.lastBody = body;
      },
    );
    const fault = this.observationFault;
    if (fault === null) return object;
    return new Proxy(object, {
      get: (target, property, receiver) => {
        if (property === "size") {
          this.observationAccesses += 1;
          if (
            fault === "size_getter" ||
            (fault === "size_second_access" && this.observationAccesses > 1)
          ) {
            throw new Error("sensitive-size-getter-detail");
          }
        }
        if (property === "bodyUsed" && fault === "body_used_getter") {
          throw new Error("sensitive-body-used-getter-detail");
        }
        if (property === "checksums" && fault === "checksums_getter") {
          throw new Error("sensitive-checksums-getter-detail");
        }
        if (property === "key" && fault === "key_getter") {
          throw new Error("sensitive-key-getter-detail");
        }
        const value = Reflect.get(target, property, receiver);
        if (
          property === "httpMetadata" &&
          fault === "http_metadata_keys" &&
          value !== undefined
        ) {
          return new Proxy(value as R2HTTPMetadata, {
            ownKeys() {
              throw new Error("sensitive-http-metadata-keys-detail");
            },
          });
        }
        if (
          property === "customMetadata" &&
          fault === "custom_metadata_keys" &&
          value !== undefined
        ) {
          return new Proxy(value as Record<string, string>, {
            ownKeys() {
              throw new Error("sensitive-custom-metadata-keys-detail");
            },
          });
        }
        return value;
      },
    });
  }
}

class TestVerifier implements AuditArchiveEnvelopeVerifier {
  calls: Uint8Array<ArrayBuffer>[] = [];
  modes: (AuditArchiveEnvelopeVerification | "throw")[] = [];

  constructor(...modes: (AuditArchiveEnvelopeVerification | "throw")[]) {
    this.modes = modes;
  }

  async verify(
    input: AuditArchiveEnvelopeVerificationInput,
  ): Promise<AuditArchiveEnvelopeVerification> {
    this.calls.push(input.objectBytes);
    const mode = this.modes.shift();
    if (mode === "throw") {
      throw new Error("sensitive-kek-provider-detail");
    }
    if (mode !== undefined) return mode;
    try {
      await openAuditArchiveV1({
        expected: input.manifest,
        kek: ZERO_KEK,
        objectBytes: input.objectBytes,
      });
      return "verified";
    } catch {
      return "crypto_integrity";
    }
  }
}

function clock(start = at(12_000), completed = at(13_000)): () => string {
  let calls = 0;
  return () => {
    const value = calls === 0
      ? start
      : new Date(Date.parse(completed) + calls - 1).toISOString();
    calls += 1;
    return value;
  };
}

function clockSequence(...values: string[]): () => string {
  const fallback = values.at(-1);
  if (fallback === undefined) throw new Error("test clock requires a value");
  return () => values.shift() ?? fallback;
}

async function batchState(batchKey: string): Promise<Record<string, unknown> | null> {
  return await env.PG72_ID_DB.prepare(
    `SELECT status, last_error_code, next_attempt_at, encrypted_envelope
       FROM audit_archive_batch WHERE batch_key = ?`,
  )
    .bind(batchKey)
    .first<Record<string, unknown>>();
}

function corruptClaimedBatchProjection(database: D1Database): D1Database {
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) => wrap(target.bind(...values));
        }
        if (property === "all") {
          return async () => {
            const result = await target.all();
            const row = result.results[0];
            if (typeof row === "object" && row !== null) {
              (row as Record<string, unknown>).manifest_json = "{}";
            }
            return result;
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => {
          const statement = target.prepare(query);
          return query.includes("length(batch.encrypted_envelope)")
            ? wrap(statement)
            : statement;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function classifyNextTerminalBatchAsDuplicate(database: D1Database): D1Database {
  let intercepted = false;
  return new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          if (!intercepted && results.length === 5) {
            intercepted = true;
            if (results[1] !== undefined) results[1].results = [];
          }
          return results;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function commitThenRejectNextBatch(
  database: D1Database,
  statementCount: number,
): D1Database {
  let intercepted = false;
  return new Proxy(database, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const results = await target.batch(statements);
          if (!intercepted && statements.length === statementCount) {
            intercepted = true;
            throw new Error("sensitive-committed-response-loss-detail");
          }
          return results;
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

type DigestFault =
  | "close"
  | "constructor"
  | "digest_getter"
  | "digest_length"
  | "digest_reject"
  | "get_writer"
  | "write";

interface DigestFaultState {
  aborts: number;
  closes: number;
  writes: number;
}

function faultDigestStreamFactory(
  fault: DigestFault,
  state: DigestFaultState,
): () => AuditArchiveDigestStream {
  return () => {
    if (fault === "constructor") {
      throw new Error("sensitive-digest-constructor-detail");
    }
    let resolveDigest: (value: ArrayBuffer) => void = () => undefined;
    let rejectDigest: (reason: Error) => void = () => undefined;
    const digest = new Promise<ArrayBuffer>((resolve, reject) => {
      resolveDigest = resolve;
      rejectDigest = reject;
    });
    const writable = new WritableStream<ArrayBuffer | ArrayBufferView>({
      abort() {
        state.aborts += 1;
        if (fault === "digest_getter") {
          resolveDigest(new ArrayBuffer(32));
        } else {
          rejectDigest(new Error("digest aborted"));
        }
      },
      close() {
        state.closes += 1;
        if (fault === "close") {
          rejectDigest(new Error("sensitive-digest-close-detail"));
          throw new Error("sensitive-digest-close-detail");
        }
        if (fault === "digest_reject") {
          rejectDigest(new Error("sensitive-digest-result-detail"));
        } else {
          resolveDigest(new ArrayBuffer(fault === "digest_length" ? 31 : 32));
        }
      },
      write() {
        state.writes += 1;
        if (fault === "write") {
          rejectDigest(new Error("sensitive-digest-write-detail"));
          throw new Error("sensitive-digest-write-detail");
        }
      },
    });
    return {
      get digest() {
        if (fault === "digest_getter") {
          throw new Error("sensitive-digest-getter-detail");
        }
        return digest;
      },
      getWriter() {
        if (fault === "get_writer") {
          throw new Error("sensitive-digest-writer-detail");
        }
        return writable.getWriter();
      },
    } satisfies AuditArchiveDigestStream;
  };
}

async function advanceToFifthAttempt(fixture: WriterFixture): Promise<AuditArchiveLease> {
  let lease = fixture.lease;
  let completedAt = 12_000;
  for (let attempt = 1; attempt < 5; attempt += 1) {
    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt: at(completedAt),
        errorCode: "r2_transient",
        evidence: null,
        lease,
        nextAttemptAt: at(completedAt),
      }),
    ).toBe("applied");
    const claimedAt = completedAt + 1;
    const acquired = await acquireAuditArchiveLease(env.PG72_ID_DB, {
      batchKey: fixture.batchKey,
      claimedAt: at(claimedAt),
      dispatchGeneration: 1,
      leaseExpiresAt: at(claimedAt + 300_000),
      leaseId: reference(),
    });
    expect(acquired.status).toBe("acquired");
    if (acquired.lease === null) throw new Error("missing retry lease");
    lease = acquired.lease;
    completedAt += 1_001;
  }
  expect(lease.attemptNumber).toBe(5);
  return lease;
}

class MutatingVerifier implements AuditArchiveEnvelopeVerifier {
  async verify(
    input: AuditArchiveEnvelopeVerificationInput,
  ): Promise<AuditArchiveEnvelopeVerification> {
    input.manifest.objectKey = "audit/v1/malicious";
    input.objectBytes.fill(0xff);
    return "verified";
  }
}

describe.sequential("unwired encrypted R2 archive writer", () => {
  beforeEach(resetArchiveLedger);

  it("creates, strongly reads back, verifies, and atomically archives one object", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const verifier = new TestVerifier();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier,
    });

    expect(result).toEqual({
      errorCode: null,
      mutation: "applied",
      outcome: "archived",
      putOutcome: "created",
    });
    expect(bucket.lastPutOptions?.onlyIf.get("If-None-Match")).toBe("*");
    expect(bucket.lastPutOptions?.customMetadata).toEqual({
      "pgid-manifest-v1": JSON.stringify(fixture.manifest),
    });
    expect(bucket.lastPutOptions?.httpMetadata).toEqual({
      cacheControl: "no-store",
      contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    });
    expect(await batchState(fixture.batchKey)).toMatchObject({
      encrypted_envelope: null,
      last_error_code: null,
      next_attempt_at: null,
      status: "archived",
    });
    expect(verifier.calls).toHaveLength(2);
    expect(bucket.chunksProvided).toBe(2);
    for (const bytes of verifier.calls) expect([...bytes]).toEqual(expect.arrayContaining([0]));
    expect(verifier.calls.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    expect(bucket.lastPutChecksum?.every((byte) => byte === 0)).toBe(true);
    expect(bucket.lastPutEnvelope?.every((byte) => byte === 0)).toBe(true);
  });

  it("recovers an uncertain PUT response through exact readback", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.putMode = "response_loss";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "response_uncertain",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("archived");
  });

  it("classifies a differing object after an uncertain PUT as a conflict", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.putMode = "response_loss";
    bucket.mutateBeforeGet = (object) => {
      object.bytes[0] ^= 1;
    };
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_object_conflict",
      outcome: "corrupt",
      putOutcome: "response_uncertain",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("corrupt");
  });

  it("treats an exact pre-existing object as an idempotent replay", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "precondition_failed",
    });
  });

  it("returns duplicate when terminal batch readback loses its success gate", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: classifyNextTerminalBatchAsDuplicate(env.PG72_ID_DB),
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: null,
      mutation: "duplicate",
      outcome: "archived",
      putOutcome: "created",
    });
    expect(await batchState(fixture.batchKey)).toMatchObject({
      encrypted_envelope: null,
      status: "archived",
    });
  });

  it("recovers an exact finalize that commits before its D1 response is lost", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 5),
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: null,
      mutation: "duplicate",
      outcome: "archived",
      putOutcome: "created",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("archived");
  });

  it("accepts optional R2 HTTP metadata fields when they round-trip as undefined", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    if (bucket.object === null) throw new Error("missing seeded object");
    bucket.object.httpMetadata.contentLanguage = undefined;
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "precondition_failed",
    });
  });

  it.each([
    { kind: "extra", mutate: (object: StoredObject) => {
      object.customMetadata.extra = "not-allowed";
    } },
    { kind: "missing", mutate: (object: StoredObject) => {
      delete object.customMetadata["pgid-manifest-v1"];
    } },
    { kind: "wrong", mutate: (object: StoredObject) => {
      object.httpMetadata.contentType = "application/octet-stream";
    } },
  ])("records full conflict evidence for $kind metadata", async ({ mutate }) => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    if (bucket.object === null) throw new Error("missing seeded object");
    mutate(bucket.object);
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_object_conflict",
      outcome: "corrupt",
      putOutcome: "precondition_failed",
    });
    const attempt = await env.PG72_ID_DB.prepare(
      `SELECT outcome, error_code, r2_observed_bytes, r2_readback_sha256
         FROM audit_archive_attempt WHERE id = ?`,
    )
      .bind(fixture.lease.leaseId)
      .first();
    expect(attempt).toEqual({
      error_code: "r2_object_conflict",
      outcome: "corrupt",
      r2_observed_bytes: fixture.manifest.objectBytes,
      r2_readback_sha256: fixture.manifest.objectSha256,
    });
  });

  it.each(["absent", "wrong"] as const)(
    "records full conflict evidence when the stored checksum is %s",
    async (checksumKind) => {
      const fixture = await writerFixture();
      const bucket = new FakeArchiveStore();
      bucket.seedExact(fixture);
      bucket.putMode = "precondition";
      if (bucket.object === null) throw new Error("missing seeded object");
      const wrongSha256 = "f".repeat(64);
      bucket.object.sha256 = checksumKind === "absent"
        ? undefined
        : arrayBuffer(hexBytes(wrongSha256));
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clock(),
        verifier: new TestVerifier(),
      });
      expect(result).toMatchObject({
        errorCode: "r2_object_conflict",
        outcome: "corrupt",
        putOutcome: "precondition_failed",
      });
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT r2_stored_sha256, r2_readback_sha256
             FROM audit_archive_attempt WHERE id = ?`,
        )
          .bind(fixture.lease.leaseId)
          .first(),
      ).toEqual({
        r2_readback_sha256: fixture.manifest.objectSha256,
        r2_stored_sha256: checksumKind === "absent" ? null : wrongSha256,
      });
    },
  );

  it("terminalizes a created object whose full readback hash differs", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.mutateBeforeGet = (object) => {
      object.bytes[0] ^= 1;
    };
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_readback_mismatch",
      outcome: "corrupt",
      putOutcome: "created",
    });
    const attempt = await env.PG72_ID_DB.prepare(
      `SELECT error_code, r2_observed_bytes, r2_stored_sha256,
              r2_readback_sha256
         FROM audit_archive_attempt WHERE id = ?`,
    )
      .bind(fixture.lease.leaseId)
      .first();
    expect(attempt).toMatchObject({
      error_code: "r2_readback_mismatch",
      r2_observed_bytes: fixture.manifest.objectBytes,
      r2_stored_sha256: fixture.manifest.objectSha256,
    });
    expect(attempt?.r2_readback_sha256).not.toBe(fixture.manifest.objectSha256);
  });

  it("records full R2 evidence when readback envelope verification fails", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier("verified", "crypto_integrity"),
    });
    expect(result).toEqual({
      errorCode: "crypto_integrity",
      mutation: "applied",
      outcome: "corrupt",
      putOutcome: "created",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT r2_observed_bytes, r2_stored_sha256, r2_readback_sha256
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(fixture.lease.leaseId)
        .first(),
    ).toEqual({
      r2_observed_bytes: fixture.manifest.objectBytes,
      r2_readback_sha256: fixture.manifest.objectSha256,
      r2_stored_sha256: fixture.manifest.objectSha256,
    });
  });

  it("retries a stream that ends before the declared object size", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.mutateBeforeGet = (object) => {
      object.reportedSize += 1;
    };
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_transient",
      outcome: "retry",
      putOutcome: "created",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("retry");
  });

  it("records bounded partial evidence without reading an oversized conflict", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    if (bucket.object === null) throw new Error("missing seeded object");
    bucket.object.reportedSize = AUDIT_ARCHIVE_MAX_OBJECT_BYTES + 1;
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_object_conflict",
      outcome: "corrupt",
    });
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.chunksProvided).toBe(0);
    expect(bucket.cancellations).toBe(1);
    expect(bucket.lastBody?.locked).toBe(false);
    const attempt = await env.PG72_ID_DB.prepare(
      `SELECT r2_observed_bytes, r2_readback_sha256
         FROM audit_archive_attempt WHERE id = ?`,
    )
      .bind(fixture.lease.leaseId)
      .first();
    expect(attempt).toEqual({
      r2_observed_bytes: AUDIT_ARCHIVE_MAX_OBJECT_BYTES + 1,
      r2_readback_sha256: null,
    });
  });

  it("records zero-byte partial evidence without consuming the body", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    if (bucket.object === null) throw new Error("missing seeded object");
    bucket.object.reportedSize = 0;
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_object_conflict",
      outcome: "corrupt",
      putOutcome: "precondition_failed",
    });
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.chunksProvided).toBe(0);
    expect(bucket.cancellations).toBe(1);
    expect(bucket.lastBody?.locked).toBe(false);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT r2_observed_bytes, r2_readback_sha256
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(fixture.lease.leaseId)
        .first(),
    ).toEqual({
      r2_observed_bytes: 0,
      r2_readback_sha256: null,
    });
  });

  it("cancels an overflowing stream and records only bounded evidence", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.seedExact(fixture);
    bucket.putMode = "precondition";
    if (bucket.object === null) throw new Error("missing seeded object");
    bucket.object.reportedSize = 1;
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: "r2_object_conflict",
      outcome: "corrupt",
      putOutcome: "precondition_failed",
    });
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.chunksProvided).toBeGreaterThanOrEqual(1);
    expect(bucket.cancellations).toBe(1);
    expect(bucket.lastBody?.locked).toBe(false);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT r2_observed_bytes, r2_readback_sha256
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(fixture.lease.leaseId)
        .first(),
    ).toEqual({
      r2_observed_bytes: 1,
      r2_readback_sha256: null,
    });
  });

  it.each([
    {
      errorCode: "r2_transient",
      kind: "unsafe etag",
      mutate: (object: StoredObject) => {
        object.etag = "unsafe\netag";
      },
      outcome: "retry",
    },
    {
      errorCode: "r2_transient",
      kind: "unsafe version",
      mutate: (object: StoredObject) => {
        object.version = "unsafe\rversion";
      },
      outcome: "retry",
    },
    {
      errorCode: "r2_object_conflict",
      kind: "invalid checksum shape",
      mutate: (object: StoredObject) => {
        object.sha256 = new ArrayBuffer(1);
      },
      outcome: "corrupt",
    },
    {
      errorCode: "r2_object_conflict",
      kind: "already-used body",
      mutate: (object: StoredObject) => {
        object.bodyUsed = true;
      },
      outcome: "corrupt",
    },
  ] as const)(
    "cancels an early $kind observation without pulling a chunk",
    async ({ errorCode, mutate, outcome }) => {
      const fixture = await writerFixture();
      const bucket = new FakeArchiveStore();
      bucket.seedExact(fixture);
      bucket.putMode = "precondition";
      if (bucket.object === null) throw new Error("missing seeded object");
      mutate(bucket.object);
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clock(),
        verifier: new TestVerifier(),
      });
      expect(result).toMatchObject({ errorCode, outcome });
      expect(bucket.bodyAccesses).toBe(1);
      expect(bucket.chunksProvided).toBe(0);
      expect(bucket.cancellations).toBe(1);
      expect(bucket.lastBody?.locked).toBe(false);
    },
  );

  it.each([
    "body_used_getter",
    "checksums_getter",
    "custom_metadata_keys",
    "http_metadata_keys",
    "key_getter",
    "size_getter",
  ] as const)(
    "cancels a throwing R2 $fault observation before reading a chunk",
    async (observationFault) => {
      const fixture = await writerFixture();
      const bucket = new FakeArchiveStore();
      bucket.observationFault = observationFault;
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clock(),
        verifier: new TestVerifier(),
      });
      expect(result).toMatchObject({
        errorCode: "r2_transient",
        outcome: "retry",
        putOutcome: "created",
      });
      expect(JSON.stringify(result)).not.toContain("sensitive-");
      expect(bucket.bodyAccesses).toBe(1);
      expect(bucket.chunksProvided).toBe(0);
      expect(bucket.cancellations).toBe(1);
      expect(bucket.lastBody?.locked).toBe(false);
    },
  );

  it("snapshots the reported R2 size exactly once before consuming the body", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.observationFault = "size_second_access";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "created",
    });
    expect(bucket.observationAccesses).toBe(1);
    expect(bucket.chunksProvided).toBeGreaterThan(0);
  });

  it("terminalizes pre-R2 cryptographic corruption without false R2 evidence", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier("crypto_integrity"),
    });
    expect(result).toEqual({
      errorCode: "crypto_integrity",
      mutation: "applied",
      outcome: "corrupt",
      putOutcome: null,
    });
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT r2_version, r2_etag, r2_observed_bytes, r2_readback_sha256
           FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(fixture.lease.leaseId)
        .first(),
    ).toEqual({
      r2_etag: null,
      r2_observed_bytes: null,
      r2_readback_sha256: null,
      r2_version: null,
    });
  });

  it.each(["null", "throw"] as const)(
    "retries a transient GET %s on the D1-owned schedule",
    async (getMode) => {
      const fixture = await writerFixture();
      const bucket = new FakeArchiveStore();
      bucket.putMode = "response_loss";
      bucket.getMode = getMode;
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clock(),
        verifier: new TestVerifier(),
      });
      expect(result).toEqual({
        errorCode: "r2_transient",
        mutation: "applied",
        outcome: "retry",
        putOutcome: "response_uncertain",
      });
      expect(await batchState(fixture.batchKey)).toMatchObject({
        last_error_code: "r2_transient",
        next_attempt_at: at(43_002),
        status: "retry",
      });
    },
  );

  it("redacts unexpected verifier failures and performs no R2 mutation", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier("throw"),
    });
    expect(result).toMatchObject({
      errorCode: "internal_error",
      outcome: "retry",
      putOutcome: null,
    });
    expect(JSON.stringify(result)).not.toContain("sensitive-kek-provider-detail");
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it.each([
    { fault: "constructor", pullsBody: false },
    { fault: "get_writer", pullsBody: false },
    { fault: "digest_getter", pullsBody: false },
    { fault: "digest_length", pullsBody: true },
    { fault: "write", pullsBody: true },
    { fault: "close", pullsBody: true },
    { fault: "digest_reject", pullsBody: true },
  ] as const)(
    "classifies a local DigestStream $fault failure as internal_error",
    async ({ fault, pullsBody }) => {
      const fixture = await writerFixture();
      const bucket = new FakeArchiveStore();
      const state: DigestFaultState = { aborts: 0, closes: 0, writes: 0 };
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        digestStreamFactory: faultDigestStreamFactory(fault, state),
        lease: fixture.lease,
        now: clock(),
        verifier: new TestVerifier(),
      });
      expect(result).toMatchObject({
        errorCode: "internal_error",
        outcome: "retry",
        putOutcome: "created",
      });
      expect(JSON.stringify(result)).not.toContain("sensitive-");
      expect(bucket.bodyAccesses).toBe(1);
      expect(bucket.cancellations).toBe(pullsBody && fault !== "write" ? 0 : 1);
      if (!pullsBody) expect(bucket.chunksProvided).toBe(0);
      expect(bucket.lastBody?.locked).toBe(false);
      if (fault === "digest_getter") expect(state.aborts).toBe(1);
    },
  );

  it("recovers a transient terminal mutation that commits before response loss", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    bucket.putMode = "response_loss";
    bucket.getMode = "throw";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 5),
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "r2_transient",
      mutation: "duplicate",
      outcome: "retry",
      putOutcome: "response_uncertain",
    });
  });

  it("recovers an integrity terminal mutation that commits before response loss", async () => {
    const fixture = await writerFixture();
    const result = await writeClaimedAuditArchive({
      bucket: new FakeArchiveStore(),
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 5),
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier("crypto_integrity"),
    });
    expect(result).toEqual({
      errorCode: "crypto_integrity",
      mutation: "duplicate",
      outcome: "corrupt",
      putOutcome: null,
    });
  });

  it("maps an unavailable KEK provider to a retry without touching R2", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier("key_unavailable"),
    });
    expect(result).toMatchObject({
      errorCode: "key_unavailable",
      outcome: "retry",
      putOutcome: null,
    });
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("maps a malformed lease-bound projection to pre-R2 crypto integrity", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: corruptClaimedBatchProjection(env.PG72_ID_DB),
      lease: fixture.lease,
      now: clock(),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "crypto_integrity",
      mutation: "applied",
      outcome: "corrupt",
      putOutcome: null,
    });
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("isolates writer identity and bytes from a mutating verifier", async () => {
    const fixture = await writerFixture();
    const expectedEnvelope = fixture.encryptedEnvelope.slice();
    const expectedKey = fixture.manifest.objectKey;
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(),
      verifier: new MutatingVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
    });
    expect(bucket.object?.key).toBe(expectedKey);
    expect(bucket.object?.bytes).toEqual(expectedEnvelope);
  });

  it("renews a near-expiry lease before R2 I/O", async () => {
    const fixture = await writerFixture(1, at(70_000));
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clockSequence(at(12_000), at(13_000), at(80_000), at(90_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "created",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("archived");
  });

  it("retries one immutable renewal intent after commit-then-reject", async () => {
    const fixture = await writerFixture(1, at(70_000));
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 3),
      lease: fixture.lease,
      now: clockSequence(at(12_000), at(13_000), at(80_000), at(90_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "created",
    });
    expect(bucket.putCalls).toBe(1);
    expect(bucket.getCalls).toBe(1);
  });

  it("adopts a live committed renewal from a later invocation", async () => {
    const fixture = await writerFixture(1, at(70_000));
    const intent = {
      lease: fixture.lease,
      leaseExpiresAt: at(312_000),
      renewedAt: at(12_000),
    };
    await expect(
      renewAuditArchiveLease(
        commitThenRejectNextBatch(env.PG72_ID_DB, 3),
        intent,
      ),
    ).rejects.toMatchObject({ code: "write_failed" });

    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(at(13_000), at(14_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "created",
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("archived");
  });

  it("returns lease_lost when a required renewal loses its CAS", async () => {
    const fixture = await writerFixture(1, at(70_000));
    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt: at(12_000),
        errorCode: "r2_transient",
        evidence: null,
        lease: fixture.lease,
        nextAttemptAt: at(42_000),
      }),
    ).toBe("applied");
    const bucket = new FakeArchiveStore();
    const verifier = new TestVerifier();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(at(13_000), at(14_000)),
      verifier,
    });
    expect(result).toEqual({
      errorCode: null,
      mutation: null,
      outcome: "lease_lost",
      putOutcome: null,
    });
    expect(verifier.calls).toHaveLength(0);
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("expires after a committed PUT and leaves the exact R2 object intact", async () => {
    const fixture = await writerFixture(1, at(100_000));
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clockSequence(at(12_000), at(20_000), at(100_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "lease_expired",
      mutation: "applied",
      outcome: "lease_expired",
      putOutcome: "created",
    });
    expect(bucket.putCalls).toBe(1);
    expect(bucket.getCalls).toBe(0);
    expect(bucket.object).toMatchObject({
      bytes: fixture.encryptedEnvelope,
      key: fixture.manifest.objectKey,
      reportedSize: fixture.manifest.objectBytes,
    });
    expect((await batchState(fixture.batchKey))?.status).toBe("retry");
  });

  it("terminalizes the fifth transient writer attempt as dead", async () => {
    const fixture = await writerFixture();
    const lease = await advanceToFifthAttempt(fixture);
    const bucket = new FakeArchiveStore();
    bucket.putMode = "response_loss";
    bucket.getMode = "throw";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease,
      now: clock(at(17_000), at(18_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "r2_transient",
      mutation: "applied",
      outcome: "dead",
      putOutcome: "response_uncertain",
    });
    expect(await batchState(fixture.batchKey)).toMatchObject({
      last_error_code: "r2_transient",
      next_attempt_at: null,
      status: "dead",
    });
  });

  it("recovers a fifth-attempt dead mutation that commits before response loss", async () => {
    const fixture = await writerFixture();
    const lease = await advanceToFifthAttempt(fixture);
    const bucket = new FakeArchiveStore();
    bucket.putMode = "response_loss";
    bucket.getMode = "throw";
    const result = await writeClaimedAuditArchive({
      bucket,
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 5),
      lease,
      now: clock(at(17_000), at(18_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "r2_transient",
      mutation: "duplicate",
      outcome: "dead",
      putOutcome: "response_uncertain",
    });
  });

  it("pins every writer-owned retry delay before the fifth attempt is dead", async () => {
    const fixture = await writerFixture();
    const delays = [30_000, 120_000, 480_000, 900_000] as const;
    let lease = fixture.lease;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const startedAt = Date.parse(lease.updatedAt) - START + 1;
      const bucket = new FakeArchiveStore();
      bucket.putMode = "response_loss";
      bucket.getMode = "throw";
      const result = await writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease,
        now: clockSequence(
          at(startedAt),
          at(startedAt + 1),
          at(startedAt + 2),
          at(startedAt + 3),
        ),
        verifier: new TestVerifier(),
      });
      expect(result.outcome).toBe(attempt === 5 ? "dead" : "retry");
      const attemptRow = await env.PG72_ID_DB.prepare(
        `SELECT completed_at FROM audit_archive_attempt WHERE id = ?`,
      )
        .bind(lease.leaseId)
        .first<{ completed_at: string }>();
      if (!attemptRow) throw new Error("missing writer attempt evidence");
      const batch = await env.PG72_ID_DB.prepare(
        `SELECT next_attempt_at, status FROM audit_archive_batch
          WHERE batch_key = ?`,
      )
        .bind(fixture.batchKey)
        .first<{ next_attempt_at: string | null; status: string }>();
      if (!batch) throw new Error("missing writer batch state");
      if (attempt === 5) {
        expect(batch).toEqual({ next_attempt_at: null, status: "dead" });
        continue;
      }
      const delay = delays[attempt - 1];
      if (delay === undefined || batch.next_attempt_at === null) {
        throw new Error("missing bounded retry delay");
      }
      expect(
        Date.parse(batch.next_attempt_at) - Date.parse(attemptRow.completed_at),
      ).toBe(delay);
      const claimedAt = batch.next_attempt_at;
      const acquired = await acquireAuditArchiveLease(env.PG72_ID_DB, {
        batchKey: fixture.batchKey,
        claimedAt,
        dispatchGeneration: 1,
        leaseExpiresAt: new Date(Date.parse(claimedAt) + 300_000).toISOString(),
        leaseId: reference(),
      });
      if (acquired.lease === null) throw new Error("missing next writer lease");
      lease = acquired.lease;
    }
  });

  it("returns lease_lost without touching R2 for a stale terminal lease", async () => {
    const fixture = await writerFixture();
    expect(
      await failAuditArchiveLease(env.PG72_ID_DB, {
        completedAt: at(12_000),
        errorCode: "r2_transient",
        evidence: null,
        lease: fixture.lease,
        nextAttemptAt: at(42_000),
      }),
    ).toBe("applied");
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(at(13_000), at(14_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: null,
      mutation: null,
      outcome: "lease_lost",
      putOutcome: null,
    });
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("completes the full writer flow while every raw sample is frozen", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: () => at(12_000),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: null,
      mutation: "applied",
      outcome: "archived",
      putOutcome: "created",
    });
    expect(bucket.putCalls).toBe(1);
    expect(bucket.getCalls).toBe(1);
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT archived_at, updated_at FROM audit_archive_batch
          WHERE batch_key = ?`,
      )
        .bind(fixture.batchKey)
        .first(),
    ).toEqual({ archived_at: at(12_003), updated_at: at(12_003) });
  });

  it("accepts raw time equal to the lease update and advances logically", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: () => fixture.lease.updatedAt,
      verifier: new TestVerifier(),
    });
    expect(result).toMatchObject({
      errorCode: null,
      outcome: "archived",
      putOutcome: "created",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT archived_at, status, updated_at FROM audit_archive_batch
          WHERE batch_key = ?`,
      )
        .bind(fixture.batchKey)
        .first(),
    ).toEqual({
      archived_at: at(11_004),
      status: "archived",
      updated_at: at(11_004),
    });
  });

  it("rejects a true raw reversal before starting new R2 I/O", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const verifier = new TestVerifier();
    await expect(
      writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clockSequence(at(12_000), at(11_999)),
        verifier,
      }),
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(verifier.calls).toHaveLength(1);
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("rejects a raw clock before the lease update without reading work", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const verifier = new TestVerifier();
    await expect(
      writeClaimedAuditArchive({
        bucket,
        database: env.PG72_ID_DB,
        lease: fixture.lease,
        now: clockSequence(at(10_999)),
        verifier,
      }),
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(verifier.calls).toHaveLength(0);
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("expires an already-lost lease before D1, KEK, or R2 work", async () => {
    const fixture = await writerFixture();
    const bucket = new FakeArchiveStore();
    const verifier = new TestVerifier();
    const result = await writeClaimedAuditArchive({
      bucket,
      database: env.PG72_ID_DB,
      lease: fixture.lease,
      now: clock(at(311_000), at(312_000)),
      verifier,
    });
    expect(result).toEqual({
      errorCode: "lease_expired",
      mutation: "applied",
      outcome: "lease_expired",
      putOutcome: null,
    });
    expect(verifier.calls).toHaveLength(0);
    expect(bucket.putCalls).toBe(0);
    expect(bucket.getCalls).toBe(0);
  });

  it("recovers an expiry mutation that commits before its response is lost", async () => {
    const fixture = await writerFixture();
    const result = await writeClaimedAuditArchive({
      bucket: new FakeArchiveStore(),
      database: commitThenRejectNextBatch(env.PG72_ID_DB, 5),
      lease: fixture.lease,
      now: clock(at(311_000), at(312_000)),
      verifier: new TestVerifier(),
    });
    expect(result).toEqual({
      errorCode: "lease_expired",
      mutation: "duplicate",
      outcome: "lease_expired",
      putOutcome: null,
    });
  });
});
