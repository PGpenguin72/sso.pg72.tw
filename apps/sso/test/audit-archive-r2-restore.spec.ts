import { describe, expect, it } from "vitest";

import {
  AuditArchiveRestoreError,
  verifyAndOpenAuditArchiveObjectV1,
  type AuditArchiveCustodyOpenInput,
  type AuditArchiveCustodyOpenResult,
  type AuditArchiveCustodyOpener,
  type AuditArchiveRestoreErrorCode,
  type AuditArchiveRestoreStore,
  type VerifyAndOpenAuditArchiveObjectInput,
} from "../worker/audit-archive-r2-restore";
import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  encodeCanonicalAuditRecordsV1,
  type AuditArchiveManifestV1,
  type AuditArchiveRecordV1,
} from "../worker/audit-archive-crypto";

const CREATED_AT = "2026-07-18T14:00:00.000Z";
const MANIFEST_METADATA_KEY = "pgid-manifest-v1";

interface RestoreFixture {
  manifest: AuditArchiveManifestV1;
  objectBytes: Uint8Array<ArrayBuffer>;
  records: AuditArchiveRecordV1[];
}

type StreamMode =
  | "done_value"
  | "empty_chunk"
  | "error"
  | "normal"
  | "overflow"
  | "short"
  | "zero";

function record(sequence: number): AuditArchiveRecordV1 {
  return {
    actorRef: null,
    actorRefHashVersion: null,
    actorUserId: null,
    clientId: "pg72-restore-test",
    eventId: `audit.restore.${sequence}`,
    eventType: "test.audit_restore",
    ipHash: null,
    metadataJson: JSON.stringify({ kind: "restore_test", ordinal: sequence }),
    occurredAt: new Date(Date.parse(CREATED_AT) + sequence).toISOString(),
    outcome: "success",
    sequence,
    sessionId: null,
    subjectId: `subject:${sequence}`,
    userAgentHash: null,
  };
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

function hexBuffer(value: string): ArrayBuffer {
  const bytes = new Uint8Array(new ArrayBuffer(value.length / 2));
  for (let index = 0; index < bytes.byteLength; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes.buffer;
}

async function restoreFixture(
  records = [record(1), record(3)],
): Promise<RestoreFixture> {
  const objectBytes = new TextEncoder().encode(
    JSON.stringify({ contract: "opaque-custody-test-object", revision: 1 }),
  );
  const plaintext = encodeCanonicalAuditRecordsV1(records);
  try {
    const objectSha256 = await sha256Hex(objectBytes);
    const firstSequence = records[0]?.sequence ?? 0;
    const lastSequence = records.at(-1)?.sequence ?? 0;
    const manifest: AuditArchiveManifestV1 = {
      batchGeneration: 1,
      checkpointFromSequence: 0,
      contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      contract: AUDIT_ARCHIVE_ENVELOPE_CONTRACT,
      createdAt: CREATED_AT,
      eventCount: records.length,
      firstSequence,
      keyVersion: "v1",
      lastSequence,
      objectBytes: objectBytes.byteLength,
      objectKey: `audit/v1/${String(firstSequence).padStart(16, "0")}-${String(
        lastSequence,
      ).padStart(16, "0")}/${objectSha256}.pgid-audit`,
      objectSha256,
      plaintextSha256: await sha256Hex(plaintext),
      schemaVersion: 1,
    };
    return { manifest, objectBytes, records };
  } finally {
    plaintext.fill(0);
  }
}

function r2Checksums(sha256: ArrayBuffer | undefined): R2Checksums {
  return {
    sha256,
    toJSON: () => ({ sha256: undefined }),
  };
}

class FakeRestoreStore implements AuditArchiveRestoreStore {
  bodyAccesses = 0;
  bodyUsed = false;
  cancellations = 0;
  checksumBuffers: Uint8Array<ArrayBuffer>[] = [];
  checksumSnapshots: Uint8Array<ArrayBuffer>[] = [];
  customMetadata: Record<string, string> | null = null;
  getCalls = 0;
  getMode: "normal" | "null" | "throw" = "normal";
  httpMetadata: R2HTTPMetadata | null = null;
  objectBytes: Uint8Array<ArrayBuffer>;
  objectKey: string;
  providedChunks: Uint8Array<ArrayBufferLike>[] = [];
  providedChunkSnapshots: Uint8Array<ArrayBuffer>[] = [];
  reportedSize: number;
  requestedKeys: string[] = [];
  storedChecksum: "malformed" | "missing" | string;
  streamMode: StreamMode = "normal";

  constructor(readonly fixture: RestoreFixture) {
    this.objectBytes = fixture.objectBytes.slice();
    this.objectKey = fixture.manifest.objectKey;
    this.reportedSize = fixture.manifest.objectBytes;
    this.storedChecksum = fixture.manifest.objectSha256;
  }

  private checksum(): ArrayBuffer | undefined {
    if (this.storedChecksum === "missing") return undefined;
    const checksum = this.storedChecksum === "malformed"
      ? new ArrayBuffer(31)
      : hexBuffer(this.storedChecksum);
    const checksumView = new Uint8Array(checksum);
    this.checksumBuffers.push(checksumView);
    this.checksumSnapshots.push(checksumView.slice());
    return checksum;
  }

  private stream(): ReadableStream<Uint8Array<ArrayBufferLike>> {
    let bytes = this.objectBytes.slice();
    if (this.streamMode === "short") bytes = bytes.slice(0, -1);
    if (this.streamMode === "zero") bytes = new Uint8Array();
    if (this.streamMode === "overflow") {
      const overflowing = new Uint8Array(bytes.byteLength + 1);
      overflowing.set(bytes);
      overflowing[overflowing.byteLength - 1] = 1;
      bytes.fill(0);
      bytes = overflowing;
    }
    const split = Math.max(1, Math.floor(bytes.byteLength / 2));
    const chunks = this.streamMode === "empty_chunk"
      ? [new Uint8Array()]
      : bytes.byteLength === 0
        ? []
        : [bytes.slice(0, split), bytes.slice(split)].filter(
          (chunk) => chunk.byteLength > 0,
        );
    bytes.fill(0);
    let index = 0;
    let reads = 0;
    const reader = {
      cancel: async () => {
        this.cancellations += 1;
        for (const chunk of chunks.slice(index)) chunk.fill(0);
      },
      read: async (): Promise<ReadableStreamReadResult<Uint8Array<ArrayBufferLike>>> => {
        if (this.streamMode === "error" && reads > 0) {
          throw new Error("sensitive-stream-provider-detail");
        }
        reads += 1;
        const chunk = chunks[index];
        if (chunk === undefined) {
          if (this.streamMode === "done_value") {
            const trailing = new Uint8Array([1]);
            this.providedChunks.push(trailing);
            this.providedChunkSnapshots.push(trailing.slice());
            return { done: true, value: trailing };
          }
          return { done: true, value: undefined };
        }
        index += 1;
        this.providedChunks.push(chunk);
        this.providedChunkSnapshots.push(new Uint8Array(chunk));
        return { done: false, value: chunk };
      },
      releaseLock: () => undefined,
    };
    return {
      getReader: () => reader,
    } as unknown as ReadableStream<Uint8Array<ArrayBufferLike>>;
  }

  async get(key: string): Promise<R2ObjectBody | null> {
    this.getCalls += 1;
    this.requestedKeys.push(key);
    if (this.getMode === "throw") {
      throw new Error("sensitive-r2-provider-detail");
    }
    if (this.getMode === "null") return null;
    const checksum = this.checksum();
    const httpMetadata = this.httpMetadata ?? {
      cacheControl: "no-store",
      cacheExpiry: undefined,
      contentDisposition: undefined,
      contentEncoding: undefined,
      contentLanguage: undefined,
      contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
    };
    const customMetadata = this.customMetadata ?? {
      [MANIFEST_METADATA_KEY]: JSON.stringify(this.fixture.manifest),
    };
    const object: R2Object = {
      checksums: r2Checksums(checksum),
      customMetadata,
      etag: "etag-restore-test",
      httpEtag: '"etag-restore-test"',
      httpMetadata,
      key: this.objectKey,
      size: this.reportedSize,
      storageClass: "Standard",
      uploaded: new Date(CREATED_AT),
      version: "version-restore-test",
      writeHttpMetadata: () => undefined,
    };
    const store = this;
    let body: ReadableStream<Uint8Array<ArrayBufferLike>> | undefined;
    return {
      ...object,
      arrayBuffer: async () => this.objectBytes.slice().buffer,
      blob: async () => new Blob([this.objectBytes]),
      get body() {
        body ??= store.stream();
        store.bodyAccesses += 1;
        return body;
      },
      bodyUsed: this.bodyUsed,
      bytes: async () => this.objectBytes.slice(),
      json: async <T>() => JSON.parse(
        new TextDecoder().decode(this.objectBytes),
      ) as T,
      text: async () => new TextDecoder().decode(this.objectBytes),
      writeHttpMetadata: object.writeHttpMetadata.bind(object),
    } satisfies R2ObjectBody;
  }
}

class TestCustodyOpener implements AuditArchiveCustodyOpener {
  calls: AuditArchiveCustodyOpenInput[] = [];
  mutateInput = false;
  result: AuditArchiveCustodyOpenResult | "throw";

  constructor(
    records: readonly AuditArchiveRecordV1[],
    result: AuditArchiveCustodyOpenResult | "throw" = {
      outcome: "opened",
      records,
    },
  ) {
    this.result = result;
  }

  async open(
    input: AuditArchiveCustodyOpenInput,
  ): Promise<AuditArchiveCustodyOpenResult> {
    this.calls.push(input);
    if (this.mutateInput) {
      input.manifest.objectKey = "audit/v1/provider-mutated";
      input.objectBytes.fill(0xff);
    }
    if (this.result === "throw") {
      throw new Error("sensitive-custody-provider-detail");
    }
    return this.result;
  }
}

async function restoreFailure(
  input: VerifyAndOpenAuditArchiveObjectInput,
  code: AuditArchiveRestoreErrorCode,
): Promise<AuditArchiveRestoreError> {
  let failure: unknown;
  try {
    await verifyAndOpenAuditArchiveObjectV1(input);
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(AuditArchiveRestoreError);
  expect((failure as AuditArchiveRestoreError).code).toBe(code);
  expect(
    Object.prototype.propertyIsEnumerable.call(failure, "code"),
  ).toBe(true);
  return failure as AuditArchiveRestoreError;
}

function input(
  fixture: RestoreFixture,
  bucket: AuditArchiveRestoreStore = new FakeRestoreStore(fixture),
  opener: AuditArchiveCustodyOpener = new TestCustodyOpener(fixture.records),
): VerifyAndOpenAuditArchiveObjectInput {
  return { bucket, expected: fixture.manifest, opener };
}

describe("pure audit archive R2 restore verifier", () => {
  it("opens one exact object, preserves provider buffers, and clears owned copies", async () => {
    const fixture = await restoreFixture();
    const objectBefore = fixture.objectBytes.slice();
    const manifestBefore = structuredClone(fixture.manifest);
    const bucket = new FakeRestoreStore(fixture);
    const opener = new TestCustodyOpener(fixture.records);

    const restored = await verifyAndOpenAuditArchiveObjectV1(
      input(fixture, bucket, opener),
    );

    expect(restored).toEqual(fixture.records);
    expect(restored).not.toBe(fixture.records);
    expect(restored[0]).not.toBe(fixture.records[0]);
    expect(Object.isFrozen(restored)).toBe(true);
    expect(restored.every((value) => Object.isFrozen(value))).toBe(true);
    expect(bucket.requestedKeys).toEqual([fixture.manifest.objectKey]);
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.providedChunks).toHaveLength(2);
    expect(bucket.providedChunks).toEqual(bucket.providedChunkSnapshots);
    expect(bucket.checksumBuffers).toEqual(bucket.checksumSnapshots);
    expect(opener.calls).toHaveLength(1);
    expect(opener.calls[0]?.objectBytes.every((byte) => byte === 0)).toBe(true);
    expect(fixture.objectBytes).toEqual(objectBefore);
    expect(fixture.manifest).toEqual(manifestBefore);
  });

  it("validates the trusted manifest and derived key before the first source read", async () => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    const opener = new TestCustodyOpener(fixture.records);
    const hostile = {
      ...fixture.manifest,
      objectKey: "audit/v1/arbitrary-object-selected-by-hostile-input",
    } as AuditArchiveManifestV1;

    await restoreFailure(
      { bucket, expected: hostile, opener },
      "invalid_input",
    );
    expect(bucket.getCalls).toBe(0);
    expect(bucket.requestedKeys).toEqual([]);
    expect(opener.calls).toEqual([]);
  });

  it("redacts a hostile manifest accessor before the first source read", async () => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    const hostile = {
      ...fixture.manifest,
      get objectKey(): string {
        throw new Error("sensitive-hostile-manifest-detail");
      },
    };
    const failure = await restoreFailure(
      {
        bucket,
        expected: hostile,
        opener: new TestCustodyOpener(fixture.records),
      },
      "internal_error",
    );
    expect(bucket.getCalls).toBe(0);
    expect(failure.message).not.toContain("sensitive-hostile-manifest-detail");
  });

  it("snapshots a dynamic manifest key once and cannot read an arbitrary key later", async () => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    let reads = 0;
    const dynamic = {
      ...fixture.manifest,
      get objectKey(): string {
        reads += 1;
        return reads === 1
          ? fixture.manifest.objectKey
          : "audit/v1/arbitrary-after-validation";
      },
    };
    const restored = await verifyAndOpenAuditArchiveObjectV1({
      bucket,
      expected: dynamic,
      opener: new TestCustodyOpener(fixture.records),
    });
    expect(restored).toEqual(fixture.records);
    expect(reads).toBe(1);
    expect(bucket.requestedKeys).toEqual([fixture.manifest.objectKey]);
  });

  it.each([
    ["extra field", (manifest: AuditArchiveManifestV1) => ({ ...manifest, extra: true })],
    ["wrong contract", (manifest: AuditArchiveManifestV1) => ({ ...manifest, contract: "legacy" })],
    ["wrong content type", (manifest: AuditArchiveManifestV1) => ({ ...manifest, contentType: "application/json" })],
    ["wrong schema", (manifest: AuditArchiveManifestV1) => ({ ...manifest, schemaVersion: 2 })],
    ["zero object bytes", (manifest: AuditArchiveManifestV1) => ({ ...manifest, objectBytes: 0 })],
  ])("rejects a manifest with %s before R2 access", async (_name, mutate) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    await restoreFailure(
      {
        bucket,
        expected: mutate(fixture.manifest) as unknown as AuditArchiveManifestV1,
        opener: new TestCustodyOpener(fixture.records),
      },
      "invalid_input",
    );
    expect(bucket.getCalls).toBe(0);
  });

  it("fails closed on a missing or unavailable object without provider details", async () => {
    const fixture = await restoreFixture();
    const missing = new FakeRestoreStore(fixture);
    missing.getMode = "null";
    await restoreFailure(input(fixture, missing), "object_missing");

    const unavailable = new FakeRestoreStore(fixture);
    unavailable.getMode = "throw";
    const failure = await restoreFailure(
      input(fixture, unavailable),
      "object_unavailable",
    );
    expect(failure.message).not.toContain("sensitive-r2-provider-detail");
  });

  it("does not inspect or forward thrown provider codes, cause, or accessors", async () => {
    const fixture = await restoreFixture();
    let codeRead = false;
    const thrown = Object.create(null) as Record<string, unknown>;
    Object.defineProperties(thrown, {
      cause: { value: new Error("sensitive-provider-cause") },
      code: {
        get() {
          codeRead = true;
          throw new Error("sensitive-provider-code-getter");
        },
      },
      message: { value: "sensitive-provider-message" },
    });
    const bucket: AuditArchiveRestoreStore = {
      async get() {
        throw thrown;
      },
    };
    const failure = await restoreFailure(
      input(fixture, bucket),
      "object_unavailable",
    );
    expect(codeRead).toBe(false);
    expect(failure.message).not.toContain("sensitive-provider-message");
    expect(JSON.stringify(failure)).not.toContain("sensitive-provider-cause");
  });

  it.each([
    ["object key", "object_identity_mismatch" as const],
    ["content type", "metadata_mismatch" as const],
    ["cache policy", "metadata_mismatch" as const],
    ["missing manifest metadata", "metadata_mismatch" as const],
    ["extra manifest metadata", "metadata_mismatch" as const],
    ["extra HTTP metadata", "metadata_mismatch" as const],
    ["malformed HTTP metadata", "metadata_mismatch" as const],
    ["self-derived divergent manifest", "metadata_mismatch" as const],
  ])("rejects wrong %s before opening the body", async (kind, code) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    if (kind === "object key") bucket.objectKey = `${fixture.manifest.objectKey}.other`;
    if (kind === "content type") {
      bucket.httpMetadata = {
        cacheControl: "no-store",
        contentType: "application/json",
      };
    }
    if (kind === "cache policy") {
      bucket.httpMetadata = {
        cacheControl: "public, max-age=60",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      };
    }
    if (kind === "missing manifest metadata") bucket.customMetadata = {};
    if (kind === "extra manifest metadata") {
      bucket.customMetadata = {
        [MANIFEST_METADATA_KEY]: JSON.stringify(fixture.manifest),
        extra: "not-allowed",
      };
    }
    if (kind === "extra HTTP metadata") {
      bucket.httpMetadata = {
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
        unexpected: "not-allowed",
      } as unknown as R2HTTPMetadata;
    }
    if (kind === "malformed HTTP metadata") {
      bucket.httpMetadata = [] as unknown as R2HTTPMetadata;
    }
    if (kind === "self-derived divergent manifest") {
      bucket.customMetadata = {
        [MANIFEST_METADATA_KEY]: JSON.stringify({
          ...fixture.manifest,
          keyVersion: "v2",
        }),
      };
    }
    await restoreFailure(input(fixture, bucket), code);
    expect(bucket.bodyAccesses).toBe(0);
  });

  it.each([
    ["missing", "missing" as const],
    ["malformed", "malformed" as const],
    ["wrong", "0".repeat(64)],
  ])("rejects a %s stored SHA-256 before reading the body", async (_name, checksum) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    bucket.storedChecksum = checksum;
    await restoreFailure(input(fixture, bucket), "checksum_mismatch");
    expect(bucket.bodyAccesses).toBe(0);
    expect(bucket.checksumBuffers).toEqual(bucket.checksumSnapshots);
  });

  it.each([
    ["zero", 0, "bounds_exceeded" as const],
    ["short", -1, "size_mismatch" as const],
    ["oversized", AUDIT_ARCHIVE_MAX_OBJECT_BYTES + 1, "bounds_exceeded" as const],
  ])("rejects a %s declared object size without body access", async (_name, size, code) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    bucket.reportedSize = size === -1 ? fixture.manifest.objectBytes - 1 : size;
    await restoreFailure(input(fixture, bucket), code);
    expect(bucket.bodyAccesses).toBe(0);
  });

  it.each([
    ["zero", "size_mismatch" as const, false],
    ["short", "size_mismatch" as const, false],
    ["done_value", "bounds_exceeded" as const, false],
    ["overflow", "bounds_exceeded" as const, true],
    ["empty_chunk", "stream_failed" as const, true],
    ["error", "stream_failed" as const, true],
  ] satisfies Array<[StreamMode, AuditArchiveRestoreErrorCode, boolean]>) (
    "fails closed on a %s stream and clears every delivered chunk",
    async (streamMode, code, cancelled) => {
      const fixture = await restoreFixture();
      const bucket = new FakeRestoreStore(fixture);
      bucket.streamMode = streamMode;
      await restoreFailure(input(fixture, bucket), code);
      expect(bucket.cancellations > 0).toBe(cancelled);
      expect(bucket.providedChunks).toEqual(bucket.providedChunkSnapshots);
    },
  );

  it("rejects an already-consumed body without opening or invoking custody", async () => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    const opener = new TestCustodyOpener(fixture.records);
    bucket.bodyUsed = true;
    await restoreFailure(input(fixture, bucket, opener), "stream_failed");
    expect(bucket.bodyAccesses).toBe(0);
    expect(opener.calls).toEqual([]);
  });

  it("rejects body bytes whose computed SHA-256 differs from stored identity", async () => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    bucket.objectBytes[0] ^= 1;
    await restoreFailure(input(fixture, bucket), "checksum_mismatch");
    expect(bucket.bodyAccesses).toBe(1);
  });

  it.each([
    ["key unavailable", { outcome: "key_unavailable" } as const, "custody_unavailable" as const],
    ["cryptographic integrity", { outcome: "crypto_integrity" } as const, "crypto_integrity" as const],
  ])("maps %s custody results to a closed redacted error", async (_name, result, code) => {
    const fixture = await restoreFixture();
    const opener = new TestCustodyOpener(fixture.records, result);
    await restoreFailure(input(fixture, new FakeRestoreStore(fixture), opener), code);
    expect(opener.calls[0]?.objectBytes.every((byte) => byte === 0)).toBe(true);
  });

  it("redacts thrown custody errors and clears its object copy", async () => {
    const fixture = await restoreFixture();
    const opener = new TestCustodyOpener(fixture.records, "throw");
    const failure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), opener),
      "internal_error",
    );
    expect(failure.message).not.toContain("sensitive-custody-provider-detail");
    expect(opener.calls[0]?.objectBytes.every((byte) => byte === 0)).toBe(true);
  });

  it("rejects a malformed custody result without passing provider fields through", async () => {
    const fixture = await restoreFixture();
    const calls: AuditArchiveCustodyOpenInput[] = [];
    const opener: AuditArchiveCustodyOpener = {
      async open(value) {
        calls.push(value);
        return {
          outcome: "opened",
          records: fixture.records,
          providerDetail: "sensitive-provider-result-detail",
        } as unknown as AuditArchiveCustodyOpenResult;
      },
    };
    const failure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), opener),
      "internal_error",
    );
    expect(failure.message).not.toContain("sensitive-provider-result-detail");
    expect(calls[0]?.objectBytes.every((byte) => byte === 0)).toBe(true);
  });

  it.each([
    ["extra record field", (fixture: RestoreFixture) => [{ ...fixture.records[0], extra: true }, fixture.records[1]]],
    ["missing record", (fixture: RestoreFixture) => fixture.records.slice(0, 1)],
    ["wrong first sequence", (fixture: RestoreFixture) => [{ ...fixture.records[0], sequence: 2 }, fixture.records[1]]],
    ["duplicate event", (fixture: RestoreFixture) => [fixture.records[0], { ...fixture.records[1], eventId: fixture.records[0]?.eventId }]],
  ])("rejects a provider's %s as a noncanonical or divergent record set", async (_name, mutate) => {
    const fixture = await restoreFixture();
    const opener = new TestCustodyOpener(
      mutate(fixture) as unknown as readonly AuditArchiveRecordV1[],
    );
    await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), opener),
      "record_mismatch",
    );
  });

  it("rejects a record set that diverges only from the trusted plaintext digest", async () => {
    const fixture = await restoreFixture();
    const expected = {
      ...fixture.manifest,
      plaintextSha256: "0".repeat(64),
    };
    const expectedFixture = { ...fixture, manifest: expected };
    await restoreFailure(
      input(expectedFixture, new FakeRestoreStore(expectedFixture)),
      "record_mismatch",
    );
  });

  it("returns detached records despite opener input and post-return mutation", async () => {
    const fixture = await restoreFixture();
    const providerRecords = structuredClone(fixture.records);
    const opener = new TestCustodyOpener(providerRecords);
    opener.mutateInput = true;
    const restored = await verifyAndOpenAuditArchiveObjectV1(
      input(fixture, new FakeRestoreStore(fixture), opener),
    );

    providerRecords[0]!.eventId = "audit.restore.provider-mutated";
    providerRecords.splice(1);
    expect(restored).toEqual(fixture.records);
    expect(restored).toHaveLength(2);
    expect(fixture.manifest.objectKey).not.toBe("audit/v1/provider-mutated");
  });

  it("keeps errors enumerable, closed, and free of bodies or full records", async () => {
    const fixture = await restoreFixture();
    const opener = new TestCustodyOpener(fixture.records, "throw");
    const failure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), opener),
      "internal_error",
    );
    const serialized = JSON.stringify(failure);
    expect(serialized).toContain('"code":"internal_error"');
    expect(serialized).not.toContain(fixture.records[0]!.eventId);
    expect(serialized).not.toContain(fixture.records[0]!.metadataJson!);
    expect(failure.message).not.toContain(
      new TextDecoder().decode(fixture.objectBytes),
    );
  });
});
