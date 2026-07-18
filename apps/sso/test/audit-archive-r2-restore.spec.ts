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
  AUDIT_ARCHIVE_MAX_RECORDS,
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
  | "detached_chunk"
  | "empty_chunk"
  | "error"
  | "malformed_chunk"
  | "normal"
  | "overflow"
  | "short"
  | "wrong_typed_array"
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
  bodyFailure: unknown;
  bodyMode: "normal" | "throw" = "normal";
  bodyAccesses = 0;
  bodyUsed = false;
  cancellationMode: "normal" | "throw" = "normal";
  cancellations = 0;
  checksumBuffers: Uint8Array<ArrayBuffer>[] = [];
  checksumSnapshots: Uint8Array<ArrayBuffer>[] = [];
  checksumSliceCalls = 0;
  checksumSliceMode: "forged" | "normal" | "throwing_getter" = "normal";
  customMetadata: Record<string, string> | null = null;
  getCalls = 0;
  getMode: "normal" | "null" | "throw" = "normal";
  httpMetadata: R2HTTPMetadata | null = null;
  objectBytes: Uint8Array<ArrayBuffer>;
  objectKey: string;
  providedChunks: Uint8Array<ArrayBufferLike>[] = [];
  providedChunkSnapshots: Uint8Array<ArrayBuffer>[] = [];
  readCalls = 0;
  reportedSize: number;
  requestedKeys: string[] = [];
  storedChecksum: "malformed" | "missing" | string;
  shadowStreamMethods = false;
  streamFailure: unknown;
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
    if (this.checksumSliceMode === "throwing_getter") {
      Object.defineProperty(checksum, "slice", {
        get: () => {
          this.checksumSliceCalls += 1;
          throw new Error("sensitive-checksum-slice-getter");
        },
      });
    }
    if (this.checksumSliceMode === "forged") {
      Object.defineProperty(checksum, "slice", {
        value: () => {
          this.checksumSliceCalls += 1;
          return hexBuffer(this.fixture.manifest.objectSha256);
        },
      });
    }
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
    let chunks: unknown[] = bytes.byteLength === 0
      ? []
      : [bytes.slice(0, split), bytes.slice(split)].filter(
        (chunk) => chunk.byteLength > 0,
      );
    if (this.streamMode === "empty_chunk") chunks = [new Uint8Array()];
    if (this.streamMode === "malformed_chunk") chunks = [{ bytes: "invalid" }];
    if (this.streamMode === "wrong_typed_array") {
      chunks = [new Int16Array([1])];
    }
    if (this.streamMode === "detached_chunk") {
      const detached = bytes.slice(0, 1);
      structuredClone(detached.buffer, { transfer: [detached.buffer] });
      chunks = [detached];
    }
    bytes.fill(0);
    let index = 0;
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array<ArrayBufferLike>>(
      {
        cancel: () => {
          this.cancellations += 1;
          if (this.cancellationMode === "throw") {
            throw new Error("sensitive-stream-cancel-detail");
          }
        },
        pull: (controller) => {
          this.readCalls += 1;
          if (this.streamMode === "error" && pulls > 0) {
            controller.error(
              this.streamFailure ??
                new Error("sensitive-stream-provider-detail"),
            );
            return;
          }
          pulls += 1;
          const chunk = chunks[index];
          if (chunk === undefined) {
            controller.close();
            return;
          }
          index += 1;
          if (chunk instanceof Uint8Array) {
            this.providedChunks.push(chunk);
            try {
              this.providedChunkSnapshots.push(new Uint8Array(chunk));
            } catch {
              this.providedChunkSnapshots.push(new Uint8Array());
            }
          }
          controller.enqueue(chunk as Uint8Array<ArrayBufferLike>);
        },
      },
      { highWaterMark: 0 },
    );
    if (this.shadowStreamMethods) {
      Object.defineProperties(stream, {
        cancel: {
          get: () => {
            throw new Error("sensitive-own-stream-cancel");
          },
        },
        getReader: {
          get: () => {
            throw new Error("sensitive-own-stream-reader");
          },
        },
      });
    }
    return stream;
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
        store.bodyAccesses += 1;
        if (store.bodyMode === "throw") {
          throw store.bodyFailure ?? new Error("sensitive-body-getter-detail");
        }
        body ??= store.stream();
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

function withManifest(
  fixture: RestoreFixture,
  overrides: Partial<AuditArchiveManifestV1>,
): RestoreFixture {
  const manifest = { ...fixture.manifest, ...overrides };
  manifest.objectKey = `audit/v1/${String(manifest.firstSequence).padStart(
    16,
    "0",
  )}-${String(manifest.lastSequence).padStart(16, "0")}/${
    manifest.objectSha256
  }.pgid-audit`;
  return { ...fixture, manifest };
}

function forgedProviderError(
  code: AuditArchiveRestoreErrorCode,
): { error: unknown; trapReads: () => number } {
  let reads = 0;
  const error = new Proxy(Object.create(null), {
    get() {
      reads += 1;
      throw new Error("sensitive-forged-error-get");
    },
    getOwnPropertyDescriptor(_target, key) {
      reads += 1;
      return key === "code"
        ? {
          configurable: true,
          enumerable: true,
          value: code,
          writable: false,
        }
        : undefined;
    },
    getPrototypeOf() {
      reads += 1;
      return AuditArchiveRestoreError.prototype;
    },
  });
  return { error, trapReads: () => reads };
}

function expectNoProviderSentinel(failure: AuditArchiveRestoreError): void {
  expect(failure.message).not.toContain("sensitive-");
  expect(JSON.stringify(failure)).not.toContain("sensitive-");
}

describe("pure audit archive R2 restore verifier", () => {
  it("rejects invalid arity with a fresh closed error", async () => {
    await expect(
      Reflect.apply(verifyAndOpenAuditArchiveObjectV1, undefined, []),
    ).rejects.toMatchObject({ code: "invalid_input" });
    await expect(
      Reflect.apply(verifyAndOpenAuditArchiveObjectV1, undefined, [
        undefined,
        undefined,
      ]),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

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
      "invalid_input",
    );
    expect(bucket.getCalls).toBe(0);
    expect(failure.message).not.toContain("sensitive-hostile-manifest-detail");
  });

  it("rejects a dynamic manifest key without invoking its accessor", async () => {
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
    await restoreFailure(
      {
        bucket,
        expected: dynamic,
        opener: new TestCustodyOpener(fixture.records),
      },
      "invalid_input",
    );
    expect(reads).toBe(0);
    expect(bucket.requestedKeys).toEqual([]);
  });

  it.each([
    ["extra field", (manifest: AuditArchiveManifestV1) => ({ ...manifest, extra: true })],
    ["wrong contract", (manifest: AuditArchiveManifestV1) => ({ ...manifest, contract: "legacy" })],
    ["wrong content type", (manifest: AuditArchiveManifestV1) => ({ ...manifest, contentType: "application/json" })],
    ["wrong schema", (manifest: AuditArchiveManifestV1) => ({ ...manifest, schemaVersion: 2 })],
    ["zero batch generation", (manifest: AuditArchiveManifestV1) => ({ ...manifest, batchGeneration: 0 })],
    ["checkpoint at first sequence", (manifest: AuditArchiveManifestV1) => ({ ...manifest, checkpointFromSequence: manifest.firstSequence })],
    ["zero event count", (manifest: AuditArchiveManifestV1) => ({ ...manifest, eventCount: 0 })],
    ["excess event count", (manifest: AuditArchiveManifestV1) => ({ ...manifest, eventCount: AUDIT_ARCHIVE_MAX_RECORDS + 1 })],
    ["reversed sequence range", (manifest: AuditArchiveManifestV1) => ({ ...manifest, lastSequence: 0 })],
    ["invalid key version", (manifest: AuditArchiveManifestV1) => ({ ...manifest, keyVersion: "latest" })],
    ["noncanonical timestamp", (manifest: AuditArchiveManifestV1) => ({ ...manifest, createdAt: "2026-07-18" })],
    ["invalid object digest", (manifest: AuditArchiveManifestV1) => ({ ...manifest, objectSha256: "ABC" })],
    ["invalid plaintext digest", (manifest: AuditArchiveManifestV1) => ({ ...manifest, plaintextSha256: "xyz" })],
    ["zero object bytes", (manifest: AuditArchiveManifestV1) => ({ ...manifest, objectBytes: 0 })],
    ["oversized object bytes", (manifest: AuditArchiveManifestV1) => ({ ...manifest, objectBytes: AUDIT_ARCHIVE_MAX_OBJECT_BYTES + 1 })],
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

  it("rejects hidden and symbol manifest extras without dependency resolution", async () => {
    const fixture = await restoreFixture();
    for (const kind of ["hidden", "symbol"] as const) {
      const expected = { ...fixture.manifest } as AuditArchiveManifestV1 &
        Record<PropertyKey, unknown>;
      if (kind === "hidden") {
        Object.defineProperty(expected, "hidden-extra", { value: true });
      } else {
        expected[Symbol("manifest-extra")] = true;
      }
      let getReads = 0;
      let openReads = 0;
      const bucket = {
        get get() {
          getReads += 1;
          return async () => null;
        },
      };
      const opener = {
        get open() {
          openReads += 1;
          return async () => ({ outcome: "key_unavailable" as const });
        },
      };
      await restoreFailure({ bucket, expected, opener }, "invalid_input");
      expect(getReads).toBe(0);
      expect(openReads).toBe(0);
    }
  });

  it("validates an invalid manifest before bucket or opener accessors and calls", async () => {
    const fixture = await restoreFixture();
    let getReads = 0;
    let getCalls = 0;
    let openReads = 0;
    let openCalls = 0;
    const bucket = {
      get get() {
        getReads += 1;
        return async () => {
          getCalls += 1;
          return null;
        };
      },
    };
    const opener = {
      get open() {
        openReads += 1;
        return async () => {
          openCalls += 1;
          return { outcome: "key_unavailable" as const };
        };
      },
    };
    await restoreFailure(
      {
        bucket,
        expected: { ...fixture.manifest, objectKey: "audit/v1/invalid" },
        opener,
      },
      "invalid_input",
    );
    expect({ getCalls, getReads, openCalls, openReads }).toEqual({
      getCalls: 0,
      getReads: 0,
      openCalls: 0,
      openReads: 0,
    });
  });

  it.each(["accessor", "hidden extra", "symbol extra"] as const)(
    "rejects a top-level input %s without invoking it",
    async (kind) => {
      const fixture = await restoreFixture();
      const bucket = new FakeRestoreStore(fixture);
      const opener = new TestCustodyOpener(fixture.records);
      let accessorReads = 0;
      const value = {
        bucket,
        expected: fixture.manifest,
        opener,
      } as VerifyAndOpenAuditArchiveObjectInput & Record<PropertyKey, unknown>;
      if (kind === "accessor") {
        Object.defineProperty(value, "bucket", {
          get() {
            accessorReads += 1;
            return bucket;
          },
        });
      }
      if (kind === "hidden extra") {
        Object.defineProperty(value, "hidden-extra", { value: true });
      }
      if (kind === "symbol extra") value[Symbol("input-extra")] = true;
      await restoreFailure(value, "invalid_input");
      expect(accessorReads).toBe(0);
      expect(bucket.getCalls).toBe(0);
      expect(opener.calls).toEqual([]);
    },
  );

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

  it("defines exact exported error fields while keeping its prototype extensible", () => {
    const error = new AuditArchiveRestoreError("object_missing");

    expect(Object.getOwnPropertyDescriptor(error, "name")).toEqual({
      configurable: true,
      enumerable: true,
      value: "AuditArchiveRestoreError",
      writable: true,
    });
    expect(Object.getOwnPropertyDescriptor(error, "code")).toEqual({
      configurable: true,
      enumerable: true,
      value: "object_missing",
      writable: true,
    });
    expect(Object.getOwnPropertyDescriptor(error, "message")).toEqual({
      configurable: true,
      enumerable: false,
      value: "Audit archive restore verification failed (object_missing)",
      writable: true,
    });
    expect(Object.isFrozen(AuditArchiveRestoreError)).toBe(true);
    expect(Object.isExtensible(AuditArchiveRestoreError.prototype)).toBe(true);
  });

  it("keeps exported and Proxy-forged errors outside private failure provenance", async () => {
    const fixture = await restoreFixture();
    const injected = new AuditArchiveRestoreError("object_missing");
    const topLevel = new Proxy(input(fixture), {
      ownKeys() {
        throw injected;
      },
    });
    const inputFailure = await restoreFailure(topLevel, "invalid_input");
    expect(inputFailure).not.toBe(injected);

    const bucketGetter: AuditArchiveRestoreStore = Object.create(null);
    Object.defineProperty(bucketGetter, "get", {
      get() {
        throw injected;
      },
    });
    const bucketFailure = await restoreFailure(
      input(fixture, bucketGetter),
      "object_unavailable",
    );
    expect(bucketFailure).not.toBe(injected);

    const forged = forgedProviderError("record_mismatch");
    const store = new FakeRestoreStore(fixture);
    const object = await store.get(fixture.manifest.objectKey);
    if (!object) throw new Error("restore fixture object missing");
    Object.defineProperty(object, "key", {
      get() {
        throw forged.error;
      },
    });
    const fieldFailure = await restoreFailure(
      input(fixture, { get: async () => object }),
      "object_unavailable",
    );
    expect(forged.trapReads()).toBe(0);
    expectNoProviderSentinel(fieldFailure);
  });

  it("uses fixed metadata and checksum codes for forged nested failures", async () => {
    const fixture = await restoreFixture();

    const metadataForged = forgedProviderError("object_missing");
    const metadataStore = new FakeRestoreStore(fixture);
    metadataStore.httpMetadata = new Proxy(
      {
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      },
      {
        ownKeys() {
          throw metadataForged.error;
        },
      },
    );
    const metadataFailure = await restoreFailure(
      input(fixture, metadataStore),
      "metadata_mismatch",
    );
    expect(metadataForged.trapReads()).toBe(0);
    expectNoProviderSentinel(metadataFailure);

    const checksumForged = forgedProviderError("object_missing");
    const checksumStore = new FakeRestoreStore(fixture);
    const object = await checksumStore.get(fixture.manifest.objectKey);
    if (!object) throw new Error("restore fixture object missing");
    Object.defineProperty(object, "checksums", {
      value: {
        get sha256() {
          throw checksumForged.error;
        },
      },
    });
    const checksumFailure = await restoreFailure(
      input(fixture, { get: async () => object }),
      "checksum_mismatch",
    );
    expect(checksumForged.trapReads()).toBe(0);
    expectNoProviderSentinel(checksumFailure);
  });

  it.each([
    "size",
    "httpMetadata",
    "customMetadata",
    "checksums",
  ] as const)("maps a throwing outer R2 %s getter to object_unavailable", async (field) => {
    const fixture = await restoreFixture();
    const store = new FakeRestoreStore(fixture);
    const object = await store.get(fixture.manifest.objectKey);
    if (!object) throw new Error("restore fixture object missing");
    const injected = new AuditArchiveRestoreError("record_mismatch");
    Object.defineProperty(object, field, {
      get() {
        throw injected;
      },
    });
    const failure = await restoreFailure(
      input(fixture, { get: async () => object }),
      "object_unavailable",
    );
    expect(failure).not.toBe(injected);
    expectNoProviderSentinel(failure);
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
  ])("rejects wrong %s without reading body chunks", async (kind, code) => {
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
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.readCalls).toBe(0);
    expect(bucket.cancellations).toBe(1);
  });

  it("accepts exact two-field and Workerd-shaped six-field metadata projections", async () => {
    const fixture = await restoreFixture();
    const projections: R2HTTPMetadata[] = [
      {
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      },
      {
        cacheControl: "no-store",
        cacheExpiry: undefined,
        contentDisposition: undefined,
        contentEncoding: undefined,
        contentLanguage: undefined,
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      },
    ];
    for (const projection of projections) {
      let propertyReads = 0;
      const bucket = new FakeRestoreStore(fixture);
      bucket.httpMetadata = new Proxy(projection, {
        get() {
          propertyReads += 1;
          throw new Error("sensitive-metadata-get");
        },
      });
      const customMetadata = Object.create(null) as Record<string, string>;
      customMetadata[MANIFEST_METADATA_KEY] = JSON.stringify(fixture.manifest);
      bucket.customMetadata = customMetadata;
      await expect(
        verifyAndOpenAuditArchiveObjectV1(input(fixture, bucket)),
      ).resolves.toEqual(fixture.records);
      expect(propertyReads).toBe(0);
    }
  });

  it.each([
    "inherited required HTTP fields",
    "HTTP accessor",
    "custom accessor",
    "hidden custom extra",
    "HTTP symbol extra",
  ])("rejects %s as non-exact metadata without invoking accessors", async (kind) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    let accessorReads = 0;
    if (kind === "inherited required HTTP fields") {
      bucket.httpMetadata = Object.create({
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      }) as R2HTTPMetadata;
    }
    if (kind === "HTTP accessor") {
      const metadata = { cacheControl: "no-store" };
      Object.defineProperty(metadata, "contentType", {
        get() {
          accessorReads += 1;
          return AUDIT_ARCHIVE_CONTENT_TYPE;
        },
      });
      bucket.httpMetadata = metadata as R2HTTPMetadata;
    }
    if (kind === "custom accessor") {
      const metadata = Object.create(null);
      Object.defineProperty(metadata, MANIFEST_METADATA_KEY, {
        get() {
          accessorReads += 1;
          return JSON.stringify(fixture.manifest);
        },
      });
      bucket.customMetadata = metadata as Record<string, string>;
    }
    if (kind === "hidden custom extra") {
      const metadata = {
        [MANIFEST_METADATA_KEY]: JSON.stringify(fixture.manifest),
      };
      Object.defineProperty(metadata, "hidden-extra", { value: "rejected" });
      bucket.customMetadata = metadata;
    }
    if (kind === "HTTP symbol extra") {
      const metadata = {
        cacheControl: "no-store",
        contentType: AUDIT_ARCHIVE_CONTENT_TYPE,
      } as R2HTTPMetadata & Record<PropertyKey, unknown>;
      metadata[Symbol("metadata-extra")] = "rejected";
      bucket.httpMetadata = metadata;
    }
    await restoreFailure(input(fixture, bucket), "metadata_mismatch");
    expect(accessorReads).toBe(0);
    expect(bucket.readCalls).toBe(0);
    expect(bucket.cancellations).toBe(1);
  });

  it.each([
    ["missing", "missing" as const],
    ["malformed", "malformed" as const],
    ["wrong", "0".repeat(64)],
  ])("rejects a %s stored SHA-256 with zero body reads", async (_name, checksum) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    bucket.storedChecksum = checksum;
    await restoreFailure(input(fixture, bucket), "checksum_mismatch");
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.readCalls).toBe(0);
    expect(bucket.cancellations).toBe(1);
    expect(bucket.checksumBuffers).toEqual(bucket.checksumSnapshots);
  });

  it("copies borrowed checksum bytes without invoking a shadowed slice", async () => {
    const fixture = await restoreFixture();
    const accepted = new FakeRestoreStore(fixture);
    accepted.checksumSliceMode = "throwing_getter";
    await expect(
      verifyAndOpenAuditArchiveObjectV1(input(fixture, accepted)),
    ).resolves.toEqual(fixture.records);
    expect(accepted.checksumSliceCalls).toBe(0);
    expect(accepted.checksumBuffers).toEqual(accepted.checksumSnapshots);

    const rejected = new FakeRestoreStore(fixture);
    rejected.storedChecksum = "0".repeat(64);
    rejected.checksumSliceMode = "forged";
    await restoreFailure(input(fixture, rejected), "checksum_mismatch");
    expect(rejected.checksumSliceCalls).toBe(0);
    expect(rejected.checksumBuffers).toEqual(rejected.checksumSnapshots);
  });

  it.each([
    ["zero", 0, "bounds_exceeded" as const],
    ["short", -1, "size_mismatch" as const],
    ["oversized", AUDIT_ARCHIVE_MAX_OBJECT_BYTES + 1, "bounds_exceeded" as const],
  ])("rejects a %s declared object size with zero body reads", async (_name, size, code) => {
    const fixture = await restoreFixture();
    const bucket = new FakeRestoreStore(fixture);
    bucket.reportedSize = size === -1 ? fixture.manifest.objectBytes - 1 : size;
    await restoreFailure(input(fixture, bucket), code);
    expect(bucket.bodyAccesses).toBe(1);
    expect(bucket.readCalls).toBe(0);
    expect(bucket.cancellations).toBe(1);
  });

  it("preserves the primary early-rejection code across unused-body cleanup failures", async () => {
    const fixture = await restoreFixture();

    const rejectedCancel = new FakeRestoreStore(fixture);
    rejectedCancel.objectKey = `${fixture.manifest.objectKey}.other`;
    rejectedCancel.cancellationMode = "throw";
    const cancelFailure = await restoreFailure(
      input(fixture, rejectedCancel),
      "object_identity_mismatch",
    );
    expect(rejectedCancel.readCalls).toBe(0);
    expect(rejectedCancel.cancellations).toBe(1);
    expectNoProviderSentinel(cancelFailure);

    const rejectedBody = new FakeRestoreStore(fixture);
    rejectedBody.objectKey = `${fixture.manifest.objectKey}.other`;
    rejectedBody.bodyMode = "throw";
    const bodyFailure = await restoreFailure(
      input(fixture, rejectedBody),
      "object_identity_mismatch",
    );
    expect(rejectedBody.bodyAccesses).toBe(1);
    expect(rejectedBody.readCalls).toBe(0);
    expectNoProviderSentinel(bodyFailure);

    const shadowedCancel = new FakeRestoreStore(fixture);
    shadowedCancel.objectKey = `${fixture.manifest.objectKey}.other`;
    shadowedCancel.shadowStreamMethods = true;
    await restoreFailure(
      input(fixture, shadowedCancel),
      "object_identity_mismatch",
    );
    expect(shadowedCancel.readCalls).toBe(0);
    expect(shadowedCancel.cancellations).toBe(1);
  });

  it.each([
    ["zero", "size_mismatch" as const, false],
    ["short", "size_mismatch" as const, false],
    ["overflow", "bounds_exceeded" as const, true],
    ["empty_chunk", "stream_failed" as const, true],
    ["detached_chunk", "stream_failed" as const, true],
    ["malformed_chunk", "stream_failed" as const, true],
    ["wrong_typed_array", "stream_failed" as const, true],
    ["error", "stream_failed" as const, false],
  ] satisfies Array<[StreamMode, AuditArchiveRestoreErrorCode, boolean]>) (
    "fails closed on a %s stream and preserves provider chunks",
    async (streamMode, code, cancelled) => {
      const fixture = await restoreFixture();
      const bucket = new FakeRestoreStore(fixture);
      bucket.streamMode = streamMode;
      await restoreFailure(input(fixture, bucket), code);
      expect(bucket.cancellations > 0).toBe(cancelled);
      if (streamMode === "detached_chunk") {
        expect(bucket.providedChunks).toHaveLength(1);
        expect(bucket.providedChunks[0]?.byteLength).toBe(0);
      } else {
        expect(bucket.providedChunks).toEqual(bucket.providedChunkSnapshots);
      }
    },
  );

  it("uses captured stream methods and fixed codes for hostile body and reader failures", async () => {
    const fixture = await restoreFixture();

    const shadowed = new FakeRestoreStore(fixture);
    shadowed.shadowStreamMethods = true;
    await expect(
      verifyAndOpenAuditArchiveObjectV1(input(fixture, shadowed)),
    ).resolves.toEqual(fixture.records);

    const bodyInjected = new AuditArchiveRestoreError("object_missing");
    const bodyFailureStore = new FakeRestoreStore(fixture);
    bodyFailureStore.bodyMode = "throw";
    bodyFailureStore.bodyFailure = bodyInjected;
    const bodyFailure = await restoreFailure(
      input(fixture, bodyFailureStore),
      "stream_failed",
    );
    expect(bodyFailure).not.toBe(bodyInjected);

    const readForged = forgedProviderError("object_missing");
    const readFailureStore = new FakeRestoreStore(fixture);
    readFailureStore.streamMode = "error";
    readFailureStore.streamFailure = readForged.error;
    const readFailure = await restoreFailure(
      input(fixture, readFailureStore),
      "stream_failed",
    );
    expect(readForged.trapReads()).toBe(0);
    expectNoProviderSentinel(readFailure);

    const cleanupFailureStore = new FakeRestoreStore(fixture);
    cleanupFailureStore.streamMode = "overflow";
    cleanupFailureStore.cancellationMode = "throw";
    const cleanupFailure = await restoreFailure(
      input(fixture, cleanupFailureStore),
      "bounds_exceeded",
    );
    expect(cleanupFailureStore.cancellations).toBe(1);
    expectNoProviderSentinel(cleanupFailure);
  });

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

    const injected = new AuditArchiveRestoreError("object_missing");
    const injectedFailure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), {
        async open() {
          throw injected;
        },
      }),
      "internal_error",
    );
    expect(injectedFailure).not.toBe(injected);
  });

  it("uses independent intrinsic wipes for overridden and detached opener buffers", async () => {
    const fixture = await restoreFixture();
    let fillReads = 0;
    let overriddenBytes: Uint8Array<ArrayBuffer> | undefined;
    const overridingOpener: AuditArchiveCustodyOpener = {
      async open(value) {
        overriddenBytes = value.objectBytes;
        Object.defineProperty(value.objectBytes, "fill", {
          get() {
            fillReads += 1;
            throw new Error("sensitive-provider-cleanup-sentinel");
          },
        });
        return { outcome: "opened", records: fixture.records };
      },
    };
    await expect(
      verifyAndOpenAuditArchiveObjectV1(
        input(fixture, new FakeRestoreStore(fixture), overridingOpener),
      ),
    ).resolves.toEqual(fixture.records);
    expect(fillReads).toBe(0);
    expect(overriddenBytes?.every((byte) => byte === 0)).toBe(true);

    const failingOpener: AuditArchiveCustodyOpener = {
      async open(value) {
        Object.defineProperty(value.objectBytes, "fill", {
          value() {
            throw new Error("sensitive-provider-cleanup-sentinel");
          },
        });
        return { outcome: "key_unavailable" };
      },
    };
    const fixedFailure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), failingOpener),
      "custody_unavailable",
    );
    expectNoProviderSentinel(fixedFailure);

    let detachedBytes: Uint8Array<ArrayBuffer> | undefined;
    const detachingOpener: AuditArchiveCustodyOpener = {
      async open(value) {
        detachedBytes = value.objectBytes;
        structuredClone(value.objectBytes.buffer, {
          transfer: [value.objectBytes.buffer],
        });
        return { outcome: "opened", records: fixture.records };
      },
    };
    await expect(
      verifyAndOpenAuditArchiveObjectV1(
        input(fixture, new FakeRestoreStore(fixture), detachingOpener),
      ),
    ).resolves.toEqual(fixture.records);
    expect(detachedBytes?.byteLength).toBe(0);
  });

  it("uses captured invocation when methods shadow call and thenables throw", async () => {
    const fixture = await restoreFixture();
    const store = new FakeRestoreStore(fixture);
    const opener = new TestCustodyOpener(fixture.records);
    let callReads = 0;
    const getObject = (key: string) => store.get(key);
    const openObject = (value: AuditArchiveCustodyOpenInput) => opener.open(value);
    for (const method of [getObject, openObject]) {
      Object.defineProperty(method, "call", {
        get() {
          callReads += 1;
          throw new Error("sensitive-call-getter");
        },
      });
    }
    await expect(
      verifyAndOpenAuditArchiveObjectV1({
        bucket: { get: getObject },
        expected: fixture.manifest,
        opener: { open: openObject },
      }),
    ).resolves.toEqual(fixture.records);
    expect(callReads).toBe(0);

    const injected = new AuditArchiveRestoreError("object_missing");
    const bucketThenable = Object.create(null);
    Object.defineProperty(bucketThenable, "then", {
      get() {
        throw injected;
      },
    });
    const throwingThenable = bucketThenable as Promise<R2ObjectBody | null>;
    const bucketFailure = await restoreFailure(
      input(fixture, { get: () => throwingThenable }),
      "object_unavailable",
    );
    expect(bucketFailure).not.toBe(injected);

    const custodyThenable = Object.create(null);
    Object.defineProperty(custodyThenable, "then", {
      get() {
        throw injected;
      },
    });
    const openerThenable = custodyThenable as Promise<AuditArchiveCustodyOpenResult>;
    const openerFailure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), {
        open: () => openerThenable,
      }),
      "internal_error",
    );
    expect(openerFailure).not.toBe(injected);
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

  it("rejects custody result and record accessors, holes, extras, and Proxy traps", async () => {
    const fixture = await restoreFixture();
    let accessorReads = 0;
    const resultAccessor = Object.create(null);
    Object.defineProperty(resultAccessor, "outcome", {
      get() {
        accessorReads += 1;
        return "opened";
      },
    });
    await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), {
        open: async () => resultAccessor,
      } as AuditArchiveCustodyOpener),
      "internal_error",
    );
    expect(accessorReads).toBe(0);

    const recordsAccessor = { outcome: "opened" };
    Object.defineProperty(recordsAccessor, "records", {
      get() {
        accessorReads += 1;
        return fixture.records;
      },
    });
    await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), {
        open: async () => recordsAccessor,
      } as AuditArchiveCustodyOpener),
      "internal_error",
    );
    expect(accessorReads).toBe(0);

    const hiddenResult = {
      outcome: "opened",
      records: fixture.records,
    };
    Object.defineProperty(hiddenResult, "hidden-extra", { value: true });
    const symbolResult = {
      outcome: "opened",
      records: fixture.records,
    } as Record<PropertyKey, unknown>;
    symbolResult[Symbol("result-extra")] = true;
    for (const result of [hiddenResult, symbolResult]) {
      await restoreFailure(
        input(fixture, new FakeRestoreStore(fixture), {
          open: async () => result,
        } as AuditArchiveCustodyOpener),
        "internal_error",
      );
    }

    const arrays: unknown[] = [];
    const holey = [fixture.records[0], , fixture.records[1]];
    arrays.push(holey);
    const indexed = [...fixture.records];
    delete indexed[0];
    Object.defineProperty(indexed, "0", {
      get() {
        accessorReads += 1;
        return fixture.records[0];
      },
    });
    arrays.push(indexed);
    const hiddenArray = [...fixture.records];
    Object.defineProperty(hiddenArray, "hidden-extra", { value: true });
    arrays.push(hiddenArray);
    const symbolArray = [...fixture.records] as Array<AuditArchiveRecordV1> &
      Record<PropertyKey, unknown>;
    symbolArray[Symbol("records-extra")] = true;
    arrays.push(symbolArray);

    for (const records of arrays) {
      await restoreFailure(
        input(fixture, new FakeRestoreStore(fixture), {
          open: async () => ({ outcome: "opened", records }),
        } as AuditArchiveCustodyOpener),
        "record_mismatch",
      );
    }
    expect(accessorReads).toBe(0);

    const recordAccessor = { ...fixture.records[0] };
    Object.defineProperty(recordAccessor, "eventId", {
      get() {
        accessorReads += 1;
        return fixture.records[0]?.eventId;
      },
    });
    const hiddenRecord = { ...fixture.records[0] };
    Object.defineProperty(hiddenRecord, "hidden-extra", { value: true });
    const symbolRecord = { ...fixture.records[0] } as AuditArchiveRecordV1 &
      Record<PropertyKey, unknown>;
    symbolRecord[Symbol("record-extra")] = true;
    const forged = forgedProviderError("object_missing");
    const proxyRecord = new Proxy(fixture.records[0]!, {
      ownKeys() {
        throw forged.error;
      },
    });
    for (const recordValue of [
      recordAccessor,
      hiddenRecord,
      symbolRecord,
      proxyRecord,
    ]) {
      await restoreFailure(
        input(fixture, new FakeRestoreStore(fixture), {
          open: async () => ({
            outcome: "opened",
            records: [recordValue, fixture.records[1]],
          }),
        } as AuditArchiveCustodyOpener),
        "record_mismatch",
      );
    }
    expect(accessorReads).toBe(0);
    expect(forged.trapReads()).toBe(0);

    const resultForged = forgedProviderError("object_missing");
    const resultProxy = new Proxy(Object.create(null), {
      ownKeys() {
        throw resultForged.error;
      },
    });
    const resultFailure = await restoreFailure(
      input(fixture, new FakeRestoreStore(fixture), {
        open: async () => resultProxy,
      } as AuditArchiveCustodyOpener),
      "internal_error",
    );
    expect(resultForged.trapReads()).toBe(0);
    expectNoProviderSentinel(resultFailure);
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

  it.each([
    ["event count", { eventCount: 3 }],
    ["first sequence", { firstSequence: 2 }],
    ["last sequence", { lastSequence: 4 }],
  ] satisfies Array<[
    string,
    Partial<AuditArchiveManifestV1>,
  ]>)("independently binds the manifest %s after plaintext verification", async (_name, overrides) => {
    const fixture = await restoreFixture();
    const divergent = withManifest(fixture, overrides);
    await restoreFailure(
      input(divergent, new FakeRestoreStore(divergent)),
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
