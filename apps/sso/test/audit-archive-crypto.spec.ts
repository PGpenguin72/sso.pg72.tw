import { describe, expect, expectTypeOf, it } from "vitest";

import {
  AUDIT_ARCHIVE_CONTENT_TYPE,
  AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
  AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES,
  AUDIT_ARCHIVE_MAX_RECORDS,
  AuditArchiveCryptoError,
  type AuditArchiveManifestV1,
  type AuditArchiveRecordV1,
  encodeCanonicalAuditRecordsV1,
  openAuditArchiveV1,
  sealAuditArchiveV1,
} from "../worker/audit-archive-crypto";

const CREATED_AT = "2026-07-17T00:00:00.000Z";

function base64Url(bytes: Uint8Array<ArrayBuffer>): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function generatedKek(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(new ArrayBuffer(32))));
}

function credentialMarker(kind: "at" | "cs" | "rt"): string {
  return `pg72_${kind}_`;
}

function record(
  sequence: number,
  overrides: Partial<AuditArchiveRecordV1> = {},
): AuditArchiveRecordV1 {
  return {
    actorUserId: crypto.randomUUID(),
    clientId: "pg72-test-rp",
    eventId: crypto.randomUUID(),
    eventType: "passkey.step_up_succeeded",
    ipHash: null,
    metadataJson: JSON.stringify({ method: "passkey", sequence }),
    occurredAt: new Date(Date.parse(CREATED_AT) + sequence).toISOString(),
    outcome: "success",
    sequence,
    sessionId: crypto.randomUUID(),
    subjectId: crypto.randomUUID(),
    userAgentHash: null,
    ...overrides,
  };
}

function changedBase64Url(value: string): string {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}

function decodedEnvelope(bytes: Uint8Array<ArrayBuffer>): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

function encodedEnvelope(value: Record<string, unknown>): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(value));
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function manifestForBytes(
  manifest: AuditArchiveManifestV1,
  bytes: Uint8Array<ArrayBuffer>,
  overrides: Partial<AuditArchiveManifestV1> = {},
): Promise<AuditArchiveManifestV1> {
  const next = { ...manifest, ...overrides };
  const digest = await sha256Hex(bytes);
  return {
    ...next,
    objectBytes: bytes.byteLength,
    objectKey: `audit/v1/${String(next.firstSequence).padStart(16, "0")}-${String(
      next.lastSequence,
    ).padStart(16, "0")}/${digest}.pgid-audit`,
    objectSha256: digest,
  };
}

function expectArchiveError(
  action: () => unknown | Promise<unknown>,
  code?: AuditArchiveCryptoError["code"],
): Promise<void> {
  return archiveError(action).then((error) => {
    if (code) expect(error.code).toBe(code);
  });
}

async function archiveError(
  action: () => unknown | Promise<unknown>,
): Promise<AuditArchiveCryptoError> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(AuditArchiveCryptoError);
    return error as AuditArchiveCryptoError;
  }
  throw new Error("Expected archive crypto to fail");
}

function expectReconstructedArchiveError(
  error: AuditArchiveCryptoError,
  incoming: unknown,
  code: AuditArchiveCryptoError["code"],
  sentinel: string,
): void {
  expect(error).not.toBe(incoming);
  expect(error.code).toBe(code);
  expect(error.message).toBe(`Audit archive crypto failed (${code})`);
  expect(error.message).not.toContain(sentinel);
  expect(error.stack ?? "").not.toContain(sentinel);
}

function fullBoundaryMetadata(): string {
  return JSON.stringify(
    Object.fromEntries(
      Array.from({ length: 32 }, (_, index) => [
        `field${index}`,
        "x".repeat(256),
      ]),
    ),
  );
}

describe("audit archive crypto v1", () => {
  it("exposes one-argument entry points backed only by global Web Crypto", () => {
    expectTypeOf<
      Parameters<typeof sealAuditArchiveV1>["length"]
    >().toEqualTypeOf<1>();
    expectTypeOf<
      Parameters<typeof openAuditArchiveV1>["length"]
    >().toEqualTypeOf<1>();
    expect(sealAuditArchiveV1).toHaveLength(1);
    expect(openAuditArchiveV1).toHaveLength(1);
  });

  it("round-trips exact records while fresh Web Crypto randomness changes the envelope", async () => {
    const records = [record(5), record(9, { outcome: "denied" })];
    const kek = generatedKek();
    const input = {
      batchGeneration: 3,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v1",
      records,
    } as const;

    const first = await sealAuditArchiveV1(input);
    const second = await sealAuditArchiveV1(input);

    expect(first.manifest.contentType).toBe(AUDIT_ARCHIVE_CONTENT_TYPE);
    expect(first.manifest.firstSequence).toBe(5);
    expect(first.manifest.lastSequence).toBe(9);
    expect(first.manifest.eventCount).toBe(2);
    expect(first.manifest.objectSha256).not.toBe(second.manifest.objectSha256);
    expect([...first.objectBytes]).not.toEqual([...second.objectBytes]);
    expect(
      await openAuditArchiveV1({
        expected: first.manifest,
        kek,
        objectBytes: first.objectBytes,
      }),
    ).toEqual(records);
    expect(
      await openAuditArchiveV1({
        expected: second.manifest,
        kek,
        objectBytes: second.objectBytes,
      }),
    ).toEqual(records);
  });

  it("encodes one exact canonical record shape deterministically and permits sequence gaps", () => {
    const records = [record(2), record(11)];
    const first = encodeCanonicalAuditRecordsV1(records);
    const second = encodeCanonicalAuditRecordsV1(records.map((entry) => ({ ...entry })));
    expect([...first]).toEqual([...second]);

    const withExtraField = records.map((entry, index) =>
      index === 0 ? { ...entry, unapproved: true } : entry,
    );
    expect(() =>
      encodeCanonicalAuditRecordsV1(
        withExtraField as unknown as AuditArchiveRecordV1[],
      ),
    ).toThrow(AuditArchiveCryptoError);
  });

  it("accepts the current audit source's nullable shape and masked IP metadata", async () => {
    const records = [
      record(1, {
        actorUserId: null,
        clientId: null,
        ipHash: null,
        metadataJson: null,
        sessionId: null,
        subjectId: null,
        userAgentHash: null,
      }),
      record(2, {
        actorUserId: null,
        clientId: null,
        ipHash: null,
        metadataJson: JSON.stringify({ ipPrefix: "local" }),
        sessionId: null,
        subjectId: null,
        userAgentHash: null,
      }),
      record(3, {
        actorUserId: null,
        clientId: null,
        ipHash: null,
        metadataJson: JSON.stringify({ ipPrefix: "203.0.x.x" }),
        sessionId: null,
        subjectId: null,
        userAgentHash: null,
      }),
      record(4, {
        actorUserId: null,
        clientId: null,
        ipHash: null,
        metadataJson: JSON.stringify({ ipPrefix: "2001::" }),
        sessionId: null,
        subjectId: null,
        userAgentHash: null,
      }),
    ];
    const kek = generatedKek();
    const sealed = await sealAuditArchiveV1({
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v1",
      records,
    });

    expect(
      await openAuditArchiveV1({
        expected: sealed.manifest,
        kek,
        objectBytes: sealed.objectBytes,
      }),
    ).toEqual(records);
  });

  it("rejects noncanonical KEKs, arbitrary metadata, PII-like metadata, and closed bounds", async () => {
    const validKek = generatedKek();
    const input = {
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek: validKek,
      keyVersion: "v1",
      records: [record(1)],
    };

    await expectArchiveError(
      () => sealAuditArchiveV1({ ...input, kek: `${validKek}=` }),
      "invalid_kek",
    );
    await expectArchiveError(
      () => sealAuditArchiveV1({ ...input, batchGeneration: 0 }),
      "invalid_input",
    );
    await expectArchiveError(
      () => sealAuditArchiveV1({ ...input, keyVersion: "latest" }),
      "invalid_input",
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          createdAt: "2026-99-17T00:00:00.000Z",
        }),
      "invalid_input",
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          records: [record(1, { metadataJson: JSON.stringify({ nested: {} }) })],
        }),
      "invalid_input",
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          records: [
            record(1, {
              metadataJson: JSON.stringify({
                note: `${crypto.randomUUID()}@example.test`,
              }),
            }),
          ],
        }),
      "invalid_input",
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          records: Array.from({ length: AUDIT_ARCHIVE_MAX_RECORDS + 1 }, (_, index) =>
            record(index + 1),
          ),
        }),
      "bounds_exceeded",
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          records: [
            record(1, {
              metadataJson: JSON.stringify({ note: "x".repeat(70 * 1024) }),
            }),
          ],
        }),
      "bounds_exceeded",
    );
    for (const ipPrefix of [
      "203.0.113.9",
      "256.0.x.x",
      "0.256.x.x",
      "2001:db8::",
      "2001:0db8:0000:0000:0000:ff00:0042:8329",
    ]) {
      await expectArchiveError(
        () =>
          sealAuditArchiveV1({
            ...input,
            records: [
              record(1, { metadataJson: JSON.stringify({ ipPrefix }) }),
            ],
          }),
        "invalid_input",
      );
    }
    for (const kind of ["at", "cs", "rt"] as const) {
      const marker = `${credentialMarker(kind)}${crypto.randomUUID()}`;
      await expectArchiveError(
        () =>
          sealAuditArchiveV1({
            ...input,
            records: [record(1, { eventId: marker })],
          }),
        "invalid_input",
      );
      await expectArchiveError(
        () =>
          sealAuditArchiveV1({
            ...input,
            records: [
              record(1, {
                metadataJson: JSON.stringify({ reason: marker }),
              }),
            ],
          }),
        "invalid_input",
      );
    }
  });

  it("rejects empty, duplicate, and non-monotonic record sets", () => {
    expect(() => encodeCanonicalAuditRecordsV1([])).toThrow(
      AuditArchiveCryptoError,
    );

    const first = record(1);
    expect(() => encodeCanonicalAuditRecordsV1([first, record(1)])).toThrow(
      AuditArchiveCryptoError,
    );
    expect(() => encodeCanonicalAuditRecordsV1([record(2), record(1)])).toThrow(
      AuditArchiveCryptoError,
    );
    expect(() =>
      encodeCanonicalAuditRecordsV1([
        first,
        record(2, { eventId: first.eventId }),
      ]),
    ).toThrow(AuditArchiveCryptoError);
  });

  it("enforces the exact plaintext cap and the derived object cap", async () => {
    const nearObjectLimit = Array.from({ length: 43 }, (_, index) =>
      record(index + 1, { metadataJson: fullBoundaryMetadata() }),
    );
    const exactPlaintextLimit = [
      ...nearObjectLimit,
      record(44, {
        metadataJson: JSON.stringify({
          field: "x".repeat(55),
          other: "x".repeat(256),
        }),
      }),
    ];
    expect(encodeCanonicalAuditRecordsV1(exactPlaintextLimit).byteLength).toBe(
      AUDIT_ARCHIVE_MAX_PLAINTEXT_BYTES,
    );
    expect(() =>
      encodeCanonicalAuditRecordsV1([
        ...nearObjectLimit,
        record(44, {
          metadataJson: JSON.stringify({
            field: "x".repeat(56),
            other: "x".repeat(256),
          }),
        }),
      ]),
    ).toThrow(AuditArchiveCryptoError);

    const input = {
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek: generatedKek(),
      keyVersion: "v1",
      records: nearObjectLimit,
    } as const;
    const sealed = await sealAuditArchiveV1(input);
    expect(sealed.objectBytes.byteLength).toBeLessThanOrEqual(
      AUDIT_ARCHIVE_MAX_OBJECT_BYTES,
    );
    expect(AUDIT_ARCHIVE_MAX_OBJECT_BYTES - sealed.objectBytes.byteLength).toBeLessThan(
      1024,
    );
    await expectArchiveError(
      () =>
        sealAuditArchiveV1({
          ...input,
          records: [...nearObjectLimit, record(44, { metadataJson: "{}" })],
        }),
      "bounds_exceeded",
    );
  });

  it("fails closed for a wrong KEK and every authenticated envelope field", async () => {
    const kek = generatedKek();
    const sealed = await sealAuditArchiveV1({
      batchGeneration: 7,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v2",
      records: [record(3), record(8)],
    });

    await expectArchiveError(
      () =>
        openAuditArchiveV1({
          expected: sealed.manifest,
          kek: generatedKek(),
          objectBytes: sealed.objectBytes,
        }),
      "decryption_failed",
    );

    for (const mutate of [
      (envelope: Record<string, unknown>) => {
        envelope.ciphertext = changedBase64Url(String(envelope.ciphertext));
      },
      (envelope: Record<string, unknown>) => {
        envelope.nonce = changedBase64Url(String(envelope.nonce));
      },
      (envelope: Record<string, unknown>) => {
        envelope.wrappedDek = changedBase64Url(String(envelope.wrappedDek));
      },
      (envelope: Record<string, unknown>) => {
        const header = envelope.header as Record<string, unknown>;
        header.eventCount = Number(header.eventCount) + 1;
      },
    ]) {
      const envelope = decodedEnvelope(sealed.objectBytes);
      mutate(envelope);
      const bytes = encodedEnvelope(envelope);
      const header = envelope.header as Record<string, unknown>;
      const expected = await manifestForBytes(sealed.manifest, bytes, {
        eventCount: Number(header.eventCount),
      });
      await expectArchiveError(() =>
        openAuditArchiveV1({ expected, kek, objectBytes: bytes }),
      );
    }
  });

  it("rejects truncation, noncanonical or extra envelope fields, and expected metadata drift", async () => {
    const kek = generatedKek();
    const sealed = await sealAuditArchiveV1({
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v1",
      records: [record(1), record(3)],
    });

    const truncated = sealed.objectBytes.slice(0, -1);
    await expectArchiveError(async () =>
      openAuditArchiveV1({
        expected: await manifestForBytes(sealed.manifest, truncated),
        kek,
        objectBytes: truncated,
      }),
    );

    const extra = decodedEnvelope(sealed.objectBytes);
    extra.unapproved = true;
    const extraBytes = encodedEnvelope(extra);
    await expectArchiveError(async () =>
      openAuditArchiveV1({
        expected: await manifestForBytes(sealed.manifest, extraBytes),
        kek,
        objectBytes: extraBytes,
      }),
    );

    const reordered = decodedEnvelope(sealed.objectBytes);
    const reorderedBytes = new TextEncoder().encode(
      JSON.stringify({
        wrappedDek: reordered.wrappedDek,
        nonce: reordered.nonce,
        header: reordered.header,
        ciphertext: reordered.ciphertext,
      }),
    );
    await expectArchiveError(
      async () =>
        openAuditArchiveV1({
          expected: await manifestForBytes(sealed.manifest, reorderedBytes),
          kek,
          objectBytes: reorderedBytes,
        }),
      "integrity_mismatch",
    );

    await expectArchiveError(
      () =>
        openAuditArchiveV1({
          expected: { ...sealed.manifest, eventCount: 3 },
          kek,
          objectBytes: sealed.objectBytes,
        }),
      "integrity_mismatch",
    );
    await expectArchiveError(
      () =>
        openAuditArchiveV1({
          expected: { ...sealed.manifest, firstSequence: 2 },
          kek,
          objectBytes: sealed.objectBytes,
        }),
      "integrity_mismatch",
    );
    await expectArchiveError(
      () =>
        openAuditArchiveV1({
          expected: { ...sealed.manifest, lastSequence: 2 },
          kek,
          objectBytes: sealed.objectBytes,
        }),
      "integrity_mismatch",
    );
    await expectArchiveError(
      () =>
        openAuditArchiveV1({
          expected: { ...sealed.manifest, objectKey: "audit/v1/not-the-object" },
          kek,
          objectBytes: sealed.objectBytes,
        }),
      "integrity_mismatch",
    );
  });

  it("reconstructs seal records-accessor failures with fixed identity and text", async () => {
    const sentinel = `seal-accessor-${crypto.randomUUID()}`;
    const incoming = new AuditArchiveCryptoError("invalid_input");
    incoming.message = sentinel;
    const failure = await archiveError(() =>
      sealAuditArchiveV1({
        batchGeneration: 1,
        createdAt: CREATED_AT,
        kek: generatedKek(),
        keyVersion: "v1",
        get records(): readonly AuditArchiveRecordV1[] {
          throw incoming;
        },
      }),
    );

    expectReconstructedArchiveError(
      failure,
      incoming,
      "invalid_input",
      sentinel,
    );

    const fallbackSentinel = `seal-fallback-${crypto.randomUUID()}`;
    const fallbackIncoming = new Error(fallbackSentinel);
    const fallback = await archiveError(() =>
      sealAuditArchiveV1({
        batchGeneration: 1,
        createdAt: CREATED_AT,
        kek: generatedKek(),
        keyVersion: "v1",
        get records(): readonly AuditArchiveRecordV1[] {
          throw fallbackIncoming;
        },
      }),
    );
    expectReconstructedArchiveError(
      fallback,
      fallbackIncoming,
      "encryption_failed",
      fallbackSentinel,
    );
  });

  it("reconstructs open input and manifest accessors without reading hostile codes", async () => {
    const kek = generatedKek();
    const sealed = await sealAuditArchiveV1({
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v1",
      records: [record(1)],
    });

    const expectedSentinel = `open-expected-${crypto.randomUUID()}`;
    const expectedIncoming = new AuditArchiveCryptoError("integrity_mismatch");
    expectedIncoming.message = expectedSentinel;
    const expectedFailure = await archiveError(() =>
      openAuditArchiveV1({
        get expected(): AuditArchiveManifestV1 {
          throw expectedIncoming;
        },
        kek,
        objectBytes: sealed.objectBytes,
      }),
    );
    expectReconstructedArchiveError(
      expectedFailure,
      expectedIncoming,
      "integrity_mismatch",
      expectedSentinel,
    );

    const objectSentinel = `open-object-${crypto.randomUUID()}`;
    const objectIncoming = new AuditArchiveCryptoError("invalid_input");
    objectIncoming.message = objectSentinel;
    let objectCodeRead = false;
    Object.defineProperty(objectIncoming, "code", {
      configurable: true,
      get() {
        objectCodeRead = true;
        throw new Error(objectSentinel);
      },
    });
    const objectFailure = await archiveError(() =>
      openAuditArchiveV1({
        expected: sealed.manifest,
        kek,
        get objectBytes(): Uint8Array<ArrayBuffer> {
          throw objectIncoming;
        },
      }),
    );
    expectReconstructedArchiveError(
      objectFailure,
      objectIncoming,
      "decryption_failed",
      objectSentinel,
    );
    expect(objectCodeRead).toBe(false);

    const manifestSentinel = `open-manifest-${crypto.randomUUID()}`;
    let manifestCodeRead = false;
    const crossRealmLike = Object.create(null) as Record<string, unknown>;
    Object.defineProperties(crossRealmLike, {
      code: {
        get() {
          manifestCodeRead = true;
          throw new Error(manifestSentinel);
        },
      },
      message: { value: manifestSentinel },
    });
    const hostileManifest = {
      ...sealed.manifest,
      get eventCount(): number {
        throw crossRealmLike;
      },
    };
    const manifestFailure = await archiveError(() =>
      openAuditArchiveV1({
        expected: hostileManifest,
        kek,
        objectBytes: sealed.objectBytes,
      }),
    );
    expectReconstructedArchiveError(
      manifestFailure,
      crossRealmLike,
      "decryption_failed",
      manifestSentinel,
    );
    expect(manifestCodeRead).toBe(false);
  });

  it("does not mutate caller data or expose caller values in failures", async () => {
    const records = [record(1)];
    const recordsBefore = structuredClone(records);
    const kek = generatedKek();
    const sealed = await sealAuditArchiveV1({
      batchGeneration: 1,
      createdAt: CREATED_AT,
      kek,
      keyVersion: "v1",
      records,
    });
    expect(records).toEqual(recordsBefore);

    const objectBefore = [...sealed.objectBytes];
    const wrongKek = generatedKek();
    let failure: unknown;
    try {
      await openAuditArchiveV1({
        expected: sealed.manifest,
        kek: wrongKek,
        objectBytes: sealed.objectBytes,
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(AuditArchiveCryptoError);
    expect((failure as AuditArchiveCryptoError).code).toBe("decryption_failed");
    const message = (failure as Error).message;
    expect(message).not.toContain(kek);
    expect(message).not.toContain(wrongKek);
    expect(message).not.toContain(records[0]?.eventId ?? "unreachable");
    expect(message).not.toContain(records[0]?.metadataJson ?? "unreachable");
    expect([...sealed.objectBytes]).toEqual(objectBefore);
    expect(records).toEqual(recordsBefore);

    const invalidKek = `${crypto.randomUUID()}-${crypto.randomUUID()}`;
    const invalidKekRecords = [record(2)];
    const invalidKekRecordsBefore = structuredClone(invalidKekRecords);
    let invalidKekRecordsRead = false;
    const invalidKekError = await archiveError(() =>
      sealAuditArchiveV1({
        batchGeneration: 1,
        createdAt: CREATED_AT,
        kek: invalidKek,
        keyVersion: "v1",
        get records() {
          invalidKekRecordsRead = true;
          return invalidKekRecords;
        },
      }),
    );
    expect(invalidKekError.code).toBe("invalid_kek");
    expect(invalidKekError.message).not.toContain(invalidKek);
    expect(invalidKekError.message).not.toContain(
      invalidKekRecords[0]?.eventId ?? "unreachable",
    );
    expect(invalidKekRecordsRead).toBe(false);
    expect(invalidKekRecords).toEqual(invalidKekRecordsBefore);

    const invalidIdentifier = `${credentialMarker("at")}${crypto.randomUUID()}`;
    const invalidRecords = [record(3, { eventId: invalidIdentifier })];
    const invalidRecordsBefore = structuredClone(invalidRecords);
    const invalidRecordError = await archiveError(() =>
      sealAuditArchiveV1({
        batchGeneration: 1,
        createdAt: CREATED_AT,
        kek,
        keyVersion: "v1",
        records: invalidRecords,
      }),
    );
    expect(invalidRecordError.code).toBe("invalid_input");
    expect(invalidRecordError.message).not.toContain(invalidIdentifier);
    expect(invalidRecordError.message).not.toContain(
      invalidRecords[0]?.metadataJson ?? "unreachable",
    );
    expect(invalidRecords).toEqual(invalidRecordsBefore);
  });
});
