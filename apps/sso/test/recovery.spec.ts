import { env, exports } from "cloudflare:workers";
import {
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { app } from "../worker/index";
import {
  canonicalRecoveryCode,
  sha256Base64Url,
} from "../worker/recovery-codes";
import {
  createAuthenticatedUser,
  createBootstrapAdmin,
  interposeAfterD1First,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const CODE_PATTERN =
  /^PGID-R1-(?:[0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/;
let recoveryIpSequence = 1;

interface IssuedCodes {
  codes: string[];
  count: number;
  expiresAt: null;
  formatVersion: number;
  generation: number;
}

interface RecoveryOptions {
  challengeId: string;
  expiresAt: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

interface TestRegistration {
  credentialId: string;
  privateKey: CryptoKey;
  response: RegistrationResponseJSON;
}

function recoveryRequest(
  path: string,
  options: RequestInit = {},
): Request {
  const headers = new Headers(options.headers);
  headers.set("Origin", BASE_URL);
  if (options.body !== undefined && !headers.has("content-type")) {
    headers.set("Content-Type", "application/json");
  }
  return new Request(`${BASE_URL}${path}`, { ...options, headers });
}

function unreadRequestBody(byteLength: number): {
  body: ReadableStream<Uint8Array<ArrayBuffer>>;
  readCount: () => number;
} {
  let reads = 0;
  const body = new ReadableStream<Uint8Array<ArrayBuffer>>(
    {
      pull(controller) {
        reads += 1;
        controller.enqueue(new Uint8Array(new ArrayBuffer(byteLength)));
        controller.close();
      },
    },
    { highWaterMark: 0 },
  );
  return { body, readCount: () => reads };
}

async function issueCodes(
  session: Awaited<ReturnType<typeof createAuthenticatedUser>>,
): Promise<{ payload: IssuedCodes; response: Response }> {
  const response = await exports.default.fetch(
    recoveryRequest("/api/account/recovery-codes/rotate", {
      method: "POST",
      headers: session.headers,
      body: "{}",
    }),
  );
  return { payload: (await response.json()) as IssuedCodes, response };
}

async function startRecovery(code: string): Promise<Response> {
  return exports.default.fetch(
    recoveryRequest("/api/recovery/start", {
      method: "POST",
      headers: {
        "CF-Connecting-IP": `192.0.2.${recoveryIpSequence++}`,
      },
      body: JSON.stringify({ code }),
    }),
  );
}

function cookieFrom(response: Response): string {
  const setCookie = response.headers.get("set-cookie");
  if (!setCookie) throw new Error("Recovery cookie missing");
  return setCookie.split(";", 1)[0] ?? "";
}

function concatBytes(
  ...parts: Uint8Array<ArrayBuffer>[]
): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    new ArrayBuffer(parts.reduce((sum, part) => sum + part.length, 0)),
  );
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function derInteger(
  source: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  let first = 0;
  while (first < source.length - 1 && source[first] === 0) first += 1;
  const value = source.slice(first);
  return value[0] !== undefined && (value[0] & 0x80) !== 0
    ? concatBytes(new Uint8Array(new ArrayBuffer(1)), value)
    : value;
}

function rawEcdsaToDer(
  signature: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  if (signature.length !== 64) throw new Error("Unexpected ECDSA signature");
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  const sequenceLength = 2 + r.length + 2 + s.length;
  return concatBytes(
    Uint8Array.of(0x30, sequenceLength, 0x02, r.length),
    r,
    Uint8Array.of(0x02, s.length),
    s,
  );
}

async function createRegistration(
  challenge: string,
  options: {
    credentialByteLength?: number;
    origin?: string;
    rpId?: string;
    userVerified?: boolean;
  } = {},
): Promise<TestRegistration> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const rawPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  const cosePublicKey = isoCBOR.encode(
    new Map<number, number | Uint8Array<ArrayBuffer>>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, rawPublicKey.slice(1, 33)],
      [-3, rawPublicKey.slice(33, 65)],
    ]),
  );
  const credentialBytes = crypto.getRandomValues(
    new Uint8Array(new ArrayBuffer(options.credentialByteLength ?? 32)),
  );
  const credentialId = isoBase64URL.fromBuffer(credentialBytes);
  const rpId = options.rpId ?? "localhost";
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)),
  );
  const credentialLength = new Uint8Array(new ArrayBuffer(2));
  new DataView(credentialLength.buffer).setUint16(0, credentialBytes.length, false);
  const authenticatorData = concatBytes(
    rpIdHash,
    Uint8Array.of(options.userVerified === false ? 0x41 : 0x45),
    new Uint8Array(new ArrayBuffer(4)),
    new Uint8Array(new ArrayBuffer(16)),
    credentialLength,
    credentialBytes,
    cosePublicKey,
  );
  const attestationObject = isoCBOR.encode(
    new Map<
      string,
      string | Map<string, string> | Uint8Array<ArrayBuffer>
    >([
      ["fmt", "none"],
      ["attStmt", new Map<string, string>()],
      ["authData", authenticatorData],
    ]),
  );
  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      challenge,
      crossOrigin: false,
      origin: options.origin ?? BASE_URL,
      type: "webauthn.create",
    }),
  );
  return {
    credentialId,
    privateKey: keyPair.privateKey,
    response: {
      id: credentialId,
      rawId: credentialId,
      response: {
        attestationObject: isoBase64URL.fromBuffer(attestationObject),
        clientDataJSON: isoBase64URL.fromBuffer(clientDataJSON),
        transports: ["internal"],
      },
      clientExtensionResults: {},
      type: "public-key",
    },
  };
}

async function createAuthentication(
  registration: TestRegistration,
  challenge: string,
): Promise<AuthenticationResponseJSON> {
  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      challenge,
      crossOrigin: false,
      origin: BASE_URL,
      type: "webauthn.get",
    }),
  );
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("localhost")),
  );
  const authenticatorData = new Uint8Array(new ArrayBuffer(37));
  authenticatorData.set(rpIdHash, 0);
  authenticatorData[32] = 0x05;
  new DataView(authenticatorData.buffer).setUint32(33, 1, false);
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSON),
  );
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      registration.privateKey,
      concatBytes(authenticatorData, clientDataHash),
    ),
  );
  return {
    id: registration.credentialId,
    rawId: registration.credentialId,
    response: {
      authenticatorData: isoBase64URL.fromBuffer(authenticatorData),
      clientDataJSON: isoBase64URL.fromBuffer(clientDataJSON),
      signature: isoBase64URL.fromBuffer(rawEcdsaToDer(rawSignature)),
    },
    clientExtensionResults: {},
    type: "public-key",
  };
}

async function beginPasskeyRecovery(cookie: string): Promise<RecoveryOptions> {
  const response = await exports.default.fetch(
    recoveryRequest("/api/recovery/passkey/options", {
      method: "POST",
      headers: { Cookie: cookie },
      body: "{}",
    }),
  );
  expect(response.status).toBe(200);
  return (await response.json()) as RecoveryOptions;
}

async function seedVisitedRp(
  userId: string,
  sessionId: string,
): Promise<string> {
  const clientId = `recovery-rp-${crypto.randomUUID()}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
  const refreshId = crypto.randomUUID();
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthClient (
        id, clientId, disabled, skipConsent, enableEndSession, subjectType,
        scopes, createdAt, updatedAt, name, redirectUris,
        tokenEndpointAuthMethod, grantTypes, responseTypes, public, type,
        requirePKCE, metadata, backchannelLogoutUri
      ) VALUES (?, ?, 0, 0, 1, 'public', '["openid","offline_access"]',
                ?, ?, 'Recovery RP', ?, 'none',
                '["authorization_code","refresh_token"]', '["code"]', 1,
                'web', 1, '{}', ?)`,
    ).bind(
      crypto.randomUUID(),
      clientId,
      now.toISOString(),
      now.toISOString(),
      JSON.stringify([`https://${clientId}.example/callback`]),
      `https://${clientId}.example/backchannel-logout`,
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthRefreshToken
        (id, token, clientId, sessionId, userId, expiresAt, createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, '["openid","offline_access"]')`,
    ).bind(
      refreshId,
      crypto.randomUUID(),
      clientId,
      sessionId,
      userId,
      expiresAt,
      now.toISOString(),
    ),
    env.PG72_ID_DB.prepare(
      `INSERT INTO oauthAccessToken
        (id, token, clientId, sessionId, userId, refreshId, expiresAt,
         createdAt, scopes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, '["openid"]')`,
    ).bind(
      crypto.randomUUID(),
      crypto.randomUUID(),
      clientId,
      sessionId,
      userId,
      refreshId,
      expiresAt,
      now.toISOString(),
    ),
  ]);
  return clientId;
}

interface RecoveryCompletionState {
  completed_audits: number;
  logout_deliveries: number;
  passkeys: number;
  recovery_codes: number;
  recovery_sessions: number;
  recovery_sets: number;
  revoked_sets: number;
  sessions: number;
}

async function recoveryCompletionState(
  userId: string,
): Promise<RecoveryCompletionState> {
  const state = await env.PG72_ID_DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM passkey WHERE userId = ?) AS passkeys,
       (SELECT COUNT(*) FROM recovery_code_set WHERE user_id = ?)
         AS recovery_sets,
       (SELECT COUNT(*) FROM recovery_code_set
         WHERE user_id = ? AND revoked_at IS NOT NULL) AS revoked_sets,
       (SELECT COUNT(*) FROM recovery_code
         JOIN recovery_code_set ON recovery_code_set.id = recovery_code.set_id
        WHERE recovery_code_set.user_id = ?) AS recovery_codes,
       (SELECT COUNT(*) FROM recovery_session WHERE user_id = ?)
         AS recovery_sessions,
       (SELECT COUNT(*) FROM session WHERE userId = ?) AS sessions,
       (SELECT COUNT(*) FROM logout_delivery WHERE user_id = ?)
         AS logout_deliveries,
       (SELECT COUNT(*) FROM audit_event
         WHERE subject_id = ? AND event_type = 'recovery.completed')
         AS completed_audits`,
  )
    .bind(
      userId,
      userId,
      userId,
      userId,
      userId,
      userId,
      userId,
      userId,
    )
    .first<RecoveryCompletionState>();
  if (!state) throw new Error("Recovery completion state unavailable");
  return state;
}

async function verifyRecoveryWithQueueSpies(
  cookie: string,
  options: RecoveryOptions,
  response: RegistrationResponseJSON,
): Promise<{
  logoutSend: ReturnType<typeof vi.fn>;
  response: Response;
  securitySend: ReturnType<typeof vi.fn>;
}> {
  const securitySend = vi.fn(async () => undefined);
  const logoutSend = vi.fn(async () => undefined);
  const requestEnv = {
    ...env,
    SECURITY_EVENTS: { send: securitySend } as unknown as Queue,
    LOGOUT_DELIVERIES: { send: logoutSend } as unknown as Queue,
  } as Env;
  const ctx = createExecutionContext();
  const result = await app.fetch(
    recoveryRequest("/api/recovery/passkey/verify", {
      method: "POST",
      headers: { Cookie: cookie },
      body: JSON.stringify({ challengeId: options.challengeId, response }),
    }),
    requestEnv,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return { logoutSend, response: result, securitySend };
}

describe("recovery code management", () => {
  it("issues ten 160-bit R1 codes once and stores only global SHA-256 hashes", async () => {
    const session = await createAuthenticatedUser(
      `recovery-issue-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    expect(issued.response.status).toBe(200);
    expect(issued.response.headers.get("cache-control")).toBe("no-store");
    expect(issued.response.headers.get("pragma")).toBe("no-cache");
    expect(issued.payload.codes).toHaveLength(10);
    expect(new Set(issued.payload.codes).size).toBe(10);
    issued.payload.codes.forEach((code) => expect(code).toMatch(CODE_PATTERN));

    const rows = await env.PG72_ID_DB.prepare(
      `SELECT code_hash FROM recovery_code
        WHERE set_id = (
          SELECT id FROM recovery_code_set
           WHERE user_id = ? AND revoked_at IS NULL
        ) ORDER BY ordinal`,
    )
      .bind(session.userId)
      .all<{ code_hash: string }>();
    expect(rows.results).toHaveLength(10);
    expect(rows.results.every((row) => /^[A-Za-z0-9_-]{43}$/.test(row.code_hash))).toBe(true);
    for (let index = 0; index < issued.payload.codes.length; index += 1) {
      const canonical = canonicalRecoveryCode(issued.payload.codes[index]);
      expect(canonical).not.toBeNull();
      expect(rows.results[index]?.code_hash).toBe(
        await sha256Base64Url(canonical ?? ""),
      );
    }
    const serialized = JSON.stringify(rows.results);
    issued.payload.codes.forEach((code) => expect(serialized).not.toContain(code));

    const status = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/recovery-codes`, {
        headers: session.headers,
      }),
    );
    expect(await status.json()).toEqual({
      configured: true,
      count: 10,
      formatVersion: 1,
      generation: 1,
      remaining: 10,
      expiresAt: null,
    });
  });

  it("requires fresh same-session Passkey step-up and rotates generations atomically", async () => {
    const noStepUp = await createAuthenticatedUser(
      `recovery-no-step-${crypto.randomUUID()}@example.test`,
    );
    const denied = await issueCodes(noStepUp);
    expect(denied.response.status).toBe(403);
    expect(denied.payload).toMatchObject({ error: "passkey_enrollment_required" });

    const session = await createAuthenticatedUser(
      `recovery-rotate-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const first = await issueCodes(session);
    const second = await issueCodes(session);
    expect(first.response.status).toBe(200);
    expect(second.response.status).toBe(200);
    expect(second.payload.generation).toBe(2);
    const oldHash = await sha256Base64Url(
      canonicalRecoveryCode(first.payload.codes[0]) ?? "",
    );
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT 1 AS present FROM recovery_code WHERE code_hash = ?",
      )
        .bind(oldHash)
        .first(),
    ).toBeNull();
    const generations = await env.PG72_ID_DB.prepare(
      `SELECT generation, revoked_at FROM recovery_code_set
        WHERE user_id = ? ORDER BY generation`,
    )
      .bind(session.userId)
      .all<{ generation: number; revoked_at: string | null }>();
    expect(generations.results.map((row) => row.generation)).toEqual([1, 2]);
    expect(generations.results[0]?.revoked_at).not.toBeNull();
    expect(generations.results[1]?.revoked_at).toBeNull();
  });

  it("requires a strict empty JSON body before rotating codes", async () => {
    const session = await createAuthenticatedUser(
      `recovery-media-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const wrongMediaHeaders = new Headers(session.headers);
    wrongMediaHeaders.set("Content-Type", "text/plain");
    const wrongMediaType = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/recovery-codes/rotate`, {
        method: "POST",
        headers: wrongMediaHeaders,
        body: "{}",
      }),
    );
    expect(wrongMediaType.status).toBe(415);

    const extraField = await exports.default.fetch(
      recoveryRequest("/api/account/recovery-codes/rotate", {
        method: "POST",
        headers: session.headers,
        body: JSON.stringify({ extra: true }),
      }),
    );
    expect(extraField.status).toBe(400);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM recovery_code_set WHERE user_id = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });

  it("has no bootstrap bypass and repeats the freshness/step-up predicate at commit", async () => {
    const bootstrap = await createBootstrapAdmin();
    const bootstrapDenied = await issueCodes({
      ...bootstrap,
      accessLevel: "standard",
      googleAccountId: null,
    });
    expect(bootstrapDenied.response.status).toBe(403);
    expect(bootstrapDenied.payload).toMatchObject({
      error: "passkey_enrollment_required",
    });

    const session = await createAuthenticatedUser(
      `recovery-race-guard-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const interposed = interposeAfterD1First(
      "active.id AS active_set_id",
      async () => {
        await env.PG72_ID_DB.prepare(
          "UPDATE session SET passkeyStepUpAt = ? WHERE id = ?",
        )
          .bind(new Date(Date.now() - 11 * 60 * 1000).toISOString(), session.sessionId)
          .run();
      },
    );
    const ctx = createExecutionContext();
    const response = await app.fetch(
      recoveryRequest("/api/account/recovery-codes/rotate", {
        method: "POST",
        headers: session.headers,
        body: "{}",
      }),
      { ...env, PG72_ID_DB: interposed.database } as Env,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(interposed.wasIntercepted()).toBe(true);
    expect(response.status).toBe(409);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM recovery_code_set WHERE user_id = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });

  it("allows an active restricted account but denies suspended accounts", async () => {
    const restricted = await createAuthenticatedUser(
      `recovery-restricted-${crypto.randomUUID()}@example.test`,
      "user",
      { accessLevel: "restricted", passkeyStepUp: true },
    );
    expect((await issueCodes(restricted)).response.status).toBe(200);

    const suspended = await createAuthenticatedUser(
      `recovery-suspended-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    await env.PG72_ID_DB.prepare("UPDATE user SET status = 'suspended' WHERE id = ?")
      .bind(suspended.userId)
      .run();
    expect((await issueCodes(suspended)).response.status).toBe(401);
  });

  it("rejects stale and future-dated management authentication", async () => {
    const session = await createAuthenticatedUser(
      `recovery-freshness-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ? WHERE id = ?",
    )
      .bind(
        new Date(Date.now() - 11 * 60 * 1000).toISOString(),
        session.sessionId,
      )
      .run();
    const stale = await issueCodes(session);
    expect(stale.response.status).toBe(403);
    expect(stale.payload).toMatchObject({ error: "fresh_session_required" });

    const future = new Date(Date.now() + 60 * 1000).toISOString();
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET createdAt = ?, passkeyStepUpAt = ? WHERE id = ?",
    )
      .bind(future, future, session.sessionId)
      .run();
    const futureDated = await issueCodes(session);
    expect(futureDated.response.status).toBe(403);
    expect(futureDated.payload).toMatchObject({ error: "fresh_session_required" });
  });

  it("revokes the active set and any in-progress restricted session", async () => {
    const session = await createAuthenticatedUser(
      `recovery-revoke-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    expect(started.status).toBe(200);
    const revoked = await exports.default.fetch(
      recoveryRequest("/api/account/recovery-codes", {
        method: "DELETE",
        headers: session.headers,
      }),
    );
    expect(revoked.status).toBe(200);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM recovery_session WHERE user_id = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });
});

describe("restricted recovery entry", () => {
  it("rejects disabled recovery before fixed-length or streamed bodies and bindings", async () => {
    const prepare = vi.fn(() => {
      throw new Error("disabled recovery touched D1");
    });
    const batch = vi.fn(() => {
      throw new Error("disabled recovery touched D1");
    });
    const authLimit = vi.fn(async () => ({ success: true }));
    const recoveryLimit = vi.fn(async () => ({ success: true }));
    const securitySend = vi.fn(async () => undefined);
    const logoutSend = vi.fn(async () => undefined);
    const disabledEnv = {
      ...env,
      RECOVERY_MODE: "disabled",
      PG72_ID_DB: { batch, prepare } as unknown as D1Database,
      AUTH_RATE_LIMITER: { limit: authLimit } as unknown as RateLimit,
      RECOVERY_RATE_LIMITER: {
        limit: recoveryLimit,
      } as unknown as RateLimit,
      SECURITY_EVENTS: { send: securitySend } as unknown as Queue,
      LOGOUT_DELIVERIES: { send: logoutSend } as unknown as Queue,
    } as Env;
    const surfaces = [
      { path: "/api/account/recovery-codes", size: 2 * 1024 },
      { path: "/api/account/recovery-codes/rotate", size: 2 * 1024 },
      { path: "/api/recovery/start", size: 2 * 1024 },
      { path: "/api/recovery/passkey/verify", size: 65 * 1024 },
    ];
    const responseBodies: number[][] = [];

    for (const surface of surfaces) {
      for (const fixedLength of [true, false]) {
        const instrumented = unreadRequestBody(surface.size);
        const headers = new Headers({
          "Content-Type": "application/json",
          Origin: BASE_URL,
        });
        if (fixedLength) headers.set("Content-Length", String(surface.size));
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request(`${BASE_URL}${surface.path}`, {
            method: "POST",
            headers,
            body: instrumented.body,
          }),
          disabledEnv,
          ctx,
        );
        await waitOnExecutionContext(ctx);
        expect(response.status).toBe(404);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        expect(instrumented.readCount()).toBe(0);
        responseBodies.push([...new Uint8Array(await response.arrayBuffer())]);
      }
    }

    const referenceBody = responseBodies[0];
    if (!referenceBody) throw new Error("Disabled recovery response missing");
    for (const body of responseBodies.slice(1)) {
      expect(body).toEqual(referenceBody);
    }
    expect(new TextDecoder().decode(new Uint8Array(referenceBody))).toBe(
      '{"error":"not_found"}',
    );
    expect(prepare).not.toHaveBeenCalled();
    expect(batch).not.toHaveBeenCalled();
    expect(authLimit).not.toHaveBeenCalled();
    expect(recoveryLimit).not.toHaveBeenCalled();
    expect(securitySend).not.toHaveBeenCalled();
    expect(logoutSend).not.toHaveBeenCalled();
  });

  it("retains the enabled body limits for every recovery matcher", async () => {
    const surfaces = [
      { path: "/api/account/recovery-codes", size: 2 * 1024 },
      { path: "/api/account/recovery-codes/rotate", size: 2 * 1024 },
      { path: "/api/recovery/start", size: 2 * 1024 },
      { path: "/api/recovery/passkey/verify", size: 65 * 1024 },
    ];
    for (const surface of surfaces) {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        recoveryRequest(surface.path, {
          method: "POST",
          body: "x".repeat(surface.size),
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);
      expect(response.status).toBe(413);
      expect(await response.json()).toEqual({ error: "request_too_large" });
    }
  });
  it("returns equal generic denials and has exactly one winner for a competing code", async () => {
    const session = await createAuthenticatedUser(
      `recovery-race-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const unknown = await startRecovery(
      "PGID-R1-0000-0000-0000-0000-0000-0000-0000-0000",
    );
    const malformed = await startRecovery("not a recovery code");
    expect(unknown.status).toBe(400);
    expect(malformed.status).toBe(400);
    expect(await unknown.text()).toBe(await malformed.text());

    const code = issued.payload.codes[0] ?? "";
    const [first, second] = await Promise.all([
      startRecovery(code.toLowerCase().replaceAll("-", " ")),
      startRecovery(code),
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 400]);
    const count = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM recovery_session WHERE user_id = ?",
    )
      .bind(session.userId)
      .first<{ count: number }>();
    expect(count?.count).toBe(1);
  });

  it("does not consume an expired code set and preserves the generic denial", async () => {
    const session = await createAuthenticatedUser(
      `recovery-expired-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const code = "PGID-R1-2222-2222-2222-2222-2222-2222-2222-2222";
    const setId = crypto.randomUUID();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO recovery_code_set
          (id, user_id, generation, format_version, created_at, expires_at)
         VALUES (?, ?, 1, 1, ?, ?)`,
      ).bind(
        setId,
        session.userId,
        new Date(Date.now() - 2 * 60 * 1000).toISOString(),
        new Date(Date.now() - 60 * 1000).toISOString(),
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO recovery_code
          (id, set_id, ordinal, code_hash, consumed_at)
         VALUES (?, ?, 1, ?, NULL)`,
      ).bind(
        crypto.randomUUID(),
        setId,
        await sha256Base64Url(canonicalRecoveryCode(code) ?? ""),
      ),
    ]);

    const expired = await startRecovery(code);
    const unknown = await startRecovery(
      "PGID-R1-3333-3333-3333-3333-3333-3333-3333-3333",
    );
    expect(expired.status).toBe(400);
    expect(await expired.text()).toBe(await unknown.text());
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT consumed_at FROM recovery_code WHERE set_id = ?",
      )
        .bind(setId)
        .first<{ consumed_at: string | null }>(),
    ).toEqual({ consumed_at: null });
  });

  it("creates only a scoped hash-token cookie and cannot authorize normal surfaces", async () => {
    const session = await createAuthenticatedUser(
      `recovery-scope-${crypto.randomUUID()}@example.test`,
      "user",
      { accessLevel: "restricted", passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const beforeSessions = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM session WHERE userId = ?",
    )
      .bind(session.userId)
      .first<{ count: number }>();
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    expect(started.status).toBe(200);
    const setCookie = started.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("Path=/api/recovery");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Strict");
    const rawToken = cookieFrom(started).split("=", 2)[1] ?? "";
    const row = await env.PG72_ID_DB.prepare(
      "SELECT token_hash FROM recovery_session WHERE user_id = ?",
    )
      .bind(session.userId)
      .first<{ token_hash: string }>();
    expect(row?.token_hash).toBe(await sha256Base64Url(rawToken));
    expect(row?.token_hash).not.toBe(rawToken);
    const afterSessions = await env.PG72_ID_DB.prepare(
      "SELECT COUNT(*) AS count FROM session WHERE userId = ?",
    )
      .bind(session.userId)
      .first<{ count: number }>();
    expect(afterSessions).toEqual(beforeSessions);

    const recoveryCookie = cookieFrom(started);
    const normalPaths = [
      "/api/account/profile",
      "/api/admin/users",
      "/passkey/list-user-passkeys",
      "/get-session",
    ];
    for (const path of normalPaths) {
      const response = await exports.default.fetch(
        new Request(`${BASE_URL}${path}`, { headers: { Cookie: recoveryCookie } }),
      );
      if (path === "/get-session") {
        expect(await response.json()).toBeNull();
      } else {
        expect([401, 403]).toContain(response.status);
      }
    }

    const linkProvider = await exports.default.fetch(
      new Request(`${BASE_URL}/link-social`, {
        method: "POST",
        headers: {
          Cookie: recoveryCookie,
          "Content-Type": "application/json",
          Origin: BASE_URL,
        },
        body: JSON.stringify({
          provider: "google",
          callbackURL: `${BASE_URL}/`,
        }),
      }),
    );
    expect(linkProvider.status).toBe(401);

    const clientId = await seedVisitedRp(session.userId, session.sessionId);
    const redirectUri = `https://${clientId}.example/callback`;
    const authorizeQuery = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid offline_access",
      code_challenge: "A".repeat(43),
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const authorize = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/authorize?${authorizeQuery}`, {
        headers: { Cookie: recoveryCookie, "Sec-Fetch-Mode": "cors" },
        redirect: "manual",
      }),
    );
    expect(authorize.status).toBe(302);
    const location = new URL(authorize.headers.get("location") ?? "", BASE_URL);
    expect(location.pathname).toBe("/sign-in");
    expect(location.pathname).not.toBe("/consent");
  });

  it("cancellation never restores the consumed code and leaves the other nine valid", async () => {
    const session = await createAuthenticatedUser(
      `recovery-cancel-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    const cookie = cookieFrom(started);
    const cancelled = await exports.default.fetch(
      recoveryRequest("/api/recovery/session", {
        method: "DELETE",
        headers: { Cookie: cookie },
      }),
    );
    expect(cancelled.status).toBe(200);
    expect((await startRecovery(issued.payload.codes[0] ?? "")).status).toBe(400);
    expect((await startRecovery(issued.payload.codes[1] ?? "")).status).toBe(200);
  });

  it("fails closed when the recovery limiter binding is unavailable", async () => {
    const requestEnv = {
      ...env,
      RECOVERY_RATE_LIMITER: {
        limit: async () => {
          throw new Error("unavailable");
        },
      },
    } as Env;
    const ctx = createExecutionContext();
    const response = await app.fetch(
      recoveryRequest("/api/recovery/start", {
        method: "POST",
        body: JSON.stringify({ code: "secret-code-must-not-echo" }),
      }),
      requestEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("secret-code-must-not-echo");
  });

  it("does not accept a valid code from a non-JSON request", async () => {
    const session = await createAuthenticatedUser(
      `recovery-entry-media-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const code = issued.payload.codes[0] ?? "";
    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/api/recovery/start`, {
        method: "POST",
        headers: {
          "CF-Connecting-IP": `192.0.2.${recoveryIpSequence++}`,
          "Content-Type": "text/plain",
          Origin: BASE_URL,
        },
        body: JSON.stringify({ code }),
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "recovery_not_available" });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT consumed_at FROM recovery_code WHERE code_hash = ?",
      )
        .bind(await sha256Base64Url(canonicalRecoveryCode(code) ?? ""))
        .first<{ consumed_at: string | null }>(),
    ).toEqual({ consumed_at: null });
  });

  it("requires an empty JSON object before creating Passkey options", async () => {
    const session = await createAuthenticatedUser(
      `recovery-options-media-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    const cookie = cookieFrom(started);

    const wrongMediaType = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/options", {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "text/plain" },
        body: "{}",
      }),
    );
    expect(wrongMediaType.status).toBe(415);
    const extraField = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/options", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({ extra: true }),
      }),
    );
    expect(extraField.status).toBe(400);
    expect((await beginPasskeyRecovery(cookie)).challengeId).toMatch(
      /^[0-9a-f-]{36}$/,
    );
  });
});

describe("recovery Passkey completion", () => {
  it("rejects a 1024-byte outer credential ID before verifier completion", async () => {
    const session = await createAuthenticatedUser(
      `recovery-outer-id-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    const cookie = cookieFrom(started);
    const options = await beginPasskeyRecovery(cookie);
    const registration = await createRegistration(options.options.challenge, {
      credentialByteLength: 1024,
    });
    expect(isoBase64URL.toBuffer(registration.credentialId).byteLength).toBe(1024);
    const before = await recoveryCompletionState(session.userId);

    const verified = await verifyRecoveryWithQueueSpies(
      cookie,
      options,
      registration.response,
    );
    expect(verified.response.status).toBe(400);
    expect(await verified.response.json()).toEqual({
      error: "recovery_passkey_failed",
    });
    // A matched challenge remains one-time even when the parsed credential is
    // rejected before SimpleWebAuthn. The failure audit/security event below
    // are intentional; no completion state or logout work may change.
    expect(await recoveryCompletionState(session.userId)).toEqual(before);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM recovery_passkey_challenge WHERE id = ?",
      )
        .bind(options.challengeId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM audit_event
          WHERE subject_id = ? AND event_type = 'recovery.passkey_failed'`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(verified.securitySend).toHaveBeenCalledTimes(1);
    expect(verified.logoutSend).not.toHaveBeenCalled();
  });

  it("rejects verifier credential mismatches before every completion mutation", async () => {
    for (const idCase of [
      { embeddedBytes: 32, outerBytes: 32 },
      { embeddedBytes: 1024, outerBytes: 1023 },
    ]) {
      const session = await createAuthenticatedUser(
        `recovery-id-mismatch-${crypto.randomUUID()}@example.test`,
        "user",
        { passkeyStepUp: true },
      );
      const issued = await issueCodes(session);
      const started = await startRecovery(issued.payload.codes[0] ?? "");
      const cookie = cookieFrom(started);
      const options = await beginPasskeyRecovery(cookie);
      const registration = await createRegistration(options.options.challenge, {
        credentialByteLength: idCase.embeddedBytes,
      });
      const outerId = isoBase64URL.fromBuffer(
        crypto.getRandomValues(
          new Uint8Array(new ArrayBuffer(idCase.outerBytes)),
        ),
      );
      expect(outerId).not.toBe(registration.credentialId);
      const mismatched: RegistrationResponseJSON = {
        ...registration.response,
        id: outerId,
        rawId: outerId,
      };
      const before = await recoveryCompletionState(session.userId);

      const verified = await verifyRecoveryWithQueueSpies(
        cookie,
        options,
        mismatched,
      );
      expect(verified.response.status).toBe(400);
      expect(await verified.response.json()).toEqual({
        error: "recovery_passkey_failed",
      });
      // Authoritative-ID rejection happens after verifier success and keeps
      // the same one-time challenge and failure-audit policy. The aggregate
      // snapshot excludes those intentional effects and covers every
      // completion mutation plus central session/logout state.
      expect(await recoveryCompletionState(session.userId)).toEqual(before);
      expect(
        await env.PG72_ID_DB.prepare(
          "SELECT COUNT(*) AS count FROM recovery_passkey_challenge WHERE id = ?",
        )
          .bind(options.challengeId)
          .first<{ count: number }>(),
      ).toEqual({ count: 0 });
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT COUNT(*) AS count FROM audit_event
            WHERE subject_id = ? AND event_type = 'recovery.passkey_failed'`,
        )
          .bind(session.userId)
          .first<{ count: number }>(),
      ).toEqual({ count: 1 });
      expect(verified.securitySend).toHaveBeenCalledTimes(1);
      expect(verified.logoutSend).not.toHaveBeenCalled();
    }
  });

  it("requires exact origin and UV, consumes challenges once, then atomically rotates and revokes all normal sessions", async () => {
    const session = await createAuthenticatedUser(
      `recovery-complete-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    const cookie = cookieFrom(started);

    const badOptions = await beginPasskeyRecovery(cookie);
    const badRegistration = await createRegistration(badOptions.options.challenge, {
      origin: "https://wrong.example",
    });
    const badVerify = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/verify", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({
          challengeId: badOptions.challengeId,
          response: badRegistration.response,
        }),
      }),
    );
    expect(badVerify.status).toBe(400);
    const replay = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/verify", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({
          challengeId: badOptions.challengeId,
          response: badRegistration.response,
        }),
      }),
    );
    expect(replay.status).toBe(400);

    const noUvOptions = await beginPasskeyRecovery(cookie);
    const noUvRegistration = await createRegistration(
      noUvOptions.options.challenge,
      { userVerified: false },
    );
    const noUvVerify = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/verify", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({
          challengeId: noUvOptions.challengeId,
          response: noUvRegistration.response,
        }),
      }),
    );
    expect(noUvVerify.status).toBe(400);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT 1 AS present FROM passkey WHERE credentialID = ?",
      )
        .bind(noUvRegistration.credentialId)
        .first(),
    ).toBeNull();

    const options = await beginPasskeyRecovery(cookie);
    expect(options.options.authenticatorSelection?.userVerification).toBe("required");
    expect(options.options.authenticatorSelection?.residentKey).toBe("preferred");
    expect(options.options.attestation).toBe("none");
    const registration = await createRegistration(options.options.challenge, {
      credentialByteLength: 1023,
    });
    expect(isoBase64URL.toBuffer(registration.credentialId).byteLength).toBe(1023);
    const clientId = await seedVisitedRp(session.userId, session.sessionId);
    const queueFailureEnv = {
      ...env,
      LOGOUT_DELIVERIES: {
        send: vi.fn(async () => {
          throw new Error("queue unavailable");
        }),
      } as unknown as Queue,
      SECURITY_EVENTS: {
        send: vi.fn(async () => {
          throw new Error("queue unavailable");
        }),
      } as unknown as Queue,
    } as Env;
    const ctx = createExecutionContext();
    const verified = await app.fetch(
      recoveryRequest("/api/recovery/passkey/verify", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({
          challengeId: options.challengeId,
          response: registration.response,
        }),
      }),
      queueFailureEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(verified.status).toBe(200);
    const payload = (await verified.json()) as IssuedCodes & {
      completed: boolean;
      signInRequired: boolean;
    };
    expect(payload.completed).toBe(true);
    expect(payload.signInRequired).toBe(true);
    expect(payload.codes).toHaveLength(10);
    expect(payload.generation).toBe(2);
    expect(verified.headers.get("set-cookie")).toContain("Max-Age=0");

    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM session WHERE userId = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM recovery_session WHERE user_id = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    const passkey = await env.PG72_ID_DB.prepare(
      `SELECT counter, credentialID FROM passkey
        WHERE userId = ? AND credentialID = ?`,
    )
      .bind(session.userId, registration.credentialId)
      .first<{ counter: number; credentialID: string }>();
    expect(passkey).toEqual({ counter: 0, credentialID: registration.credentialId });
    const active = await env.PG72_ID_DB.prepare(
      `SELECT generation,
              (SELECT COUNT(*) FROM recovery_code WHERE set_id = recovery_code_set.id)
                AS code_count
         FROM recovery_code_set
        WHERE user_id = ? AND revoked_at IS NULL`,
    )
      .bind(session.userId)
      .first<{ code_count: number; generation: number }>();
    expect(active).toEqual({ generation: 2, code_count: 10 });
    const delivery = await env.PG72_ID_DB.prepare(
      `SELECT client_id, reason, status FROM logout_delivery
        WHERE user_id = ? AND client_id = ?`,
    )
      .bind(session.userId, clientId)
      .first<{ client_id: string; reason: string; status: string }>();
    expect(delivery).toEqual({
      client_id: clientId,
      reason: "self_revoke",
      status: "pending",
    });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM oauthAccessToken WHERE userId = ?`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM oauthRefreshToken
          WHERE userId = ? AND revoked IS NULL`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json FROM audit_event
        WHERE event_type = 'recovery.completed' AND subject_id = ?`,
    )
      .bind(session.userId)
      .first<{ metadata_json: string }>();
    const auditText = audit?.metadata_json ?? "";
    issued.payload.codes.forEach((code) => expect(auditText).not.toContain(code));
    payload.codes.forEach((code) => expect(auditText).not.toContain(code));

    const normalOptionsResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/passkey/generate-authenticate-options`, {
        headers: { Origin: BASE_URL },
      }),
    );
    expect(normalOptionsResponse.status).toBe(200);
    const normalOptions =
      (await normalOptionsResponse.json()) as PublicKeyCredentialRequestOptionsJSON;
    const normalAssertion = await createAuthentication(
      registration,
      normalOptions.challenge,
    );
    const normalSignIn = await exports.default.fetch(
      new Request(`${BASE_URL}/passkey/verify-authentication`, {
        method: "POST",
        headers: {
          Cookie: cookieFrom(normalOptionsResponse),
          "Content-Type": "application/json",
          Origin: BASE_URL,
        },
        body: JSON.stringify({ response: normalAssertion }),
      }),
    );
    expect(normalSignIn.status).toBe(200);
    expect(await normalSignIn.json()).toMatchObject({
      user: { id: session.userId },
    });
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT COUNT(*) AS count FROM session WHERE userId = ?",
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
  });

  it("rolls back Passkey, code rotation, audit, logout, and session revocation when the completion batch fails", async () => {
    const session = await createAuthenticatedUser(
      `recovery-rollback-${crypto.randomUUID()}@example.test`,
      "user",
      { passkeyStepUp: true },
    );
    const issued = await issueCodes(session);
    const started = await startRecovery(issued.payload.codes[0] ?? "");
    const cookie = cookieFrom(started);
    const options = await beginPasskeyRecovery(cookie);
    const registration = await createRegistration(options.options.challenge);

    const realDatabase = env.PG72_ID_DB;
    let sabotaged = false;
    const failingDatabase = new Proxy(realDatabase, {
      get(target, property) {
        if (property === "batch") {
          return async (statements: D1PreparedStatement[]) => {
            if (sabotaged) return target.batch(statements);
            sabotaged = true;
            return target.batch([
              ...statements,
              target.prepare(
                `INSERT INTO recovery_code
                  (id, set_id, ordinal, code_hash, consumed_at)
                 VALUES (?, ?, 1, 'plaintext-is-forbidden', NULL)`,
              ).bind(crypto.randomUUID(), crypto.randomUUID()),
            ]);
          };
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const requestEnv = { ...env, PG72_ID_DB: failingDatabase } as Env;
    const ctx = createExecutionContext();
    const response = await app.fetch(
      recoveryRequest("/api/recovery/passkey/verify", {
        method: "POST",
        headers: { Cookie: cookie },
        body: JSON.stringify({
          challengeId: options.challengeId,
          response: registration.response,
        }),
      }),
      requestEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(500);
    expect(sabotaged).toBe(true);
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT 1 AS present FROM passkey WHERE credentialID = ?",
      )
        .bind(registration.credentialId)
        .first(),
    ).toBeNull();
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM recovery_code_set
          WHERE user_id = ? AND generation > 1`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM recovery_session WHERE user_id = ?`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM session WHERE userId = ?`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(
      await env.PG72_ID_DB.prepare(
        `SELECT COUNT(*) AS count FROM audit_event
          WHERE subject_id = ? AND event_type = 'recovery.completed'`,
      )
        .bind(session.userId)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    const stillUsable = await exports.default.fetch(
      recoveryRequest("/api/recovery/passkey/options", {
        method: "POST",
        headers: { Cookie: cookie },
        body: "{}",
      }),
    );
    expect(stillUsable.status).toBe(200);
  });
});
