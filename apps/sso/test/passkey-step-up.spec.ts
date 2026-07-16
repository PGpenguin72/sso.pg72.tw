import { env, exports } from "cloudflare:workers";
import {
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";

import { readRuntimeConfig } from "../worker/config";
import {
  createAuthenticatedUser,
  createBootstrapAdmin,
  createSessionFor,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const CHALLENGE_URL = `${BASE_URL}/api/account/passkey-step-up/challenge`;
const VERIFY_URL = `${BASE_URL}/api/account/passkey-step-up/verify`;
const CLIENTS_URL = `${BASE_URL}/api/admin/clients`;

interface TestAuthenticator {
  counter: number;
  credentialId: string;
  passkeyId: string;
  privateKey: CryptoKey;
}

interface StepUpChallengeResponse {
  challengeId: string;
  options: PublicKeyCredentialRequestOptionsJSON;
  verified: boolean;
}

interface SessionFixture {
  headers: Headers;
  sessionId: string;
  userId: string;
}

function concatBytes(
  ...parts: Uint8Array<ArrayBuffer>[]
): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(
    new ArrayBuffer(parts.reduce((total, part) => total + part.length, 0)),
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

async function createAuthenticator(userId: string): Promise<TestAuthenticator> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const rawPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  expect(rawPublicKey[0]).toBe(0x04);
  const cosePublicKey = isoCBOR.encode(
    new Map<number, number | Uint8Array<ArrayBuffer>>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, rawPublicKey.slice(1, 33)],
      [-3, rawPublicKey.slice(33, 65)],
    ]),
  );
  const credentialBytes = crypto.getRandomValues(new Uint8Array(32));
  const credentialId = isoBase64URL.fromBuffer(credentialBytes);
  const passkeyId = crypto.randomUUID();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO passkey
      (id, name, publicKey, userId, credentialID, counter, deviceType,
       backedUp, transports, createdAt, aaguid)
     VALUES (?, ?, ?, ?, ?, 0, 'singleDevice', 0, 'internal', ?, NULL)`,
  )
    .bind(
      passkeyId,
      "Workerd test authenticator",
      isoBase64URL.fromBuffer(cosePublicKey, "base64"),
      userId,
      credentialId,
      new Date().toISOString(),
    )
    .run();
  return {
    counter: 0,
    credentialId,
    passkeyId,
    privateKey: keyPair.privateKey,
  };
}

async function createAssertion(
  authenticator: TestAuthenticator,
  challenge: string,
  options: {
    credentialId?: string;
    origin?: string;
    rpId?: string;
    userVerified?: boolean;
  } = {},
): Promise<AuthenticationResponseJSON> {
  const origin = options.origin ?? BASE_URL;
  const rpId = options.rpId ?? "localhost";
  const userVerified = options.userVerified ?? true;
  const credentialId = options.credentialId ?? authenticator.credentialId;
  authenticator.counter += 1;

  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      challenge,
      crossOrigin: false,
      origin,
      type: "webauthn.get",
    }),
  );
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)),
  );
  const authenticatorData = new Uint8Array(new ArrayBuffer(37));
  authenticatorData.set(rpIdHash, 0);
  authenticatorData[32] = userVerified ? 0x05 : 0x01;
  new DataView(authenticatorData.buffer).setUint32(
    33,
    authenticator.counter,
    false,
  );
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSON),
  );
  const signedData = concatBytes(authenticatorData, clientDataHash);
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      authenticator.privateKey,
      signedData,
    ),
  );

  return {
    id: credentialId,
    rawId: credentialId,
    response: {
      authenticatorData: isoBase64URL.fromBuffer(authenticatorData),
      clientDataJSON: isoBase64URL.fromBuffer(clientDataJSON),
      signature: isoBase64URL.fromBuffer(rawEcdsaToDer(rawSignature)),
    },
    clientExtensionResults: {},
    type: "public-key",
  };
}

async function requestChallenge(
  session: SessionFixture,
): Promise<{ payload: StepUpChallengeResponse; response: Response }> {
  const response = await exports.default.fetch(
    new Request(CHALLENGE_URL, { method: "POST", headers: session.headers }),
  );
  return {
    payload: (await response.json()) as StepUpChallengeResponse,
    response,
  };
}

function verifyStepUp(
  session: SessionFixture,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<Response> {
  return exports.default.fetch(
    new Request(VERIFY_URL, {
      method: "POST",
      headers: session.headers,
      body: JSON.stringify({ challengeId, response }),
    }),
  );
}

function createClient(session: SessionFixture, clientId: string): Promise<Response> {
  return exports.default.fetch(
    new Request(CLIENTS_URL, {
      method: "POST",
      headers: session.headers,
      body: JSON.stringify({
        clientId,
        developerName: "Step-up Test Team",
        name: "Step-up Test Client",
        redirectUris: [`https://${clientId}.example/callback`],
      }),
    }),
  );
}

async function expectNoSuccessfulStepUp(
  session: SessionFixture,
): Promise<void> {
  const state = await env.PG72_ID_DB.prepare(
    "SELECT passkeyStepUpAt FROM session WHERE id = ? AND userId = ?",
  )
    .bind(session.sessionId, session.userId)
    .first<{ passkeyStepUpAt: string | null }>();
  expect(state?.passkeyStepUpAt).toBeNull();

  const audit = await env.PG72_ID_DB.prepare(
    `SELECT COUNT(*) AS count FROM audit_event
      WHERE event_type = 'passkey.step_up_succeeded' AND subject_id = ?`,
  )
    .bind(session.userId)
    .first<{ count: number }>();
  expect(audit?.count).toBe(0);
}

async function expectClientMutationLocked(
  session: SessionFixture,
  expectedStatus = 403,
): Promise<void> {
  const response = await createClient(
    session,
    `still-locked-${crypto.randomUUID()}`,
  );
  expect(response.status).toBe(expectedStatus);
  expect(await response.json()).toEqual(
    expectedStatus === 401
      ? { error: "unauthorized" }
      : {
          code: "PASSKEY_STEP_UP_REQUIRED",
          error: "passkey_step_up_required",
        },
  );
}

async function stepUp(
  session: SessionFixture,
  authenticator: TestAuthenticator,
): Promise<{
  assertion: AuthenticationResponseJSON;
  challenge: StepUpChallengeResponse;
  response: Response;
}> {
  const generated = await requestChallenge(session);
  expect(generated.response.status).toBe(200);
  expect(generated.payload.options.userVerification).toBe("required");
  expect(generated.payload.options.rpId).toBe("localhost");
  expect(generated.payload.options.allowCredentials?.map(({ id }) => id)).toEqual(
    [authenticator.credentialId],
  );
  const assertion = await createAssertion(
    authenticator,
    generated.payload.options.challenge,
  );
  const response = await verifyStepUp(
    session,
    generated.payload.challengeId,
    assertion,
  );
  return { assertion, challenge: generated.payload, response };
}

describe("Passkey step-up", () => {
  it("requires enrollment and never grants bootadmin a bypass", async () => {
    const admin = await createBootstrapAdmin();
    await env.PG72_ID_DB.prepare("DELETE FROM passkey WHERE userId = ?")
      .bind(admin.userId)
      .run();

    const mutation = await createClient(
      admin,
      `missing-passkey-${crypto.randomUUID()}`,
    );
    expect(mutation.status).toBe(403);
    expect(await mutation.json()).toEqual({
      code: "PASSKEY_ENROLLMENT_REQUIRED",
      error: "passkey_enrollment_required",
    });

    const challenge = await requestChallenge(admin);
    expect(challenge.response.status).toBe(403);
    expect(challenge.payload).toMatchObject({
      code: "PASSKEY_ENROLLMENT_REQUIRED",
      error: "passkey_enrollment_required",
    });
  });

  it("gates all six high-risk client mutations on the current session", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    await createAuthenticator(admin.userId);
    const clientId = `no-step-up-${crypto.randomUUID()}`;
    const mutations = [
      {
        body: {
          clientId,
          developerName: "Step-up Test Team",
          name: "Step-up Test Client",
          redirectUris: [`https://${clientId}.example/callback`],
        },
        method: "POST",
        name: "create",
        url: CLIENTS_URL,
      },
      {
        body: { developerName: "Updated Step-up Test Team" },
        method: "PATCH",
        name: "trust",
        url: `${CLIENTS_URL}/${clientId}`,
      },
      {
        method: "POST",
        name: "rotate",
        url: `${CLIENTS_URL}/${clientId}/rotate-secret`,
      },
      {
        body: { disabled: true },
        method: "POST",
        name: "status",
        url: `${CLIENTS_URL}/${clientId}/status`,
      },
      {
        method: "DELETE",
        name: "delete",
        url: `${CLIENTS_URL}/${clientId}`,
      },
      {
        method: "POST",
        name: "provision",
        url: `${CLIENTS_URL}/provision-mail-introspector`,
      },
    ] as const;

    for (const mutation of mutations) {
      const response = await exports.default.fetch(
        new Request(mutation.url, {
          method: mutation.method,
          headers: admin.headers,
          ...("body" in mutation
            ? { body: JSON.stringify(mutation.body) }
            : {}),
        }),
      );
      expect(response.status, mutation.name).toBe(403);
      expect(await response.json(), mutation.name).toEqual({
        code: "PASSKEY_STEP_UP_REQUIRED",
        error: "passkey_step_up_required",
      });
    }
  });

  it("pins the production origin and RP ID to sso.pg72.tw", () => {
    const productionEnv = {
      ...env,
      AUTH_BASE_URL: "https://sso.pg72.tw",
      ENVIRONMENT: "production",
      PASSKEY_ORIGIN: "https://sso.pg72.tw",
      PASSKEY_RP_ID: "sso.pg72.tw",
    };
    const config = readRuntimeConfig(productionEnv);
    expect(config.authBaseUrl).toBe("https://sso.pg72.tw");
    expect(config.passkeyOrigin).toBe("https://sso.pg72.tw");
    expect(config.passkeyRpId).toBe("sso.pg72.tw");

    expect(() =>
      readRuntimeConfig({
        ...productionEnv,
        PASSKEY_ORIGIN: "https://login.pg72.tw",
      }),
    ).toThrow("Production Passkey origin/RP ID must be sso.pg72.tw");
    expect(() =>
      readRuntimeConfig({ ...productionEnv, PASSKEY_RP_ID: "pg72.tw" }),
    ).toThrow("Production Passkey origin/RP ID must be sso.pg72.tw");
  });

  it("enforces exact request Origin and the step-up body limit", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );

    for (const origin of [undefined, "https://attacker.example"]) {
      const headers = new Headers(admin.headers);
      if (origin) headers.set("Origin", origin);
      else headers.delete("Origin");
      const response = await exports.default.fetch(
        new Request(CHALLENGE_URL, { method: "POST", headers }),
      );
      expect(response.status).toBe(403);
      expect(await response.json()).toEqual({ error: "invalid_origin" });
    }

    const oversized = await exports.default.fetch(
      new Request(VERIFY_URL, {
        method: "POST",
        headers: admin.headers,
        body: JSON.stringify({ padding: "x".repeat(17 * 1024) }),
      }),
    );
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toEqual({ error: "request_too_large" });
  });

  it("records a verified assertion and unlocks client mutations", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);

    const verified = await stepUp(admin, authenticator);
    expect(verified.response.status).toBe(200);
    expect(await verified.response.json()).toMatchObject({ verified: true });

    const state = await env.PG72_ID_DB.prepare(
      `SELECT s.passkeyStepUpAt AS verified_at, p.counter
         FROM session s JOIN passkey p ON p.id = ?
        WHERE s.id = ?`,
    )
      .bind(authenticator.passkeyId, admin.sessionId)
      .first<{ counter: number; verified_at: string | null }>();
    expect(state?.verified_at).not.toBeNull();
    expect(state?.counter).toBe(1);
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json, outcome FROM audit_event
        WHERE event_type = 'passkey.step_up_succeeded' AND subject_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(admin.userId)
      .first<{ metadata_json: string; outcome: string }>();
    expect(audit).toEqual({
      metadata_json: JSON.stringify({ method: "passkey" }),
      outcome: "success",
    });
    expect(audit?.metadata_json).not.toContain(
      verified.challenge.options.challenge,
    );
    expect(audit?.metadata_json).not.toContain(authenticator.credentialId);

    const mutation = await createClient(
      admin,
      `stepped-up-${crypto.randomUUID()}`,
    );
    expect(mutation.status).toBe(201);
  });

  it.each([
    {
      label: "wrong assertion origin",
      options: { origin: "https://attacker.example" },
    },
    {
      label: "wrong RP ID hash",
      options: { rpId: "attacker.example" },
    },
  ])("rejects $label without recording a step-up", async ({ options }) => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    expect(generated.response.status).toBe(200);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
      options,
    );

    const response = await verifyStepUp(
      admin,
      generated.payload.challengeId,
      assertion,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "passkey_step_up_failed" });
    await expectNoSuccessfulStepUp(admin);

    const deniedAudit = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json FROM audit_event
        WHERE event_type = 'passkey.step_up_failed' AND subject_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(admin.userId)
      .first<{ metadata_json: string }>();
    expect(deniedAudit?.metadata_json).toBe(
      JSON.stringify({ reason: "assertion_invalid" }),
    );
    expect(deniedAudit?.metadata_json).not.toContain(
      generated.payload.options.challenge,
    );
    expect(deniedAudit?.metadata_json).not.toContain(
      authenticator.credentialId,
    );
  });

  it("rejects an expired challenge without verifying the session", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    expect(generated.response.status).toBe(200);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );
    const createdAt = new Date(Date.now() - 2 * 60 * 1000);
    const expiresAt = new Date(Date.now() - 60 * 1000);
    await env.PG72_ID_DB.prepare(
      `UPDATE passkey_step_up_challenge
          SET created_at = ?, expires_at = ?
        WHERE id = ?`,
    )
      .bind(
        createdAt.toISOString(),
        expiresAt.toISOString(),
        generated.payload.challengeId,
      )
      .run();

    const response = await verifyStepUp(
      admin,
      generated.payload.challengeId,
      assertion,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "passkey_step_up_challenge_invalid",
    });
    await expectNoSuccessfulStepUp(admin);
  });

  it("returns the same error for unknown and another user's credential", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    await createAuthenticator(admin.userId);
    const other = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "user",
    );
    const otherAuthenticator = await createAuthenticator(other.userId);
    const payloads: unknown[] = [];

    for (const credentialId of [
      isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(32))),
      otherAuthenticator.credentialId,
    ]) {
      const generated = await requestChallenge(admin);
      expect(generated.response.status).toBe(200);
      const assertion = await createAssertion(
        otherAuthenticator,
        generated.payload.options.challenge,
        { credentialId },
      );
      const response = await verifyStepUp(
        admin,
        generated.payload.challengeId,
        assertion,
      );
      expect(response.status).toBe(401);
      payloads.push(await response.json());
    }

    expect(payloads).toEqual([
      { error: "passkey_step_up_failed" },
      { error: "passkey_step_up_failed" },
    ]);
    await expectNoSuccessfulStepUp(admin);
    const deniedAudits = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json FROM audit_event
        WHERE event_type = 'passkey.step_up_failed' AND subject_id = ?`,
    )
      .bind(admin.userId)
      .all<{ metadata_json: string }>();
    expect(deniedAudits.results).toHaveLength(2);
    for (const audit of deniedAudits.results) {
      expect(audit.metadata_json).toBe(
        JSON.stringify({ reason: "credential_invalid" }),
      );
      expect(audit.metadata_json).not.toContain(otherAuthenticator.credentialId);
    }
  });

  it("consumes each challenge exactly once", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const verified = await stepUp(admin, authenticator);
    expect(verified.response.status).toBe(200);

    const replay = await verifyStepUp(
      admin,
      verified.challenge.challengeId,
      verified.assertion,
    );
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({
      error: "passkey_step_up_challenge_invalid",
    });
  });

  it("binds a challenge to the session that created it", async () => {
    const first = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const second = await createSessionFor(first.userId);
    const authenticator = await createAuthenticator(first.userId);
    const generated = await requestChallenge(first);
    expect(generated.response.status).toBe(200);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );

    const moved = await verifyStepUp(
      second,
      generated.payload.challengeId,
      assertion,
    );
    expect(moved.status).toBe(400);
    expect(await moved.json()).toEqual({
      error: "passkey_step_up_challenge_invalid",
    });
    const secondState = await env.PG72_ID_DB.prepare(
      "SELECT passkeyStepUpAt FROM session WHERE id = ?",
    )
      .bind(second.sessionId)
      .first<{ passkeyStepUpAt: string | null }>();
    expect(secondState?.passkeyStepUpAt).toBeNull();

    const original = await verifyStepUp(
      first,
      generated.payload.challengeId,
      assertion,
    );
    expect(original.status).toBe(200);
  });

  it("fails closed when the guarded authenticator counter conflicts", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );
    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER ignore_step_up_counter
       BEFORE UPDATE OF counter ON passkey
       BEGIN
         SELECT RAISE(IGNORE);
       END`,
    ).run();
    let response: Response;
    try {
      response = await verifyStepUp(
        admin,
        generated.payload.challengeId,
        assertion,
      );
    } finally {
      await env.PG72_ID_DB.prepare(
        "DROP TRIGGER ignore_step_up_counter",
      ).run();
    }

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "passkey_step_up_failed" });
    const counter = await env.PG72_ID_DB.prepare(
      "SELECT counter FROM passkey WHERE id = ?",
    )
      .bind(authenticator.passkeyId)
      .first<{ counter: number }>();
    expect(counter?.counter).toBe(0);
    await expectNoSuccessfulStepUp(admin);
    await expectClientMutationLocked(admin);
  });

  it("does not leave a valid step-up when the session disappears mid-batch", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );
    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER delete_step_up_session
       BEFORE INSERT ON audit_event
       WHEN NEW.event_type = 'passkey.step_up_succeeded'
       BEGIN
         DELETE FROM session WHERE userId = NEW.actor_user_id;
       END`,
    ).run();
    let response: Response;
    try {
      response = await verifyStepUp(
        admin,
        generated.payload.challengeId,
        assertion,
      );
    } finally {
      await env.PG72_ID_DB.prepare(
        "DROP TRIGGER delete_step_up_session",
      ).run();
    }

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "internal_server_error" });
    const session = await env.PG72_ID_DB.prepare(
      "SELECT passkeyStepUpAt FROM session WHERE id = ?",
    )
      .bind(admin.sessionId)
      .first();
    expect(session).toBeNull();
    const successAudit = await env.PG72_ID_DB.prepare(
      `SELECT id FROM audit_event
        WHERE event_type = 'passkey.step_up_succeeded' AND subject_id = ?`,
    )
      .bind(admin.userId)
      .first();
    expect(successAudit).toBeNull();
    await expectClientMutationLocked(admin, 401);
  });

  it("rolls back the audit batch without writing a timestamp", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );
    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER abort_step_up_audit
       BEFORE INSERT ON audit_event
       WHEN NEW.event_type = 'passkey.step_up_succeeded'
       BEGIN
         SELECT RAISE(ABORT, 'forced step-up audit failure');
       END`,
    ).run();
    let response: Response;
    try {
      response = await verifyStepUp(
        admin,
        generated.payload.challengeId,
        assertion,
      );
    } finally {
      await env.PG72_ID_DB.prepare("DROP TRIGGER abort_step_up_audit").run();
    }

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "internal_server_error" });
    const state = await env.PG72_ID_DB.prepare(
      `SELECT s.passkeyStepUpAt AS verified_at, p.counter
         FROM session s JOIN passkey p ON p.id = ?
        WHERE s.id = ?`,
    )
      .bind(authenticator.passkeyId, admin.sessionId)
      .first<{ counter: number; verified_at: string | null }>();
    expect(state).toEqual({ counter: 1, verified_at: null });
    const challenge = await env.PG72_ID_DB.prepare(
      "SELECT id FROM passkey_step_up_challenge WHERE id = ?",
    )
      .bind(generated.payload.challengeId)
      .first();
    expect(challenge).toBeNull();
    await expectNoSuccessfulStepUp(admin);
    await expectClientMutationLocked(admin);
  });

  it("clears a timestamp when an audit insert is ignored", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
    );
    await env.PG72_ID_DB.prepare(
      `CREATE TRIGGER ignore_step_up_audit
       BEFORE INSERT ON audit_event
       WHEN NEW.event_type = 'passkey.step_up_succeeded'
       BEGIN
         SELECT RAISE(IGNORE);
       END`,
    ).run();
    let response: Response;
    try {
      response = await verifyStepUp(
        admin,
        generated.payload.challengeId,
        assertion,
      );
    } finally {
      await env.PG72_ID_DB.prepare("DROP TRIGGER ignore_step_up_audit").run();
    }

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: "internal_server_error" });
    const counter = await env.PG72_ID_DB.prepare(
      "SELECT counter FROM passkey WHERE id = ?",
    )
      .bind(authenticator.passkeyId)
      .first<{ counter: number }>();
    expect(counter?.counter).toBe(1);
    await expectNoSuccessfulStepUp(admin);
    await expectClientMutationLocked(admin);
  });

  it("rejects an expired step-up timestamp", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const verified = await stepUp(admin, authenticator);
    expect(verified.response.status).toBe(200);
    await env.PG72_ID_DB.prepare(
      "UPDATE session SET passkeyStepUpAt = ? WHERE id = ?",
    )
      .bind(new Date(0).toISOString(), admin.sessionId)
      .run();

    const mutation = await createClient(
      admin,
      `expired-step-up-${crypto.randomUUID()}`,
    );
    expect(mutation.status).toBe(403);
    expect(await mutation.json()).toEqual({
      code: "PASSKEY_STEP_UP_REQUIRED",
      error: "passkey_step_up_required",
    });
  });

  it("requires authenticator user verification", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    const authenticator = await createAuthenticator(admin.userId);
    const generated = await requestChallenge(admin);
    const assertion = await createAssertion(
      authenticator,
      generated.payload.options.challenge,
      { userVerified: false },
    );

    const response = await verifyStepUp(
      admin,
      generated.payload.challengeId,
      assertion,
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "passkey_step_up_failed" });
    const state = await env.PG72_ID_DB.prepare(
      "SELECT passkeyStepUpAt FROM session WHERE id = ?",
    )
      .bind(admin.sessionId)
      .first<{ passkeyStepUpAt: string | null }>();
    expect(state?.passkeyStepUpAt).toBeNull();
  });
});
