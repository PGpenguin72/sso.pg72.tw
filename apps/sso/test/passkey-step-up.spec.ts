import { env, exports } from "cloudflare:workers";
import {
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import { isoBase64URL, isoCBOR } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";

import { createAuthenticatedUser, createSessionFor } from "./helpers";

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
  options: { origin?: string; userVerified?: boolean } = {},
): Promise<AuthenticationResponseJSON> {
  const origin = options.origin ?? BASE_URL;
  const userVerified = options.userVerified ?? true;
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
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("localhost")),
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
    id: authenticator.credentialId,
    rawId: authenticator.credentialId,
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
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );

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

  it("rejects high-risk mutations until the current session steps up", async () => {
    const admin = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "admin",
    );
    await createAuthenticator(admin.userId);

    const response = await createClient(
      admin,
      `no-step-up-${crypto.randomUUID()}`,
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      code: "PASSKEY_STEP_UP_REQUIRED",
      error: "passkey_step_up_required",
    });
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
      `SELECT outcome FROM audit_event
        WHERE event_type = 'passkey.step_up_succeeded' AND subject_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(admin.userId)
      .first<{ outcome: string }>();
    expect(audit).toEqual({ outcome: "success" });

    const mutation = await createClient(
      admin,
      `stepped-up-${crypto.randomUUID()}`,
    );
    expect(mutation.status).toBe(201);
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
