import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { ssoRoot } from "./local-runtime.mjs";

const requireFromSso = createRequire(path.join(ssoRoot, "package.json"));
const betterAuthCrypto = await import(
  pathToFileURL(requireFromSso.resolve("better-auth/crypto")).href,
);
const { isoCBOR } = await import(
  pathToFileURL(requireFromSso.resolve("@simplewebauthn/server/helpers")).href,
);

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64Url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return new Uint8Array(
    Buffer.from(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="), "base64"),
  );
}

function randomBase64Url(bytes = 32) {
  return base64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function sha256Base64Url(value) {
  return base64Url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

function sqlLiteral(value) {
  assert.equal(typeof value, "string");
  assert.ok(!value.includes("\u0000"));
  return `'${value.replaceAll("'", "''")}'`;
}

function addDays(timestamp, days) {
  return new Date(timestamp.getTime() + days * 86_400_000).toISOString();
}

async function createSigningKey(id, betterAuthSecret, createdAt, expiresAt) {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const exportedPublic = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const exportedPrivate = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const {
    alg: _publicAlgorithm,
    ext: _publicExtractable,
    key_ops: _publicOperations,
    ...publicJwk
  } = exportedPublic;
  const {
    alg: _privateAlgorithm,
    ext: _privateExtractable,
    key_ops: _privateOperations,
    ...privateJwk
  } = exportedPrivate;
  const encrypted = await betterAuthCrypto.symmetricEncrypt({
    key: betterAuthSecret,
    data: JSON.stringify(privateJwk),
  });
  return {
    createdAt,
    encrypted: JSON.stringify(encrypted),
    expiresAt,
    id,
    privateKey: pair.privateKey,
    publicJwk,
  };
}

export async function createContinuityCryptoFixtures(betterAuthSecret) {
  const now = new Date();
  const passkeyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const rawPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", passkeyPair.publicKey),
  );
  assert.equal(rawPublicKey[0], 0x04);
  const cosePublicKey = isoCBOR.encode(
    new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, rawPublicKey.slice(1, 33)],
      [-3, rawPublicKey.slice(33, 65)],
    ]),
  );
  const clientSecretSuffix = randomBase64Url();
  const credentialId = await sha256Base64Url("pgid-continuity-credential-v1");
  const keyA = await createSigningKey(
    "continuity-signing-key-a",
    betterAuthSecret,
    addDays(now, -31),
    addDays(now, -1),
  );
  const keyB = await createSigningKey(
    "continuity-signing-key-b",
    betterAuthSecret,
    now.toISOString(),
    addDays(now, 30),
  );
  return {
    betterAuthSecret,
    clientSecretHash: await sha256Base64Url(clientSecretSuffix),
    clientSecretSuffix,
    credentialId,
    expiredSessionToken: randomBase64Url(),
    keyA,
    keyB,
    liveSessionToken: randomBase64Url(),
    passkeyPrivateKey: passkeyPair.privateKey,
    passkeyPublicKey: Buffer.from(cosePublicKey).toString("base64"),
  };
}

export function renderContinuitySeed(templateFilename, outputFilename, fixture) {
  let sql = readFileSync(templateFilename, "utf8");
  const replacements = {
    CLIENT_SECRET_HASH: fixture.clientSecretHash,
    EXPIRED_SESSION_TOKEN: fixture.expiredSessionToken,
    JWK_A_CREATED_AT: fixture.keyA.createdAt,
    JWK_A_EXPIRES_AT: fixture.keyA.expiresAt,
    JWK_A_PRIVATE_ENCRYPTED: fixture.keyA.encrypted,
    JWK_A_PUBLIC: JSON.stringify(fixture.keyA.publicJwk),
    JWK_B_CREATED_AT: fixture.keyB.createdAt,
    JWK_B_EXPIRES_AT: fixture.keyB.expiresAt,
    JWK_B_PRIVATE_ENCRYPTED: fixture.keyB.encrypted,
    JWK_B_PUBLIC: JSON.stringify(fixture.keyB.publicJwk),
    LIVE_SESSION_TOKEN: fixture.liveSessionToken,
    PASSKEY_CREDENTIAL_ID: fixture.credentialId,
    PASSKEY_PUBLIC_KEY: fixture.passkeyPublicKey,
  };
  for (const [name, value] of Object.entries(replacements)) {
    const marker = `{{${name}}}`;
    assert.ok(sql.includes(marker), `seed template lacks ${marker}`);
    sql = sql.replaceAll(marker, sqlLiteral(value));
  }
  assert.ok(
    !/\{\{[A-Z0-9_]+}}/.test(sql),
    "seed template has an unresolved marker",
  );
  writeFileSync(outputFilename, sql, { encoding: "utf8", mode: 0o600 });
}

function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function derInteger(source) {
  let first = 0;
  while (first < source.length - 1 && source[first] === 0) first += 1;
  const value = source.slice(first);
  return value[0] & 0x80 ? concatBytes(Uint8Array.of(0), value) : value;
}

function rawEcdsaToDer(signature) {
  assert.equal(signature.length, 64, "P-256 signature must have two 32-byte limbs");
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  return concatBytes(
    Uint8Array.of(0x30, 2 + r.length + 2 + s.length, 0x02, r.length),
    r,
    Uint8Array.of(0x02, s.length),
    s,
  );
}

export async function createPasskeyAssertion(fixture, challenge, origin) {
  const clientData = encoder.encode(
    JSON.stringify({
      challenge,
      crossOrigin: false,
      origin,
      type: "webauthn.get",
    }),
  );
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode("127.0.0.1")),
  );
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(rpIdHash, 0);
  authenticatorData[32] = 0x05;
  new DataView(authenticatorData.buffer).setUint32(33, 1, false);
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientData),
  );
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      fixture.passkeyPrivateKey,
      concatBytes(authenticatorData, clientDataHash),
    ),
  );
  const credential = fixture.credentialId;
  return {
    clientExtensionResults: {},
    id: credential,
    rawId: credential,
    response: {
      authenticatorData: base64Url(authenticatorData),
      clientDataJSON: base64Url(clientData),
      signature: base64Url(rawEcdsaToDer(rawSignature)),
    },
    type: "public-key",
  };
}

export async function sessionCookie(token, betterAuthSecret) {
  const signature = await betterAuthCrypto.makeSignature(token, betterAuthSecret);
  const value = `${token}.${signature}`;
  return `pg72_id.session_token=${value}; __Secure-pg72_id.session_token=${value}`;
}

export async function decryptSigningKey(record, betterAuthSecret) {
  const decrypted = await betterAuthCrypto.symmetricDecrypt({
    key: betterAuthSecret,
    data: JSON.parse(record.privateKey),
  });
  const jwk = JSON.parse(decrypted);
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

export async function signCompactJwt(privateKey, kid, payload) {
  const header = base64Url(encoder.encode(JSON.stringify({ alg: "EdDSA", kid, typ: "JWT" })));
  const body = base64Url(encoder.encode(JSON.stringify(payload)));
  const signingInput = `${header}.${body}`;
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64Url(signature)}`;
}

export async function verifyCompactJwtAgainstJwks(token, keys, expected) {
  const segments = token.split(".");
  if (segments.length !== 3) return false;
  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  try {
    const header = JSON.parse(decoder.decode(fromBase64Url(encodedHeader)));
    const payload = JSON.parse(decoder.decode(fromBase64Url(encodedPayload)));
    const publicJwk = keys.find(({ kid }) => kid === header.kid);
    if (!publicJwk || header.alg !== "EdDSA") return false;
    for (const [name, value] of Object.entries(expected)) {
      if (payload[name] !== value) return false;
    }
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      fromBase64Url(encodedSignature),
      encoder.encode(`${encodedHeader}.${encodedPayload}`),
    );
  } catch {
    return false;
  }
}
