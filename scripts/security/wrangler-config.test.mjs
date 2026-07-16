import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "jsonc-parser";

import { validateSsoConfig, validateTestRpConfig } from "./wrangler-config.mjs";

const sso = parse(
  readFileSync(new URL("../../apps/sso/wrangler.jsonc", import.meta.url), "utf8"),
);
const rp = parse(
  readFileSync(new URL("../../apps/test-rp/wrangler.jsonc", import.meta.url), "utf8"),
);
const now = new Date("2026-07-17T00:00:00.000Z");

test("accepts the exact production and localhost configs", () => {
  assert.deepEqual(validateSsoConfig(sso, now), []);
  assert.deepEqual(validateTestRpConfig(rp, now), []);
});

test("rejects production binding and registration drift", () => {
  const changed = structuredClone(sso);
  changed.vars.REGISTRATION_MODE = "public";
  changed.d1_databases[0].remote = true;
  const errors = validateSsoConfig(changed, now);
  assert.ok(errors.some((error) => error.includes("vars drifted")));
  assert.ok(errors.some((error) => error.includes("remote binding")));
});

test("rejects a remotely addressable test RP", () => {
  const changed = structuredClone(rp);
  changed.routes = [{ pattern: "test.example.com", custom_domain: true }];
  changed.vars.RP_BASE_URL = "https://test.example.com";
  const errors = validateTestRpConfig(changed, now);
  assert.ok(errors.some((error) => error.includes("remote route")));
  assert.ok(errors.some((error) => error.includes("localhost HTTP")));
});
