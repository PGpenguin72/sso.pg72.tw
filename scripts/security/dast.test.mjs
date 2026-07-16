import assert from "node:assert/strict";
import test from "node:test";

import { authorizeDastTarget } from "./dast.mjs";

test("defaults to loopback and allows only loopback HTTP locally", () => {
  assert.deepEqual(authorizeDastTarget(undefined, {}), {
    mode: "local",
    origin: "http://127.0.0.1:5173",
  });
  assert.deepEqual(authorizeDastTarget("http://localhost:8787", {}), {
    mode: "local",
    origin: "http://localhost:8787",
  });
  assert.throws(() => authorizeDastTarget("https://localhost:8787", {}), /loopback HTTP/);
});

test("hard-rejects production and arbitrary custom targets", () => {
  const environment = {
    DAST_ALLOWED_PREVIEW_ORIGIN: "https://sso.pg72.tw",
    DAST_PREVIEW_OPT_IN: "owner-approved-isolated-preview",
  };
  assert.throws(() => authorizeDastTarget("https://sso.pg72.tw", environment), /never a DAST target/);
  assert.throws(() => authorizeDastTarget("https://preview.example.com", environment), /isolated Preview Worker/);
});

test("requires exact protected allowlist and owner opt-in for isolated Preview", () => {
  const origin = "https://pg72-id-preview.synthetic-preview.workers.dev";
  assert.throws(() => authorizeDastTarget(origin, {}), /allowlist value/);
  assert.throws(
    () => authorizeDastTarget(origin, { DAST_ALLOWED_PREVIEW_ORIGIN: origin }),
    /owner Preview opt-in/,
  );
  assert.deepEqual(
    authorizeDastTarget(origin, {
      DAST_ALLOWED_PREVIEW_ORIGIN: origin,
      DAST_PREVIEW_OPT_IN: "owner-approved-isolated-preview",
    }),
    { mode: "preview", origin },
  );
});

test("rejects URL paths, credentials, and lookalike Preview names", () => {
  assert.throws(() => authorizeDastTarget("http://localhost:5173/path", {}), /exact origin/);
  assert.throws(() => authorizeDastTarget("http://user:pass@localhost:5173", {}), /exact origin|credentials/);
  assert.throws(
    () =>
      authorizeDastTarget("https://pg72-id.other.workers.dev", {
        DAST_ALLOWED_PREVIEW_ORIGIN: "https://pg72-id.other.workers.dev",
        DAST_PREVIEW_OPT_IN: "owner-approved-isolated-preview",
      }),
    /isolated Preview Worker/,
  );
});
