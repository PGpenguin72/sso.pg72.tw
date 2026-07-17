import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "jsonc-parser";

import {
  expectedGeneratedSsoConfig,
  expectedSourceConfig,
  releasePolicy,
  validateEnvironmentSource,
  validateGeneratedSsoConfig,
  validateSsoConfig,
  validateTestRpConfig,
} from "./wrangler-config.mjs";

const sso = parse(
  readFileSync(new URL("../../apps/sso/wrangler.jsonc", import.meta.url), "utf8"),
);
const rp = parse(
  readFileSync(new URL("../../apps/test-rp/wrangler.jsonc", import.meta.url), "utf8"),
);
const now = new Date("2026-07-17T00:00:00.000Z");

test("accepts the exact typed production and local test-RP source contracts", () => {
  assert.deepEqual(validateSsoConfig(sso, now), []);
  assert.deepEqual(validateTestRpConfig(rp, now), []);
});

test("rejects every production binding resource and tuning mutation", () => {
  const mutations = [
    ["route", (value) => (value.routes[0].pattern = "login.pg72.tw")],
    ["cron", (value) => (value.triggers.crons[0] = "0 0 * * *")],
    ["assets", (value) => (value.assets.binding = "PUBLIC")],
    ["D1 name", (value) => (value.d1_databases[0].database_name = "other-db")],
    ["D1 id", (value) => (value.d1_databases[0].database_id = "11111111-1111-1111-1111-111111111111")],
    ["Queue producer", (value) => (value.queues.producers[0].queue = "other-events")],
    ["Queue consumer", (value) => (value.queues.consumers[0].queue = "other-events")],
    ["Queue DLQ", (value) => (value.queues.consumers[0].dead_letter_queue = "other-dlq")],
    ["Queue batch", (value) => (value.queues.consumers[0].max_batch_size = 11)],
    ["Queue timeout", (value) => (value.queues.consumers[0].max_batch_timeout = 6)],
    ["Queue retries", (value) => (value.queues.consumers[0].max_retries = 6)],
    ["logout Queue producer", (value) => (value.queues.producers[1].queue = "other-logout")],
    ["logout Queue consumer", (value) => (value.queues.consumers[1].queue = "other-logout")],
    ["logout Queue DLQ", (value) => (value.queues.consumers[1].dead_letter_queue = "other-logout-dlq")],
    ["Rate Limit namespace", (value) => (value.ratelimits[0].namespace_id = "9999")],
    ["Rate Limit limit", (value) => (value.ratelimits[0].simple.limit = 31)],
    ["Rate Limit period", (value) => (value.ratelimits[0].simple.period = 10)],
    ["Recovery Rate Limit", (value) => (value.ratelimits[5].simple.limit = 11)],
    ["Recovery mode", (value) => (value.vars.RECOVERY_MODE = "enabled")],
    ["secret names", (value) => value.secrets.required.push("UNREVIEWED_SECRET")],
    ["remote binding", (value) => (value.d1_databases[0].remote = true)],
  ];
  for (const [name, mutate] of mutations) {
    const changed = structuredClone(sso);
    mutate(changed);
    assert.notDeepEqual(validateSsoConfig(changed, now), [], `${name} mutation was accepted`);
  }
});

test("placeholder validation cannot be bypassed by changing source and policy together", () => {
  const environment = structuredClone(releasePolicy.environments.production);
  environment.worker.d1[0].target.databaseId.value = "11111111-1111-1111-1111-111111111111";
  const changed = expectedSourceConfig(environment);
  const errors = validateEnvironmentSource(changed, environment, now);
  assert.ok(errors.some((error) => error.includes("non-working UUID placeholder")));
});

test("accepts only the exact normalized generated production contract", () => {
  const root = "/reviewed/repository";
  const generated = expectedGeneratedSsoConfig(root);
  assert.deepEqual(validateGeneratedSsoConfig(generated, root), []);

  for (const [name, mutate] of [
    ["source config path", (value) => (value.configPath = "/tmp/other/wrangler.jsonc")],
    ["asset directory", (value) => (value.assets.directory = "../../unreviewed")],
    ["generated D1 target", (value) => (value.d1_databases[0].database_name = "other-db")],
    ["generated Queue target", (value) => (value.queues.producers[0].queue = "other-events")],
    ["generated cron", (value) => (value.triggers.crons[0] = "0 0 * * *")],
    ["generated logout Queue", (value) => (value.queues.producers[1].queue = "other-logout")],
    ["generated DLQ", (value) => (value.queues.consumers[0].dead_letter_queue = "other-dlq")],
    ["generated Rate Limit", (value) => (value.ratelimits[0].simple.limit = 999)],
    ["generated Recovery mode", (value) => (value.vars.RECOVERY_MODE = "enabled")],
    ["unexpected R2 binding", (value) => value.r2_buckets.push({ binding: "LEAK", bucket_name: "prod" })],
  ]) {
    const changed = structuredClone(generated);
    mutate(changed);
    assert.notDeepEqual(
      validateGeneratedSsoConfig(changed, root),
      [],
      `${name} mutation was accepted`,
    );
  }
});

test("rejects any remotely addressable or otherwise drifted test RP", () => {
  for (const mutate of [
    (value) => (value.routes = [{ pattern: "test.example.com", custom_domain: true }]),
    (value) => (value.vars.RP_BASE_URL = "https://test.example.com"),
    (value) => (value.d1_databases[0].database_name = "production-db"),
    (value) => (value.d1_databases[0].remote = true),
  ]) {
    const changed = structuredClone(rp);
    mutate(changed);
    assert.notDeepEqual(validateTestRpConfig(changed, now), []);
  }
});
