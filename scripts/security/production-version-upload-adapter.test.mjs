import assert from "node:assert/strict";
import test from "node:test";

import {
  PRODUCTION_SNAPSHOT_ENDPOINTS,
  normalizeCloudflareProductionSnapshot,
} from "./production-version-upload-adapter.mjs";
import {
  canonicalJson,
  PRODUCTION_WORKER_NAME,
  ProductionUploadGateError,
  sha256,
} from "./production-version-upload-gate.mjs";

const ACCOUNT_ID = "a".repeat(32);
const SERVICE_TAG = "service-tag-fixture";
const CORRELATION = "b".repeat(64);
const TOKEN_BINDING = "d".repeat(64);
const ACTIVE_VERSION = "11111111-1111-4111-8111-111111111111";
const OLDER_VERSION = "22222222-2222-4222-8222-222222222222";
const DEPLOYMENT = "33333333-3333-4333-8333-333333333333";
const OBSERVED_AT = "2026-07-19T00:00:00.000Z";

function versionDetail(id) {
  return {
    annotations: { "workers/message": "existing", "workers/tag": "existing" },
    id,
    metadata: { hasPreview: false },
    resources: {
      bindings: [],
      script_runtime: {
        compatibility_date: "2026-07-18",
        compatibility_flags: ["nodejs_compat"],
      },
    },
    scriptEtag: "etag-fixture",
  };
}

function endpointResults() {
  return new Map([
    ["identity", { name: PRODUCTION_WORKER_NAME, tag: SERVICE_TAG }],
    [
      "deployments",
      [{ id: DEPLOYMENT, versions: [{ percentage: 100, version_id: ACTIVE_VERSION }] }],
    ],
    [
      "versions",
      [
        { id: ACTIVE_VERSION, number: 12 },
        { id: OLDER_VERSION, number: 11 },
      ],
    ],
    ["active-version", versionDetail(ACTIVE_VERSION)],
    ["latest-version", versionDetail(ACTIVE_VERSION)],
    ["subdomain", { enabled: false, previews_enabled: false }],
    [
      "routes",
      [
        { id: "55555555-5555-4555-8555-555555555555", pattern: "z.pg72.tw/*", script: PRODUCTION_WORKER_NAME },
        { id: "44444444-4444-4444-8444-444444444444", pattern: "sso.pg72.tw/*", script: PRODUCTION_WORKER_NAME },
      ],
    ],
    [
      "custom-domains",
      [
        { environment: "production", hostname: "z.pg72.tw", id: "e".repeat(32), service: PRODUCTION_WORKER_NAME, zone_id: "f".repeat(32) },
        { environment: "production", hostname: "sso.pg72.tw", id: "d".repeat(32), service: PRODUCTION_WORKER_NAME, zone_id: "f".repeat(32) },
      ],
    ],
    [
      "schedules",
      [
        { created_on: OBSERVED_AT, cron: "5 * * * *", modified_on: OBSERVED_AT },
        { created_on: OBSERVED_AT, cron: "* * * * *", modified_on: OBSERVED_AT },
      ],
    ],
    [
      "queue-consumers",
      [{
        consumer_id: "1".repeat(32),
        queue_name: "logout",
        script_name: PRODUCTION_WORKER_NAME,
        settings: {
          batch_size: 10,
          batch_timeout: 5,
          dead_letter_queue: "logout-dlq",
          max_retries: 5,
        },
      }],
    ],
    [
      "queue-triggers",
      [{ environment: "production", queue_name: "logout", script_name: PRODUCTION_WORKER_NAME }],
    ],
    [
      "script-settings",
      {
        logpush: false,
        observability: { enabled: true, headSamplingRate: null },
        tags: ["production"],
        tail_consumers: [],
      },
    ],
  ]);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function pairingDigest(results = endpointResults()) {
  const ordered = (endpoint, identity) =>
    structuredClone(results.get(endpoint)).sort((left, right) =>
      compareText(identity(left), identity(right)),
    );
  const customDomains = ordered("custom-domains", ({ hostname }) => hostname).map(
    ({ environment, hostname, id, service, zone_id }) => ({
      environment,
      hostname,
      id,
      service,
      zoneId: zone_id,
    }),
  );
  const queueConsumers = ordered("queue-consumers", ({ queue_name }) => queue_name).map(
    ({ consumer_id, queue_name, script_name, settings }) => ({
      consumerId: consumer_id,
      deadLetterQueue: settings.dead_letter_queue,
      maxBatchSize: settings.batch_size,
      maxBatchTimeout: settings.batch_timeout,
      maxRetries: settings.max_retries,
      queueName: queue_name,
      scriptName: script_name,
    }),
  );
  const queueTriggers = ordered("queue-triggers", ({ queue_name }) => queue_name).map(
    ({ environment, queue_name, script_name }) => ({
      environment,
      queueName: queue_name,
      scriptName: script_name,
    }),
  );
  const schedules = ordered("schedules", ({ cron }) => cron).map(
    ({ created_on, cron, modified_on }) => ({
      createdOn: created_on,
      cron,
      modifiedOn: modified_on,
    }),
  );
  return sha256(
    Buffer.from(
      canonicalJson({
        customDomains,
        queueConsumers,
        queueTriggers,
        routes: ordered("routes", ({ pattern }) => pattern),
        schedules,
      }),
    ),
  );
}

function responseEnvelopes(contract, result) {
  if (!contract.list) {
    return [{ errors: [], messages: [], result, success: true }];
  }
  const perPage = contract.endpoint === "routes" ? 1 : 50;
  const pages = [];
  for (let offset = 0; offset < Math.max(1, result.length); offset += perPage) {
    pages.push(result.slice(offset, offset + perPage));
  }
  return pages.map((pageResult, index) => ({
    errors: [],
    messages: [],
    result: pageResult,
    result_info: {
      count: pageResult.length,
      page: index + 1,
      per_page: perPage,
      total_count: result.length,
      total_pages: pages.length,
    },
    success: true,
  }));
}

function expectation(phase = "preflight") {
  return {
    accountId: ACCOUNT_ID,
    correlationSha256: CORRELATION,
    observationNotAfter: OBSERVED_AT,
    observationNotBefore: OBSERVED_AT,
    pairingSha256: pairingDigest(),
    phase,
    schemaVersion: 1,
    serviceTag: SERVICE_TAG,
    tokenBindingSha256: TOKEN_BINDING,
    workerName: PRODUCTION_WORKER_NAME,
  };
}

function bundle(phase = "preflight") {
  const results = endpointResults();
  const pairingSha256 = pairingDigest(results);
  return {
    correlationSha256: CORRELATION,
    observations: PRODUCTION_SNAPSHOT_ENDPOINTS.map((contract) => {
      const result = results.get(contract.endpoint);
      return {
        accountId: ACCOUNT_ID,
        correlationSha256: CORRELATION,
        endpoint: contract.endpoint,
        observedAt: OBSERVED_AT,
        responses: responseEnvelopes(contract, result),
        pairingSha256: [
          "routes",
          "custom-domains",
          "schedules",
          "queue-consumers",
          "queue-triggers",
        ].includes(contract.endpoint)
          ? pairingSha256
          : null,
        permissionClass: contract.permissionClass,
        tokenBindingSha256: TOKEN_BINDING,
        workerName: PRODUCTION_WORKER_NAME,
      };
    }),
    pairingSha256,
    phase,
    schemaVersion: 1,
    tokenBindingSha256: TOKEN_BINDING,
  };
}

function bytes(value) {
  return Buffer.from(JSON.stringify(value));
}

function expectCode(action, code) {
  assert.throws(
    action,
    (error) => error instanceof ProductionUploadGateError && error.code === code,
  );
}

test("normalizes one complete bounded response bundle without elevating provenance", () => {
  const snapshot = normalizeCloudflareProductionSnapshot(
    bytes(bundle()),
    bytes(expectation()),
  );
  assert.equal(snapshot.schemaVersion, 2);
  assert.equal(snapshot.accountId, ACCOUNT_ID);
  assert.deepEqual(
    snapshot.routes.map(({ pattern }) => pattern),
    ["sso.pg72.tw/*", "z.pg72.tw/*"],
  );
  assert.deepEqual(
    snapshot.customDomains.map(({ hostname }) => hostname),
    ["sso.pg72.tw", "z.pg72.tw"],
  );
  assert.equal(snapshot.observation.paginationStructureClosed, true);
  assert.equal(snapshot.observation.apiProvenanceVerified, false);
  assert.equal(snapshot.observation.atomicSnapshotVerified, false);
  assert.equal(snapshot.observation.permissionScopeVerified, false);
  assert.equal(snapshot.observation.singleWriterVerified, false);
});

test("rejects non-byte, malformed, duplicate-key, partial, unknown, and oversized JSON", () => {
  expectCode(
    () => normalizeCloudflareProductionSnapshot(bundle(), bytes(expectation())),
    "BOUNDED_JSON_BYTES_REQUIRED",
  );
  expectCode(
    () => normalizeCloudflareProductionSnapshot(Buffer.from("{"), bytes(expectation())),
    "BOUNDED_JSON_SYNTAX",
  );
  expectCode(
    () =>
      normalizeCloudflareProductionSnapshot(
        Buffer.from('{"schemaVersion":1,"schemaVersion":1}'),
        bytes(expectation()),
      ),
    "BOUNDED_JSON_DUPLICATE_KEY",
  );
  const partial = bundle();
  partial.observations.pop();
  expectCode(
    () => normalizeCloudflareProductionSnapshot(bytes(partial), bytes(expectation())),
    "ADAPTER_BUNDLE_SCHEMA",
  );
  const unknown = bundle();
  unknown.unreviewed = true;
  expectCode(
    () => normalizeCloudflareProductionSnapshot(bytes(unknown), bytes(expectation())),
    "ADAPTER_BUNDLE_SCHEMA",
  );
  expectCode(
    () =>
      normalizeCloudflareProductionSnapshot(
        Buffer.alloc(512 * 1024 + 1, 0x20),
        bytes(expectation()),
      ),
    "BOUNDED_JSON_SIZE",
  );
});

test("canonicalizes unordered sets but rejects duplicates and semantic version reordering", () => {
  const reordered = bundle();
  const routeObservation = reordered.observations.find(({ endpoint }) => endpoint === "routes");
  assert.equal(routeObservation.responses[0].result[0].pattern, "z.pg72.tw/*");
  const snapshot = normalizeCloudflareProductionSnapshot(
    bytes(reordered),
    bytes(expectation()),
  );
  assert.equal(snapshot.routes[0].pattern, "sso.pg72.tw/*");

  const duplicate = bundle();
  const duplicateRoutes = duplicate.observations.find(({ endpoint }) => endpoint === "routes");
  for (const response of duplicateRoutes.responses) {
    response.result_info.total_count += 1;
    response.result_info.total_pages += 1;
  }
  duplicateRoutes.responses.push({
    errors: [],
    messages: [],
    result: [structuredClone(duplicateRoutes.responses[0].result[0])],
    result_info: {
      count: 1,
      page: 3,
      per_page: 1,
      total_count: 3,
      total_pages: 3,
    },
    success: true,
  });
  expectCode(
    () => normalizeCloudflareProductionSnapshot(bytes(duplicate), bytes(expectation())),
    "ADAPTER_ROUTE_DUPLICATE",
  );

  const versionOrder = bundle();
  const versions = versionOrder.observations.find(({ endpoint }) => endpoint === "versions");
  versions.responses[0].result.reverse();
  expectCode(
    () => normalizeCloudflareProductionSnapshot(bytes(versionOrder), bytes(expectation())),
    "REMOTE_VERSION_ORDER_REVIEW_REQUIRED",
  );
});

test("rejects foreign targets, reordered endpoints, incomplete pages, and unpaired controls", () => {
  const cases = [
    [
      "ADAPTER_OBSERVATION_IDENTITY",
      (value) => {
        value.observations.find(({ endpoint }) => endpoint === "routes").accountId = "9".repeat(32);
      },
    ],
    [
      "ADAPTER_OBSERVATION_IDENTITY",
      (value) => {
        value.observations.find(({ endpoint }) => endpoint === "custom-domains").pairingSha256 = null;
      },
    ],
    [
      "ADAPTER_PAGINATION_INCOMPLETE",
      (value) => {
        value.observations.find(({ endpoint }) => endpoint === "schedules")
          .responses[0].result_info.total_count += 1;
      },
    ],
    [
      "ADAPTER_OBSERVATION_IDENTITY",
      (value) => {
        const left = value.observations.findIndex(({ endpoint }) => endpoint === "routes");
        const right = value.observations.findIndex(({ endpoint }) => endpoint === "custom-domains");
        [value.observations[left], value.observations[right]] = [
          value.observations[right],
          value.observations[left],
        ];
      },
    ],
    [
      "ADAPTER_SERVICE_IDENTITY",
      (value) => {
        value.observations.find(({ endpoint }) => endpoint === "identity")
          .responses[0].result.name = "foreign-worker";
      },
    ],
    [
      "ADAPTER_QUEUE_PAIR_MISMATCH",
      (value) => {
        value.observations.find(({ endpoint }) => endpoint === "queue-triggers")
          .responses[0].result[0].queue_name = "foreign-queue";
      },
    ],
  ];
  for (const [code, mutate] of cases) {
    const changed = bundle();
    mutate(changed);
    expectCode(
      () => normalizeCloudflareProductionSnapshot(bytes(changed), bytes(expectation())),
      code,
    );
  }
});
