import { isDeepStrictEqual } from "node:util";

import {
  PRODUCTION_WORKER_NAME,
  ProductionUploadGateError,
  canonicalJson,
  sha256,
  validateNormalizedSnapshot,
} from "./production-version-upload-gate.mjs";

const ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const MAX_INPUT_BYTES = 512 * 1024;
const MAX_JSON_DEPTH = 24;
const MAX_JSON_ITEMS = 16_384;
const MAX_JSON_STRING_BYTES = 16 * 1024;

export const PRODUCTION_SNAPSHOT_ENDPOINTS = Object.freeze([
  Object.freeze({ endpoint: "identity", list: false, permissionClass: "worker-script-read" }),
  Object.freeze({ endpoint: "deployments", list: true, permissionClass: "worker-deployments-read" }),
  Object.freeze({ endpoint: "versions", list: true, permissionClass: "worker-versions-read" }),
  Object.freeze({ endpoint: "active-version", list: false, permissionClass: "worker-versions-read" }),
  Object.freeze({ endpoint: "latest-version", list: false, permissionClass: "worker-versions-read" }),
  Object.freeze({ endpoint: "subdomain", list: false, permissionClass: "worker-subdomain-read" }),
  Object.freeze({ endpoint: "routes", list: true, permissionClass: "worker-routes-read" }),
  Object.freeze({ endpoint: "custom-domains", list: true, permissionClass: "worker-domains-read" }),
  Object.freeze({ endpoint: "schedules", list: true, permissionClass: "worker-schedules-read" }),
  Object.freeze({ endpoint: "queue-consumers", list: true, permissionClass: "queues-read" }),
  Object.freeze({ endpoint: "queue-triggers", list: true, permissionClass: "queues-read" }),
  Object.freeze({ endpoint: "script-settings", list: false, permissionClass: "worker-settings-read" }),
]);

const CONTROL_PLANE_ENDPOINTS = new Set([
  "routes",
  "custom-domains",
  "schedules",
  "queue-consumers",
  "queue-triggers",
]);
const ENDPOINT_SET_SHA256 = sha256(
  Buffer.from(canonicalJson(PRODUCTION_SNAPSHOT_ENDPOINTS)),
);

function fail(code) {
  throw new ProductionUploadGateError(code);
}

function requireCondition(condition, code) {
  if (!condition) fail(code);
}

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())
  );
}

function scanBoundedJson(text) {
  let index = 0;
  let items = 0;

  function failSyntax() {
    fail("BOUNDED_JSON_SYNTAX");
  }

  function skipWhitespace() {
    while (/\s/.test(text[index] ?? "")) index += 1;
  }

  function countItem() {
    items += 1;
    requireCondition(items <= MAX_JSON_ITEMS, "BOUNDED_JSON_ITEMS");
  }

  function parseString() {
    requireCondition(text[index] === '"', "BOUNDED_JSON_SYNTAX");
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        let value;
        try {
          value = JSON.parse(text.slice(start, index));
        } catch {
          failSyntax();
        }
        requireCondition(
          Buffer.byteLength(value, "utf8") <= MAX_JSON_STRING_BYTES,
          "BOUNDED_JSON_STRING",
        );
        return value;
      }
      if (character === "\\") {
        index += 1;
        if (text[index] === "u") {
          requireCondition(/^[0-9a-fA-F]{4}$/.test(text.slice(index + 1, index + 5)), "BOUNDED_JSON_SYNTAX");
          index += 5;
        } else {
          requireCondition(/["\\/bfnrt]/.test(text[index] ?? ""), "BOUNDED_JSON_SYNTAX");
          index += 1;
        }
        continue;
      }
      requireCondition(character >= " " && character !== undefined, "BOUNDED_JSON_SYNTAX");
      index += 1;
    }
    failSyntax();
  }

  function parsePrimitive() {
    const remainder = text.slice(index);
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(remainder);
    requireCondition(match, "BOUNDED_JSON_SYNTAX");
    index += match[0].length;
  }

  function parseValue(depth) {
    requireCondition(depth <= MAX_JSON_DEPTH, "BOUNDED_JSON_DEPTH");
    skipWhitespace();
    countItem();
    if (text[index] === "{") return parseObject(depth + 1);
    if (text[index] === "[") return parseArray(depth + 1);
    if (text[index] === '"') return parseString();
    return parsePrimitive();
  }

  function parseObject(depth) {
    index += 1;
    skipWhitespace();
    const keys = new Set();
    if (text[index] === "}") {
      index += 1;
      return;
    }
    while (index < text.length) {
      skipWhitespace();
      const key = parseString();
      requireCondition(!keys.has(key), "BOUNDED_JSON_DUPLICATE_KEY");
      keys.add(key);
      skipWhitespace();
      requireCondition(text[index] === ":", "BOUNDED_JSON_SYNTAX");
      index += 1;
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      requireCondition(text[index] === ",", "BOUNDED_JSON_SYNTAX");
      index += 1;
    }
    failSyntax();
  }

  function parseArray(depth) {
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return;
    }
    while (index < text.length) {
      parseValue(depth);
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      requireCondition(text[index] === ",", "BOUNDED_JSON_SYNTAX");
      index += 1;
    }
    failSyntax();
  }

  skipWhitespace();
  parseValue(0);
  skipWhitespace();
  requireCondition(index === text.length, "BOUNDED_JSON_SYNTAX");
}

export function parseBoundedProductionJson(bytes) {
  requireCondition(Buffer.isBuffer(bytes), "BOUNDED_JSON_BYTES_REQUIRED");
  requireCondition(
    bytes.length > 0 && bytes.length <= MAX_INPUT_BYTES,
    "BOUNDED_JSON_SIZE",
  );
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("BOUNDED_JSON_UTF8");
  }
  scanBoundedJson(text);
  try {
    return JSON.parse(text);
  } catch {
    fail("BOUNDED_JSON_SYNTAX");
  }
}

function canonicalTimestamp(value) {
  requireCondition(typeof value === "string", "ADAPTER_OBSERVATION_TIME");
  const timestamp = Date.parse(value);
  requireCondition(
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value,
    "ADAPTER_OBSERVATION_TIME",
  );
  return timestamp;
}

function compareExactText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalizeUnique(values, identity, code, additionalIdentities = []) {
  requireCondition(Array.isArray(values), code);
  const copy = structuredClone(values);
  const identityFunctions = [identity, ...additionalIdentities];
  const identitySets = identityFunctions.map(() => new Set());
  for (const entry of copy) {
    for (let index = 0; index < identitySets.length; index += 1) {
      const key = identityFunctions[index](entry);
      requireCondition(
        typeof key === "string" && key.length > 0 && !identitySets[index].has(key),
        code,
      );
      identitySets[index].add(key);
    }
  }
  return copy.sort((left, right) =>
    compareExactText(identity(left), identity(right)),
  );
}

function canonicalizeVersionDetail(value) {
  const detail = structuredClone(value);
  if (Array.isArray(detail?.resources?.bindings)) {
    detail.resources.bindings = canonicalizeUnique(
      detail.resources.bindings,
      (binding) => `${binding?.type ?? ""}\0${binding?.name ?? ""}`,
      "ADAPTER_BINDING_DUPLICATE",
      [(binding) => binding?.name ?? ""],
    );
  }
  if (Array.isArray(detail?.resources?.script_runtime?.compatibility_flags)) {
    detail.resources.script_runtime.compatibility_flags = canonicalizeUnique(
      detail.resources.script_runtime.compatibility_flags,
      (flag) => (typeof flag === "string" ? flag : ""),
      "ADAPTER_COMPATIBILITY_FLAG_DUPLICATE",
    );
  }
  return detail;
}

function normalizeObservationResponses(observation, contract) {
  requireCondition(
    Array.isArray(observation.responses) && observation.responses.length > 0,
    "ADAPTER_RESPONSE_ENVELOPE",
  );
  if (!contract.list) {
    const response = observation.responses[0];
    requireCondition(
      observation.responses.length === 1 &&
        exactKeys(response, ["errors", "messages", "result", "success"]) &&
        response.success === true &&
        Array.isArray(response.errors) &&
        response.errors.length === 0 &&
        Array.isArray(response.messages) &&
        response.messages.length === 0,
      "ADAPTER_RESPONSE_ENVELOPE",
    );
    return response.result;
  }

  const combined = [];
  let expectedTotalCount = null;
  let expectedTotalPages = null;
  let expectedPerPage = null;
  for (let index = 0; index < observation.responses.length; index += 1) {
    const response = observation.responses[index];
    const info = response?.result_info;
    requireCondition(
      exactKeys(response, [
        "errors",
        "messages",
        "result",
        "result_info",
        "success",
      ]) &&
        response.success === true &&
        Array.isArray(response.errors) &&
        response.errors.length === 0 &&
        Array.isArray(response.messages) &&
        response.messages.length === 0 &&
        Array.isArray(response.result) &&
        exactKeys(info, [
          "count",
          "page",
          "per_page",
          "total_count",
          "total_pages",
        ]) &&
        Number.isSafeInteger(info.count) &&
        info.count === response.result.length &&
        Number.isSafeInteger(info.page) &&
        info.page === index + 1 &&
        Number.isSafeInteger(info.per_page) &&
        info.per_page > 0 &&
        response.result.length <= info.per_page &&
        Number.isSafeInteger(info.total_count) &&
        info.total_count >= 0 &&
        Number.isSafeInteger(info.total_pages) &&
        info.total_pages === observation.responses.length,
      "ADAPTER_PAGINATION_INCOMPLETE",
    );
    const standardTotalPages = Math.max(
      1,
      Math.ceil(info.total_count / info.per_page),
    );
    const finalPageCount =
      info.total_count === 0
        ? 0
        : ((info.total_count - 1) % info.per_page) + 1;
    const standardPageCount =
      info.page < standardTotalPages ? info.per_page : finalPageCount;
    requireCondition(
      info.total_pages === standardTotalPages &&
        response.result.length === standardPageCount,
      "ADAPTER_PAGINATION_INCOMPLETE",
    );
    expectedTotalCount ??= info.total_count;
    expectedTotalPages ??= info.total_pages;
    expectedPerPage ??= info.per_page;
    requireCondition(
      info.total_count === expectedTotalCount &&
        info.total_pages === expectedTotalPages &&
        info.per_page === expectedPerPage,
      "ADAPTER_PAGINATION_INCOMPLETE",
    );
    combined.push(...response.result);
  }
  requireCondition(
    combined.length === expectedTotalCount,
    "ADAPTER_PAGINATION_INCOMPLETE",
  );
  return combined;
}

function normalizeResult(endpoint, result) {
  if (endpoint === "identity") return structuredClone(result);
  if (endpoint === "active-version" || endpoint === "latest-version") {
    return canonicalizeVersionDetail(result);
  }
  if (endpoint === "routes") {
    requireCondition(
      Array.isArray(result) &&
        result.every((route) => exactKeys(route, ["id", "pattern", "script"])),
      "ADAPTER_ROUTE_SCHEMA",
    );
    return canonicalizeUnique(
      result,
      (route) => route?.pattern ?? "",
      "ADAPTER_ROUTE_DUPLICATE",
      [(route) => route?.id ?? ""],
    );
  }
  if (endpoint === "custom-domains") {
    requireCondition(
      Array.isArray(result) &&
        result.every((domain) =>
          exactKeys(domain, [
            "environment",
            "hostname",
            "id",
            "service",
            "zone_id",
          ]),
        ),
      "ADAPTER_CUSTOM_DOMAIN_SCHEMA",
    );
    const normalized = result.map(({ environment, hostname, id, service, zone_id }) => ({
      environment,
      hostname,
      id,
      service,
      zoneId: zone_id,
    }));
    return canonicalizeUnique(
      normalized,
      (domain) => domain?.hostname ?? "",
      "ADAPTER_CUSTOM_DOMAIN_DUPLICATE",
      [(domain) => domain?.id ?? ""],
    );
  }
  if (endpoint === "schedules") {
    requireCondition(
      Array.isArray(result) &&
        result.every((schedule) =>
          exactKeys(schedule, ["created_on", "cron", "modified_on"]),
        ),
      "ADAPTER_SCHEDULE_SCHEMA",
    );
    const normalized = result.map(({ created_on, cron, modified_on }) => ({
      createdOn: created_on,
      cron,
      modifiedOn: modified_on,
    }));
    return canonicalizeUnique(
      normalized,
      (schedule) => schedule?.cron ?? "",
      "ADAPTER_SCHEDULE_DUPLICATE",
    );
  }
  if (endpoint === "queue-consumers") {
    requireCondition(
      Array.isArray(result) &&
        result.every(
          (consumer) =>
            exactKeys(consumer, [
              "consumer_id",
              "queue_name",
              "script_name",
              "settings",
            ]) &&
            exactKeys(consumer.settings, [
              "batch_size",
              "batch_timeout",
              "dead_letter_queue",
              "max_retries",
            ]),
        ),
      "ADAPTER_QUEUE_CONSUMER_SCHEMA",
    );
    const normalized = result.map(
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
    return canonicalizeUnique(
      normalized,
      (consumer) => consumer?.queueName ?? "",
      "ADAPTER_QUEUE_CONSUMER_DUPLICATE",
      [(consumer) => consumer?.consumerId ?? ""],
    );
  }
  if (endpoint === "queue-triggers") {
    requireCondition(
      Array.isArray(result) &&
        result.every((trigger) =>
          exactKeys(trigger, ["environment", "queue_name", "script_name"]),
        ),
      "ADAPTER_QUEUE_TRIGGER_SCHEMA",
    );
    const normalized = result.map(({ environment, queue_name, script_name }) => ({
      environment,
      queueName: queue_name,
      scriptName: script_name,
    }));
    return canonicalizeUnique(
      normalized,
      (trigger) => trigger?.queueName ?? "",
      "ADAPTER_QUEUE_TRIGGER_DUPLICATE",
    );
  }
  if (endpoint === "script-settings") {
    const settings = structuredClone(result);
    if (Array.isArray(settings?.tags)) {
      settings.tags = canonicalizeUnique(settings.tags, (tag) => tag, "ADAPTER_TAG_DUPLICATE");
    }
    if (Array.isArray(settings?.tail_consumers)) {
      settings.tail_consumers = canonicalizeUnique(
        settings.tail_consumers,
        (consumer) => `${consumer?.service ?? ""}\0${consumer?.environment ?? ""}`,
        "ADAPTER_TAIL_CONSUMER_DUPLICATE",
      );
    }
    return settings;
  }
  return structuredClone(result);
}

function controlPlanePairingSha256(results) {
  return sha256(
    Buffer.from(
      canonicalJson({
        customDomains: results.get("custom-domains"),
        queueConsumers: results.get("queue-consumers"),
        queueTriggers: results.get("queue-triggers"),
        routes: results.get("routes"),
        schedules: results.get("schedules"),
      }),
    ),
  );
}

function validateQueuePair(results) {
  const consumers = results
    .get("queue-consumers")
    .map(({ queueName, scriptName }) => `${queueName}\0${scriptName}`);
  const triggers = results
    .get("queue-triggers")
    .map(({ queueName, scriptName }) => `${queueName}\0${scriptName}`);
  requireCondition(
    isDeepStrictEqual(consumers, triggers),
    "ADAPTER_QUEUE_PAIR_MISMATCH",
  );
}

function validateExpectation(expectation) {
  requireCondition(
    exactKeys(expectation, [
      "accountId",
      "correlationSha256",
      "observationNotAfter",
      "observationNotBefore",
      "pairingSha256",
      "phase",
      "schemaVersion",
      "serviceTag",
      "tokenBindingSha256",
      "workerName",
    ]) &&
      expectation.schemaVersion === 1 &&
      ACCOUNT_ID_PATTERN.test(expectation.accountId) &&
      DIGEST_PATTERN.test(expectation.correlationSha256) &&
      DIGEST_PATTERN.test(expectation.pairingSha256) &&
      DIGEST_PATTERN.test(expectation.tokenBindingSha256) &&
      ["preflight", "postflight"].includes(expectation.phase) &&
      typeof expectation.serviceTag === "string" &&
      expectation.serviceTag.length > 0 &&
      expectation.workerName === PRODUCTION_WORKER_NAME,
    "ADAPTER_EXPECTATION_SCHEMA",
  );
  const notBefore = canonicalTimestamp(expectation.observationNotBefore);
  const notAfter = canonicalTimestamp(expectation.observationNotAfter);
  requireCondition(
    notBefore <= notAfter && notAfter - notBefore <= 10 * 60 * 1000,
    "ADAPTER_EXPECTATION_TIME_WINDOW",
  );
  return { notAfter, notBefore };
}

export function normalizeCloudflareProductionSnapshot(bundleBytes, expectationBytes) {
  const bundle = parseBoundedProductionJson(bundleBytes);
  const expectation = parseBoundedProductionJson(expectationBytes);
  const expectationWindow = validateExpectation(expectation);
  requireCondition(
    exactKeys(bundle, [
      "correlationSha256",
      "observations",
      "pairingSha256",
      "phase",
      "schemaVersion",
      "tokenBindingSha256",
    ]) &&
      bundle.schemaVersion === 1 &&
      bundle.phase === expectation.phase &&
      bundle.correlationSha256 === expectation.correlationSha256 &&
      bundle.pairingSha256 === expectation.pairingSha256 &&
      bundle.tokenBindingSha256 === expectation.tokenBindingSha256 &&
      Array.isArray(bundle.observations) &&
      bundle.observations.length === PRODUCTION_SNAPSHOT_ENDPOINTS.length,
    "ADAPTER_BUNDLE_SCHEMA",
  );

  const results = new Map();
  let firstObservedAt = null;
  let priorObservedAt = null;
  for (let index = 0; index < PRODUCTION_SNAPSHOT_ENDPOINTS.length; index += 1) {
    const contract = PRODUCTION_SNAPSHOT_ENDPOINTS[index];
    const observation = bundle.observations[index];
    requireCondition(
      exactKeys(observation, [
        "accountId",
        "correlationSha256",
        "endpoint",
        "observedAt",
        "pairingSha256",
        "permissionClass",
        "responses",
        "tokenBindingSha256",
        "workerName",
      ]) &&
        observation.endpoint === contract.endpoint &&
        observation.accountId === expectation.accountId &&
        observation.workerName === expectation.workerName &&
        observation.correlationSha256 === expectation.correlationSha256 &&
        observation.permissionClass === contract.permissionClass &&
        observation.tokenBindingSha256 === expectation.tokenBindingSha256 &&
        observation.pairingSha256 ===
          (CONTROL_PLANE_ENDPOINTS.has(contract.endpoint)
            ? expectation.pairingSha256
            : null),
      "ADAPTER_OBSERVATION_IDENTITY",
    );
    const observedAt = canonicalTimestamp(observation.observedAt);
    requireCondition(
      observedAt >= expectationWindow.notBefore &&
        observedAt <= expectationWindow.notAfter,
      "ADAPTER_OBSERVATION_TIME_ORDER",
    );
    if (firstObservedAt === null) firstObservedAt = observedAt;
    requireCondition(
      index === 0 || observedAt >= priorObservedAt,
      "ADAPTER_OBSERVATION_TIME_ORDER",
    );
    priorObservedAt = observedAt;
    const result = normalizeObservationResponses(observation, contract);
    results.set(contract.endpoint, normalizeResult(contract.endpoint, result));
  }

  requireCondition(
    priorObservedAt - firstObservedAt <= 5 * 60 * 1000,
    "ADAPTER_OBSERVATION_TIME_ORDER",
  );
  validateQueuePair(results);
  requireCondition(
    controlPlanePairingSha256(results) === expectation.pairingSha256,
    "ADAPTER_CONTROL_PLANE_PAIRING_MISMATCH",
  );

  const identity = results.get("identity");
  requireCondition(
    exactKeys(identity, ["name", "tag"]) &&
      identity.name === expectation.workerName &&
      identity.tag === expectation.serviceTag,
    "ADAPTER_SERVICE_IDENTITY",
  );

  const snapshot = {
    schemaVersion: 2,
    accountId: expectation.accountId,
    workerName: identity.name,
    serviceTag: identity.tag,
    observation: {
      phase: expectation.phase,
      correlationSha256: expectation.correlationSha256,
      controlPlanePairingSha256: expectation.pairingSha256,
      endpointSetSha256: ENDPOINT_SET_SHA256,
      firstObservedAt: new Date(firstObservedAt).toISOString(),
      lastObservedAt: new Date(priorObservedAt).toISOString(),
      paginationStructureClosed: true,
      apiProvenanceVerified: false,
      atomicSnapshotVerified: false,
      permissionScopeVerified: false,
      singleWriterVerified: false,
      tokenBindingSha256: expectation.tokenBindingSha256,
    },
    deployments: results.get("deployments"),
    versions: results.get("versions"),
    activeVersion: results.get("active-version"),
    latestVersion: results.get("latest-version"),
    subdomain: results.get("subdomain"),
    routes: results.get("routes"),
    customDomains: results.get("custom-domains"),
    schedules: results.get("schedules"),
    queueConsumers: results.get("queue-consumers"),
    queueTriggers: results.get("queue-triggers"),
    scriptSettings: results.get("script-settings"),
  };
  validateNormalizedSnapshot(snapshot, {
    accountId: expectation.accountId,
    matchTag: expectation.serviceTag,
  });
  return Object.freeze(structuredClone(snapshot));
}
