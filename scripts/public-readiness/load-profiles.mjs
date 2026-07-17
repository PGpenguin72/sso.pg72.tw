import assert from "node:assert/strict";

function percentile(sorted, fraction) {
  if (sorted.length === 0) return 0;
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil(sorted.length * fraction) - 1),
  );
  return Math.round(sorted[index]);
}

function validateScenario(definition) {
  assert.match(definition.id, /^[a-z][a-z0-9_]{0,63}$/);
  assert.ok(
    Array.isArray(definition.expectedStatuses) &&
      definition.expectedStatuses.length > 0,
  );
  for (const status of definition.expectedStatuses) {
    assert.ok(Number.isInteger(status) && status >= 100 && status <= 599);
  }
}

function validateProfile(profile) {
  for (const name of [
    "concurrency",
    "durationMs",
    "requestsPerSecond",
    "totalRequests",
  ]) {
    assert.ok(Number.isSafeInteger(profile[name]) && profile[name] > 0);
  }
  const lastScheduledAt =
    ((profile.totalRequests - 1) / profile.requestsPerSecond) * 1000;
  assert.ok(
    lastScheduledAt <= profile.durationMs,
    "profile request budget cannot fit within its duration",
  );
}

function delay(milliseconds) {
  return milliseconds <= 0
    ? Promise.resolve()
    : new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function emptyResult(id) {
  return {
    errors: 0,
    expected: 0,
    id,
    latencies: [],
    requests: 0,
    timeouts: 0,
    unexpected: 0,
  };
}

export async function runBoundedProfile(
  profile,
  definitions,
  requestImplementation,
) {
  validateProfile(profile);
  assert.ok(Array.isArray(definitions) && definitions.length > 0);
  definitions.forEach(validateScenario);
  assert.equal(new Set(definitions.map(({ id }) => id)).size, definitions.length);
  assert.equal(typeof requestImplementation, "function");
  const results = new Map(
    definitions.map(({ id }) => [id, emptyResult(id)]),
  );
  const startedAt = performance.now();
  const deadlineSignal = AbortSignal.timeout(profile.durationMs);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= profile.totalRequests) return;
      const scheduledAt = startedAt + (index / profile.requestsPerSecond) * 1000;
      await delay(scheduledAt - performance.now());
      const definition = definitions[index % definitions.length];
      const result = results.get(definition.id);
      result.requests += 1;
      const requestStartedAt = performance.now();
      try {
        const response = await requestImplementation(
          definition,
          index,
          deadlineSignal,
        );
        const latency = performance.now() - requestStartedAt;
        result.latencies.push(latency);
        if (definition.expectedStatuses.includes(response.status)) result.expected += 1;
        else result.unexpected += 1;
        if (response.body) await response.body.cancel();
      } catch (error) {
        const latency = performance.now() - requestStartedAt;
        result.latencies.push(latency);
        if (error instanceof DOMException && error.name === "TimeoutError") {
          result.timeouts += 1;
        } else {
          result.errors += 1;
        }
      }
    }
  }

  await Promise.all(
    Array.from({ length: profile.concurrency }, () => worker()),
  );
  const elapsedSeconds = Math.max((performance.now() - startedAt) / 1000, 0.001);
  return [...results.values()].map((result) => {
    const latencies = [...result.latencies].sort((left, right) => left - right);
    const passed =
      result.expected === result.requests &&
      result.unexpected === 0 &&
      result.timeouts === 0 &&
      result.errors === 0;
    return {
      errorCount: result.errors,
      expectedStatusCount: result.expected,
      id: result.id,
      maxMs: latencies.length === 0 ? 0 : Math.round(latencies.at(-1)),
      p50Ms: percentile(latencies, 0.5),
      p95Ms: percentile(latencies, 0.95),
      p99Ms: percentile(latencies, 0.99),
      requestCount: result.requests,
      status: passed ? "passed" : "failed",
      throughputPerSecond: Number((result.requests / elapsedSeconds).toFixed(3)),
      timeoutCount: result.timeouts,
      unexpectedStatusCount: result.unexpected,
    };
  });
}
