import assert from "node:assert/strict";
import test from "node:test";

import { runBoundedProfile } from "./load-profiles.mjs";

const profile = {
  concurrency: 2,
  durationMs: 1000,
  requestsPerSecond: 100,
  totalRequests: 8,
};
const definitions = [
  { expectedStatuses: [200], id: "health" },
  { expectedStatuses: [401], id: "unauthorized" },
];

test("runs an exact bounded profile and emits body-free aggregate results", async () => {
  let active = 0;
  let maximumActive = 0;
  const results = await runBoundedProfile(
    profile,
    definitions,
    async (definition) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return new Response(null, {
        status: definition.id === "health" ? 200 : 401,
      });
    },
  );
  assert.ok(maximumActive <= profile.concurrency);
  assert.equal(results.reduce((sum, entry) => sum + entry.requestCount, 0), 8);
  assert.ok(results.every(({ status }) => status === "passed"));
  assert.ok(results.every((entry) => !Object.hasOwn(entry, "body")));
  assert.ok(results.every((entry) => !Object.hasOwn(entry, "url")));
});

test("records an unexpected status without retaining a response", async () => {
  const results = await runBoundedProfile(
    { ...profile, totalRequests: 1 },
    [definitions[0]],
    async () => new Response(null, { status: 500 }),
  );
  assert.equal(results[0].status, "failed");
  assert.equal(results[0].unexpectedStatusCount, 1);
  assert.equal(results[0].expectedStatusCount, 0);
});

test("rejects profiles whose request budget exceeds duration", async () => {
  await assert.rejects(
    runBoundedProfile(
      {
        concurrency: 1,
        durationMs: 10,
        requestsPerSecond: 1,
        totalRequests: 2,
      },
      definitions,
      async () => new Response(),
    ),
    /cannot fit within its duration/,
  );
});

test("passes a shared hard deadline to every request", async () => {
  const startedAt = performance.now();
  const results = await runBoundedProfile(
    {
      concurrency: 1,
      durationMs: 50,
      requestsPerSecond: 1,
      totalRequests: 1,
    },
    [definitions[0]],
    async (_definition, _index, signal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
      }),
  );
  assert.equal(results[0].status, "failed");
  assert.equal(results[0].timeoutCount, 1);
  assert.ok(performance.now() - startedAt < 500);
});
