import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { earlyDrillReport } from "./drills-local.mjs";
import { validateClosedReport, writeClosedReport } from "./report.mjs";

const stages = [
  "invocation",
  "setup",
  "workerd_suites",
  "migrations",
  "runtime",
  "manifest",
  "report",
];
const profile = {
  concurrency: 1,
  durationMs: 100,
  requestsPerSecond: 1,
  totalRequests: 1,
};

test("every drill failure stage writes dependencies in a closed mode-0600 report", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-drill-reports-"));
  try {
    for (const stage of stages) {
      for (const cleanupValue of [false, true]) {
        const error = new Error("not persisted");
        const report = earlyDrillReport(
          stage,
          error,
          {
            listenerStopped: cleanupValue,
            temporaryStateRemoved: cleanupValue,
          },
          profile,
          directory,
        );
        assert.doesNotThrow(() => validateClosedReport(report), stage);
        assert.equal(report.ready, false);
        assert.equal(report.dependencies.length, 5);
        const filename = path.join(directory, `${stage}-${cleanupValue}.json`);
        writeClosedReport(filename, report);
        assert.equal(statSync(filename).mode & 0o777, 0o600);
      }
    }
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
