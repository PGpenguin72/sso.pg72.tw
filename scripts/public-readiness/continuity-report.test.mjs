import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  classifiedStage,
  closedRuntimeError,
  earlyFailureReport,
} from "./continuity-local.mjs";
import { validateClosedReport, writeClosedReport } from "./report.mjs";

const stages = [
  "invocation",
  "setup",
  "workerd_suites",
  "migrations",
  "seed",
  "source_manifest",
  "source_schema",
  "source_records",
  "source_invariants",
  "export",
  "restore",
  "restore_manifest",
  "consent",
  "runtime",
  "report",
];

test("every early stage and cleanup state writes a closed mode-0600 report", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "pgid-continuity-reports-"));
  try {
    for (const stage of stages) {
      for (const cleanupValue of [false, true]) {
        const error = new Error("not persisted");
        error.name = stage === "runtime" ? "AssertionError" : "Error";
        const report = earlyFailureReport(
          stage,
          error,
          {
            listenerStopped: cleanupValue,
            temporarySqlRemoved: cleanupValue,
            temporaryStateRemoved: cleanupValue,
          },
          directory,
        );
        assert.doesNotThrow(() => validateClosedReport(report), stage);
        const filename = path.join(directory, `${stage}-${cleanupValue}.json`);
        writeClosedReport(filename, report);
        assert.equal(statSync(filename).mode & 0o777, 0o600);
      }
    }
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("classified stages expose only an allowlisted class", () => {
  const marker = "raw-wrangler-output-must-not-escape";
  assert.throws(
    () =>
      classifiedStage("D1ManifestError", () => {
        throw new Error(marker);
      }),
    (error) => {
      assert.equal(error.name, "D1ManifestError");
      assert.equal(error.message, "closed stage failure");
      assert.equal(error.message.includes(marker), false);
      assert.equal(error.cause, undefined);
      return true;
    },
  );
  assert.throws(
    () => classifiedStage("UnapprovedError", () => true),
    (error) => error?.name === "AssertionError",
  );
});

test("runtime diagnostics expose only a fixed phase class", () => {
  const error = closedRuntimeError("overlap_jwks");
  assert.equal(error.name, "RuntimeOverlapJwksError");
  assert.equal(error.message, "closed runtime failure");
  assert.equal(error.cause, undefined);
  assert.throws(
    () => closedRuntimeError("raw-caller-controlled-stage"),
    (candidate) => candidate?.name === "AssertionError",
  );
});
