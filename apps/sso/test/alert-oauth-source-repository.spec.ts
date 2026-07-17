import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ALERT_HASH_KEY_SENTINEL_DOMAIN,
  deriveAlertHashKeyFingerprintV1,
} from "../worker/alert-audit-source-repository";
import {
  ALERT_OAUTH_REPORT_GROUP_QUERY,
  ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY,
  ALERT_OAUTH_TRACKED_DIMENSIONS_QUERY,
  AlertOAuthSourceRepositoryError,
  readOAuthAlertSource,
  type OAuthAlertSourceResult,
} from "../worker/alert-oauth-source-repository";
import {
  deriveAlertReferenceV1,
  evaluateAlertRule,
  type OAuthClientReportWindowMetrics,
} from "../worker/alert-rules";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

const TEST_HMAC_KEY = base64Url(
  Uint8Array.from({ length: 32 }, (_, index) => index + 31),
);

interface InsertReportInput {
  clientId: string;
  createdAt: string;
  reason?: "impersonation" | "other" | "phishing" | "scope_abuse";
  reporterRef?: string | null;
  reporterRefHashVersion?: number | null;
  reporterUserId?: string | null;
}

async function insertUser(): Promise<string> {
  const id = crypto.randomUUID();
  const now = "2030-01-01T00:00:00.000Z";
  await env.PG72_ID_DB.prepare(
    `INSERT INTO user
      (id, name, email, emailVerified, createdAt, updatedAt, role, status,
       accessLevel)
     VALUES (?, 'OAuth source reporter', ?, 1, ?, ?, 'user', 'active',
             'standard')`,
  )
    .bind(id, `${id}@example.test`, now, now)
    .run();
  return id;
}

async function insertReport(input: InsertReportInput): Promise<string> {
  const id = crypto.randomUUID();
  await env.PG72_ID_DB.prepare(
    `INSERT INTO oauth_client_report
      (id, reporter_user_id, client_id, reason, status, created_at,
       reporter_ref, reporter_ref_hash_version)
     VALUES (?, ?, ?, ?, 'open', ?, ?, ?)`,
    )
    .bind(
      id,
      input.reporterUserId ?? null,
      input.clientId,
      input.reason ?? "other",
      input.createdAt,
      input.reporterRef ?? null,
      input.reporterRefHashVersion ?? null,
    )
    .run();
  return id;
}

function at(base: string, offsetMilliseconds: number): string {
  return new Date(new Date(base).getTime() + offsetMilliseconds).toISOString();
}

async function read(
  asOf: string,
  options: {
    database?: D1Database;
    environment?: "local" | "preview" | "production";
    key?: string | null;
  } = {},
): Promise<OAuthAlertSourceResult> {
  return readOAuthAlertSource(options.database ?? env.PG72_ID_DB, {
    asOf,
    environment: options.environment ?? "local",
    hmacKeyBase64Url: options.key === undefined ? TEST_HMAC_KEY : options.key,
  });
}

async function observationForClient(
  result: OAuthAlertSourceResult,
  clientId: string,
) {
  const reference = await deriveAlertReferenceV1(
    TEST_HMAC_KEY,
    "client_hmac",
    clientId,
  );
  return result.observations.find(
    (observation) => observation.dimension.reference.value === reference.value,
  );
}

function transformBatchDatabase(
  transform: (
    results: D1Result<Record<string, unknown>>[],
  ) => D1Result<Record<string, unknown>>[],
): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) =>
          transform(await target.batch<Record<string, unknown>>(statements));
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function replaceResultRows(
  results: D1Result<Record<string, unknown>>[],
  index: number,
  rows: readonly Record<string, unknown>[],
): D1Result<Record<string, unknown>>[] {
  return results.map((result, resultIndex) =>
    resultIndex === index ? { ...result, results: [...rows] } : result
  );
}

function failingBatchDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async () => {
          throw new Error("database failure leaked reporter-raw-forbidden");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function metrics(
  value: OAuthClientReportWindowMetrics,
): OAuthClientReportWindowMetrics {
  return value;
}

beforeAll(async () => {
  const fingerprint = await deriveAlertHashKeyFingerprintV1(TEST_HMAC_KEY);
  await env.PG72_ID_DB.prepare(
    `INSERT INTO alert_hash_key_sentinel
      (id, domain, fingerprint_ref, hash_version, created_at)
     VALUES (1, ?, ?, 1, ?)`,
  )
    .bind(
      ALERT_HASH_KEY_SENTINEL_DOMAIN,
      fingerprint.value,
      "2030-01-01T00:00:00.000Z",
    )
    .run();
});

describe.sequential("OAuth report alert source repository", () => {
  it("uses exact half-open windows and canonical total, risk, and distinct counts", async () => {
    const asOf = "2031-01-01T12:00:00.000Z";
    const clientId = "oauth-window-client";
    const firstReporter = await insertUser();
    const secondReporter = await insertUser();
    const secondReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "reporter_hmac",
      secondReporter,
    );
    await insertReport({
      clientId,
      createdAt: at(asOf, -3_600_000),
      reporterUserId: firstReporter,
    });
    await insertReport({
      clientId,
      createdAt: at(asOf, -900_000),
      reason: "phishing",
      reporterUserId: firstReporter,
    });
    await insertReport({
      clientId,
      createdAt: at(asOf, -300_000),
      reason: "impersonation",
      reporterRef: secondReference.value,
      reporterRefHashVersion: 1,
      reporterUserId: secondReporter,
    });
    await insertReport({
      clientId,
      createdAt: at(asOf, -1),
      reason: "phishing",
      reporterUserId: secondReporter,
    });
    await insertReport({
      clientId,
      createdAt: asOf,
      reason: "phishing",
      reporterUserId: null,
    });
    await insertReport({
      clientId,
      createdAt: at(asOf, -3_600_001),
      reason: "phishing",
      reporterUserId: null,
    });

    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(await observationForClient(result, clientId)).toMatchObject({
      windows: {
        "5m": metrics({ count: 2, distinctReporters: 1, highRiskCount: 2 }),
        "15m": metrics({ count: 3, distinctReporters: 2, highRiskCount: 3 }),
        "60m": metrics({ count: 4, distinctReporters: 2, highRiskCount: 3 }),
      },
    });
    expect(JSON.stringify(result)).not.toContain(firstReporter);
    expect(JSON.stringify(result)).not.toContain(secondReporter);
    expect(JSON.stringify(result)).not.toContain(clientId);
  });

  it("keeps missing reporter distinctness nullable while proven branches dominate", async () => {
    const asOf = "2031-01-02T12:00:00.000Z";
    const unknownClient = "oauth-unknown-client";
    const warningClient = "oauth-warning-client";
    const criticalClient = "oauth-critical-client";
    for (let index = 0; index < 3; index += 1) {
      await insertReport({
        clientId: unknownClient,
        createdAt: at(asOf, -1_800_000 - index),
        reason: "phishing",
      });
      await insertReport({
        clientId: warningClient,
        createdAt: at(asOf, -600_000 - index),
      });
    }
    for (let index = 0; index < 10; index += 1) {
      await insertReport({
        clientId: criticalClient,
        createdAt: at(asOf, -1_800_000 - index),
      });
    }

    const result = await read(asOf);
    expect(result.incomplete).toEqual([{
      dimensionKind: "client_hmac",
      ruleId: "pgid.oauth.client_report.v1",
    }]);
    const unknown = await observationForClient(result, unknownClient);
    const warning = await observationForClient(result, warningClient);
    const critical = await observationForClient(result, criticalClient);
    expect(unknown?.windows).toEqual({
      "5m": metrics({ count: 0, distinctReporters: 0, highRiskCount: 0 }),
      "15m": metrics({ count: 0, distinctReporters: 0, highRiskCount: 0 }),
      "60m": metrics({ count: 3, distinctReporters: null, highRiskCount: 3 }),
    });
    expect(unknown && evaluateAlertRule(unknown)).toMatchObject({
      evidence: "unknown",
      severity: "none",
    });
    expect(warning && evaluateAlertRule(warning)).toMatchObject({
      evidence: "known",
      severity: "warning",
    });
    expect(critical && evaluateAlertRule(critical)).toMatchObject({
      evidence: "known",
      severity: "critical",
    });
  });

  it("accepts raw and stored reporter equivalence and survives reporter deletion", async () => {
    const asOf = "2031-01-03T12:00:00.000Z";
    const clientId = "oauth-deleted-reporter-client";
    const reporter = await insertUser();
    const reporterReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "reporter_hmac",
      reporter,
    );
    await insertReport({
      clientId,
      createdAt: at(asOf, -2_000),
      reason: "phishing",
      reporterRef: reporterReference.value,
      reporterRefHashVersion: 1,
      reporterUserId: reporter,
    });
    const rawOnlyReportId = await insertReport({
      clientId,
      createdAt: at(asOf, -1_000),
      reporterUserId: reporter,
    });
    expect((await observationForClient(await read(asOf), clientId))?.windows["5m"])
      .toEqual(metrics({ count: 2, distinctReporters: 1, highRiskCount: 1 }));

    await env.PG72_ID_DB.prepare(
      `UPDATE oauth_client_report
          SET reporter_ref = ?, reporter_ref_hash_version = 1
        WHERE id = ? AND reporter_user_id = ?
          AND reporter_ref IS NULL AND reporter_ref_hash_version IS NULL`,
    )
      .bind(reporterReference.value, rawOnlyReportId, reporter)
      .run();

    await env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
      .bind(reporter)
      .run();
    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect((await observationForClient(result, clientId))?.windows["5m"])
      .toEqual(metrics({ count: 2, distinctReporters: 1, highRiskCount: 1 }));
  });

  it("fails reporter HMAC equality and domain mismatches into nullable evidence", async () => {
    const asOf = "2031-01-04T12:00:00.000Z";
    const clientId = "oauth-mismatched-reporter-client";
    const reporter = await insertUser();
    const wrongDomainReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      reporter,
    );
    await insertReport({
      clientId,
      createdAt: at(asOf, -1),
      reason: "phishing",
      reporterRef: wrongDomainReference.value,
      reporterRefHashVersion: 1,
      reporterUserId: reporter,
    });

    const result = await read(asOf);
    expect(result.incomplete).toHaveLength(1);
    expect((await observationForClient(result, clientId))?.windows).toEqual({
      "5m": metrics({ count: 1, distinctReporters: null, highRiskCount: 1 }),
      "15m": metrics({ count: 1, distinctReporters: null, highRiskCount: 1 }),
      "60m": metrics({ count: 1, distinctReporters: null, highRiskCount: 1 }),
    });
    expect(JSON.stringify(result)).not.toContain(reporter);
    expect(JSON.stringify(result)).not.toContain(wrongDomainReference.value);
  });

  it("reuses the exact key sentinel and rejects a corrupt sentinel domain", async () => {
    const asOf = "2031-01-05T12:00:00.000Z";
    expect((await read(asOf)).incomplete).toEqual([]);
    expect((await read(asOf, { key: null })).incomplete).toHaveLength(1);
    expect(
      (await read(asOf, { key: base64Url(new Uint8Array(32).fill(7)) }))
        .incomplete,
    ).toHaveLength(1);

    const missingSentinel = transformBatchDatabase((results) =>
      replaceResultRows(results, 1, [])
    );
    expect((await read(asOf, { database: missingSentinel })).incomplete)
      .toHaveLength(1);

    const fingerprint = await deriveAlertHashKeyFingerprintV1(TEST_HMAC_KEY);
    const wrongDomain = transformBatchDatabase((results) =>
      replaceResultRows(results, 1, [{
        domain: "pgid.wrong-alert-key-domain.v1",
        fingerprint_ref: fingerprint.value,
        hash_version: 1,
      }])
    );
    await expect(read(asOf, { database: wrongDomain })).rejects.toEqual(
      new AlertOAuthSourceRepositoryError("source_invalid"),
    );
  });

  it("fails closed on global timestamp corruption before lexical report windows", async () => {
    const asOf = "2031-01-05T13:00:00.000Z";
    const rawMarker = "raw-oauth-time-must-not-leak";
    const corruptProjections = [
      [{ invalid_timestamp_exists: 1 }],
      [],
      [{ invalid_timestamp_exists: false }],
      [{ invalid_timestamp_exists: "0" }],
      [
        { invalid_timestamp_exists: 0 },
        { invalid_timestamp_exists: 0 },
      ],
      [{ invalid_timestamp_exists: 0, unexpected: rawMarker }],
    ];
    for (const projection of corruptProjections) {
      const database = transformBatchDatabase((results) =>
        replaceResultRows(results, 0, projection)
      );
      const failure = read(asOf, { database });
      await expect(failure).rejects.toEqual(
        new AlertOAuthSourceRepositoryError("source_invalid"),
      );
      await expect(failure).rejects.not.toThrow(rawMarker);
    }

    const plan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY}`,
    ).all<{ detail: string }>();
    const details = plan.results.map(({ detail }) => detail).join("\n");
    expect(ALERT_OAUTH_TIMESTAMP_INTEGRITY_QUERY).toContain("LIMIT 1");
    expect(details).toContain(
      "USING COVERING INDEX oauth_client_report_invalid_created_at_idx",
    );
    expect(details).not.toMatch(/SCAN oauth_client_report$/m);
  });

  it("enforces canonical count caps, nesting, and subset relationships", async () => {
    const asOf = "2031-01-06T12:00:00.000Z";
    const clientId = "oauth-cap-client";
    const reporter = await insertUser();
    await insertReport({
      clientId,
      createdAt: at(asOf, -1),
      reporterUserId: reporter,
    });
    const base = (count: number, highRiskCount = 0) => ({
      client_id: clientId,
      reporter_user_id: reporter,
      reporter_ref: null,
      reporter_ref_hash_version: null,
      count_5m: count,
      high_risk_5m: highRiskCount,
      count_15m: count,
      high_risk_15m: highRiskCount,
      count_60m: count,
      high_risk_60m: highRiskCount,
    });
    const withSourceRows = (rows: readonly Record<string, unknown>[]) =>
      transformBatchDatabase((results) => replaceResultRows(results, 3, rows));

    const atCap = await read(asOf, {
      database: withSourceRows([base(1_000_000_000)]),
    });
    expect((await observationForClient(atCap, clientId))?.windows["60m"].count)
      .toBe(1_000_000_000);
    expect((await read(asOf, {
      database: withSourceRows([base(1_000_000_001)]),
    })).incomplete).toHaveLength(1);
    expect((await read(asOf, {
      database: withSourceRows([base(1, 2)]),
    })).incomplete).toHaveLength(1);
    expect((await read(asOf, {
      database: withSourceRows([{
        ...base(2),
        count_15m: 1,
      }]),
    })).incomplete).toHaveLength(1);
  });

  it("bounds source and tracked groups and zero-fills only tracked clients", async () => {
    const asOf = "2031-01-07T12:00:00.000Z";
    const trackedClient = "oauth-tracked-client";
    const trackedReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "client_hmac",
      trackedClient,
    );
    const withTracked = transformBatchDatabase((results) =>
      replaceResultRows(results, 2, [{
        hash_version: 1,
        subject_ref: trackedReference.value,
      }])
    );
    const trackedResult = await read(asOf, { database: withTracked });
    expect(await observationForClient(trackedResult, trackedClient)).toMatchObject({
      windows: {
        "5m": metrics({ count: 0, distinctReporters: 0, highRiskCount: 0 }),
        "15m": metrics({ count: 0, distinctReporters: 0, highRiskCount: 0 }),
        "60m": metrics({ count: 0, distinctReporters: 0, highRiskCount: 0 }),
      },
    });

    const overflowRows = Array.from({ length: 1_001 }, (_, index) => ({
      hash_version: 1,
      subject_ref: `${String(index).padStart(42, "0")}A`,
    }));
    const trackedOverflow = transformBatchDatabase((results) =>
      replaceResultRows(results, 2, overflowRows)
    );
    const overflow = await read(asOf, { database: trackedOverflow });
    expect(overflow.incomplete).toHaveLength(1);
    expect(overflow.observations).toEqual([]);

    const sourceOverflow = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        3,
        Array.from({ length: 1_001 }, () => ({})),
      )
    );
    const sourceOverflowResult = await read(asOf, {
      database: sourceOverflow,
    });
    expect(sourceOverflowResult.incomplete).toHaveLength(1);
    expect(sourceOverflowResult.observations).toEqual([]);
  });

  it("pins both bounded query plans to the reviewed partial and time indexes", async () => {
    const asOf = "2031-01-08T12:00:00.000Z";
    const windows = [
      at(asOf, -300_000),
      at(asOf, -900_000),
      at(asOf, -3_600_000),
      asOf,
    ] as const;
    const sourcePlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_OAUTH_REPORT_GROUP_QUERY}`,
    )
      .bind(...windows)
      .all<{ detail: string }>();
    const sourcePlanDetails = sourcePlan.results
      .map(({ detail }) => detail)
      .join("\n");
    expect(sourcePlanDetails)
      .toContain("oauth_client_report_time_client_reason_reporter_bounded_idx");
    expect(sourcePlanDetails).toMatch(/SEARCH oauth_client_report\b/);

    const trackedPlan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_OAUTH_TRACKED_DIMENSIONS_QUERY}`,
    )
      .bind("local")
      .all<{ detail: string }>();
    const trackedPlanDetails = trackedPlan.results
      .map(({ detail }) => detail)
      .join("\n");
    expect(trackedPlanDetails).toContain("alert_state_tracked_evaluation_idx");
    expect(trackedPlanDetails).toMatch(/SEARCH alert_state\b/);
  });

  it("redacts D1 failures and turns corrupt source rows into incomplete evidence", async () => {
    const asOf = "2031-01-09T12:00:00.000Z";
    const unavailable = read(asOf, { database: failingBatchDatabase() });
    await expect(unavailable).rejects.toEqual(
      new AlertOAuthSourceRepositoryError("source_unavailable"),
    );
    await expect(unavailable).rejects.not.toThrow("reporter-raw-forbidden");

    const rawMarker = "raw-client-must-not-leak";
    const corrupt = transformBatchDatabase((results) =>
      replaceResultRows(results, 3, [{
        client_id: rawMarker,
        reporter_user_id: "raw-reporter-must-not-leak",
        reporter_ref: null,
        reporter_ref_hash_version: null,
        count_5m: "1",
        high_risk_5m: 0,
        count_15m: 1,
        high_risk_15m: 0,
        count_60m: 1,
        high_risk_60m: 0,
      }])
    );
    const result = await read(asOf, { database: corrupt });
    expect(result.incomplete).toHaveLength(1);
    expect(result.observations).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(rawMarker);

    const reporterTypeCorruption = transformBatchDatabase((results) =>
      replaceResultRows(results, 3, [{
        client_id: "corrupt-reporter-type-client",
        reporter_user_id: 42,
        reporter_ref: `${"0".repeat(42)}A`,
        reporter_ref_hash_version: 1,
        count_5m: 1,
        high_risk_5m: 0,
        count_15m: 1,
        high_risk_15m: 0,
        count_60m: 1,
        high_risk_60m: 0,
      }])
    );
    const reporterCorruption = await read(asOf, {
      database: reporterTypeCorruption,
    });
    expect(reporterCorruption.incomplete).toHaveLength(1);
    expect(reporterCorruption.observations[0]?.windows["60m"])
      .toMatchObject({ distinctReporters: null });

    await expect(readOAuthAlertSource(env.PG72_ID_DB, {
      asOf: "not-a-time",
      environment: "local",
      hmacKeyBase64Url: TEST_HMAC_KEY,
    })).rejects.toEqual(new AlertOAuthSourceRepositoryError("invalid_input"));
  });
});
