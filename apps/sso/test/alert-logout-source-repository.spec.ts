import { env } from "cloudflare:workers";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ALERT_HASH_KEY_SENTINEL_DOMAIN,
  deriveAlertHashKeyFingerprintV1,
} from "../worker/alert-audit-source-repository";
import {
  ALERT_LOGOUT_CURRENT_CLIENT_QUERY,
  ALERT_LOGOUT_CURRENT_GLOBAL_QUERY,
  ALERT_LOGOUT_DELIVERY_CLIENT_QUERY,
  ALERT_LOGOUT_DELIVERY_GLOBAL_QUERY,
  ALERT_LOGOUT_LEASE_CLIENT_QUERY,
  ALERT_LOGOUT_LEASE_GLOBAL_QUERY,
  ALERT_LOGOUT_SOURCE_RESULT_INDEX,
  ALERT_LOGOUT_TIMESTAMP_INTEGRITY_QUERY,
  ALERT_LOGOUT_TRACKED_DIMENSIONS_QUERY,
  AlertLogoutSourceRepositoryError,
  readLogoutDeliveryAlertSource,
  type LogoutDeliveryAlertObservation,
  type LogoutDeliveryAlertSourceResult,
} from "../worker/alert-logout-source-repository";
import {
  deriveAlertReferenceV1,
  evaluateAlertRule,
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
  Uint8Array.from({ length: 32 }, (_, index) => index + 71),
);
const TEST_EVENT_TYPE = "logout.source_test";

type DeliveryStatus =
  | "dead"
  | "delivered"
  | "pending"
  | "processing"
  | "retry";
type AttemptOutcome =
  | "dead"
  | "delivered"
  | "in_flight"
  | "lease_expired"
  | "retry";

interface InsertDeliveryInput {
  clientId: string;
  createdAt: string;
  status: DeliveryStatus;
}

function at(base: string, offsetMilliseconds: number): string {
  return new Date(new Date(base).getTime() + offsetMilliseconds).toISOString();
}

async function insertDelivery(input: InsertDeliveryInput): Promise<number> {
  const eventId = crypto.randomUUID();
  const deliveryKey = `L${crypto.randomUUID()}${"0".repeat(8)}`;
  const fixedAuditTime = "2030-01-01T00:00:00.000Z";
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event (id, event_type, outcome, occurred_at)
     VALUES (?, ?, 'success', ?)`,
  )
    .bind(eventId, TEST_EVENT_TYPE, fixedAuditTime)
    .run();
  const nextAttemptAt = input.status === "pending" || input.status === "retry"
    ? input.createdAt
    : null;
  const leaseId = input.status === "processing" ? crypto.randomUUID() : null;
  const leaseExpiresAt = input.status === "processing"
    ? at(input.createdAt, 60_000)
    : null;
  const deliveredAt = input.status === "delivered" ? input.createdAt : null;
  await env.PG72_ID_DB.prepare(
    `INSERT INTO logout_delivery
      (delivery_key, event_id, session_id, user_id, client_id,
       backchannel_logout_uri, reason, status, attempts, replay_count, jti,
       next_attempt_at, lease_id, lease_expires_at, delivered_at,
       last_error_code, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'sign_out', ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      deliveryKey,
      eventId,
      `sensitive-sid-${crypto.randomUUID()}`,
      `sensitive-user-${crypto.randomUUID()}`,
      input.clientId,
      "https://sensitive-rp.example.test/backchannel-logout",
      input.status,
      input.status === "pending" ? 0 : 1,
      `sensitive-jti-${crypto.randomUUID()}`,
      nextAttemptAt,
      leaseId,
      leaseExpiresAt,
      deliveredAt,
      input.status === "dead" ? "sensitive-terminal-detail" : null,
      input.createdAt,
      input.createdAt,
    )
    .run();
  const row = await env.PG72_ID_DB.prepare(
    "SELECT id FROM logout_delivery WHERE delivery_key = ?",
  )
    .bind(deliveryKey)
    .first<{ id: number }>();
  if (!row) throw new Error("test logout delivery insert failed");
  return row.id;
}

async function insertAttempt(
  deliveryId: number,
  outcome: AttemptOutcome,
  completedAt: string | null,
  attemptNumber: number,
  replayCount = 0,
): Promise<void> {
  const terminal = outcome !== "in_flight";
  const resultingStatus = outcome === "delivered"
    ? "delivered"
    : outcome === "dead"
    ? "dead"
    : outcome === "in_flight"
    ? "processing"
    : "retry";
  const httpStatus = outcome === "delivered"
    ? 200
    : outcome === "retry" || outcome === "dead" ? 500 : null;
  const errorCode = outcome === "lease_expired"
    ? "lease_expired"
    : outcome === "retry" || outcome === "dead" ? "http_5xx" : null;
  const startedAt = completedAt === null
    ? "2035-01-01T00:00:00.000Z"
    : at(completedAt, -1_000);
  await env.PG72_ID_DB.prepare(
    `INSERT INTO logout_delivery_attempt
      (id, delivery_id, replay_count, attempt_number, lease_id, outcome,
       resulting_status, http_status, error_code, started_at, completed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      deliveryId,
      replayCount,
      attemptNumber,
      crypto.randomUUID(),
      outcome,
      resultingStatus,
      httpStatus,
      errorCode,
      startedAt,
      terminal ? completedAt : null,
    )
    .run();
}

async function read(
  asOf: string,
  options: {
    database?: D1Database;
    environment?: "local" | "preview" | "production";
    key?: string | null;
  } = {},
): Promise<LogoutDeliveryAlertSourceResult> {
  return readLogoutDeliveryAlertSource(
    options.database ?? env.PG72_ID_DB,
    {
      asOf,
      environment: options.environment ?? "local",
      hmacKeyBase64Url: options.key === undefined ? TEST_HMAC_KEY : options.key,
    },
  );
}

function globalObservation(
  result: LogoutDeliveryAlertSourceResult,
): LogoutDeliveryAlertObservation | undefined {
  return result.observations.find(
    (observation) => observation.dimension.kind === "global",
  );
}

async function observationForClient(
  result: LogoutDeliveryAlertSourceResult,
  clientId: string,
): Promise<LogoutDeliveryAlertObservation | undefined> {
  const reference = await deriveAlertReferenceV1(
    TEST_HMAC_KEY,
    "client_hmac",
    clientId,
  );
  return result.observations.find(
    (observation) =>
      observation.dimension.kind === "client_hmac" &&
      observation.dimension.reference.value === reference.value,
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
          throw new Error(
            "https://private.example.test token=jti sid client-id metadata user@example.test",
          );
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function emptyCurrentRow(): Record<string, unknown> {
  return {
    current_unresolved: 0,
    current_dead: 0,
    oldest_unresolved_created_at: null,
    newest_unresolved_created_at: null,
    invalid_created_at_count: 0,
  };
}

function emptyDeliveryRow(): Record<string, unknown> {
  return {
    eligible_5m: 0,
    unresolved_5m: 0,
    eligible_15m: 0,
    unresolved_15m: 0,
    eligible_60m: 0,
    unresolved_60m: 0,
    oldest_created_at: null,
    newest_created_at: null,
    invalid_created_at_count: 0,
  };
}

function emptyLeaseRow(): Record<string, unknown> {
  return {
    lease_expired_5m: 0,
    lease_expired_15m: 0,
    lease_expired_60m: 0,
    oldest_completed_at: null,
    newest_completed_at: null,
    invalid_completed_at_count: 0,
  };
}

beforeAll(async () => {
  const fingerprint = await deriveAlertHashKeyFingerprintV1(TEST_HMAC_KEY);
  await env.PG72_ID_DB.prepare(
    `INSERT OR IGNORE INTO alert_hash_key_sentinel
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

beforeEach(async () => {
  await env.PG72_ID_DB.batch([
    env.PG72_ID_DB.prepare("DELETE FROM logout_delivery"),
    env.PG72_ID_DB.prepare(
      "DELETE FROM audit_event WHERE event_type = ?",
    ).bind(TEST_EVENT_TYPE),
  ]);
});

describe.sequential("logout delivery alert source repository", () => {
  it("emits the canonical empty global observation without inventing clients", async () => {
    const asOf = "2035-01-01T12:00:00.000Z";
    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(result.observations).toHaveLength(1);
    expect(globalObservation(result)).toEqual({
      asOf,
      current: {
        currentDead: 0,
        currentUnresolved: 0,
        oldestUnresolvedAgeSeconds: null,
      },
      dimension: { kind: "global" },
      ruleId: "pgid.logout.delivery_health.v1",
      windows: {
        "5m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
        "15m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
        "60m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
      },
    });
  });

  it("keeps old current failures while using exact half-open delivery cohorts", async () => {
    const asOf = "2035-02-01T12:00:00.000Z";
    const firstClient = "logout-boundary-client-a";
    const secondClient = "logout-boundary-client-b";
    const endExclusiveClient = "logout-end-exclusive-client";
    const oldDeadId = await insertDelivery({
      clientId: firstClient,
      createdAt: at(asOf, -7_200_000),
      status: "dead",
    });
    await insertDelivery({
      clientId: firstClient,
      createdAt: at(asOf, -100_000),
      status: "pending",
    });
    await insertDelivery({
      clientId: firstClient,
      createdAt: at(asOf, -300_000),
      status: "delivered",
    });
    await insertDelivery({
      clientId: secondClient,
      createdAt: at(asOf, -900_000),
      status: "retry",
    });
    await insertDelivery({
      clientId: secondClient,
      createdAt: at(asOf, -3_600_000),
      status: "processing",
    });
    await insertDelivery({
      clientId: secondClient,
      createdAt: at(asOf, -1),
      status: "delivered",
    });
    await insertDelivery({
      clientId: endExclusiveClient,
      createdAt: asOf,
      status: "pending",
    });

    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(globalObservation(result)).toMatchObject({
      current: {
        currentDead: 1,
        currentUnresolved: 4,
        oldestUnresolvedAgeSeconds: 7_200,
      },
      windows: {
        "5m": { eligible: 3, leaseExpired: 0, unresolved: 1 },
        "15m": { eligible: 4, leaseExpired: 0, unresolved: 2 },
        "60m": { eligible: 5, leaseExpired: 0, unresolved: 3 },
      },
    });
    expect(await observationForClient(result, firstClient)).toMatchObject({
      current: {
        currentDead: 1,
        currentUnresolved: 2,
        oldestUnresolvedAgeSeconds: 7_200,
      },
      windows: {
        "5m": { eligible: 2, unresolved: 1 },
        "15m": { eligible: 2, unresolved: 1 },
        "60m": { eligible: 2, unresolved: 1 },
      },
    });
    expect(await observationForClient(result, secondClient)).toMatchObject({
      current: {
        currentDead: 0,
        currentUnresolved: 2,
        oldestUnresolvedAgeSeconds: 3_600,
      },
      windows: {
        "5m": { eligible: 1, unresolved: 0 },
        "15m": { eligible: 2, unresolved: 1 },
        "60m": { eligible: 3, unresolved: 2 },
      },
    });
    expect(await observationForClient(result, endExclusiveClient)).toBeUndefined();
    expect(evaluateAlertRule(globalObservation(result)!)).toMatchObject({
      immediateCritical: true,
      selectedEvidence: { metricName: "dead", observedValue: 1 },
      severity: "critical",
    });

    await env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery
          SET status = 'pending', next_attempt_at = ?, delivered_at = NULL,
              lease_id = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE id = ?`,
    )
      .bind(asOf, asOf, oldDeadId)
      .run();
    const replayed = await read(at(asOf, 1));
    expect(globalObservation(replayed)?.current).toEqual({
      currentDead: 0,
      currentUnresolved: 5,
      oldestUnresolvedAgeSeconds: 7_200,
    });
  });

  it("uses the closed delivery statuses and only terminal lease-expired attempts", async () => {
    const asOf = "2035-03-01T12:00:00.000Z";
    const clientId = "logout-status-client";
    const ids: number[] = [];
    for (const status of [
      "pending",
      "processing",
      "retry",
      "delivered",
      "dead",
    ] as const) {
      ids.push(await insertDelivery({
        clientId,
        createdAt: at(asOf, -1_000),
        status,
      }));
    }
    await insertAttempt(ids[0], "lease_expired", at(asOf, -500), 1);
    await insertAttempt(ids[1], "delivered", at(asOf, -400), 1);
    await insertAttempt(ids[2], "retry", at(asOf, -300), 1);
    await insertAttempt(ids[3], "dead", at(asOf, -200), 1);
    await insertAttempt(ids[4], "in_flight", null, 1);

    const observation = globalObservation(await read(asOf));
    expect(observation).toMatchObject({
      current: {
        currentDead: 1,
        currentUnresolved: 4,
        oldestUnresolvedAgeSeconds: 1,
      },
      windows: {
        "5m": { eligible: 5, leaseExpired: 1, unresolved: 4 },
        "15m": { eligible: 5, leaseExpired: 1, unresolved: 4 },
        "60m": { eligible: 5, leaseExpired: 1, unresolved: 4 },
      },
    });
    expect(ALERT_LOGOUT_DELIVERY_GLOBAL_QUERY).toContain(
      "status IN ('pending', 'processing', 'retry', 'delivered', 'dead')",
    );
    expect(ALERT_LOGOUT_LEASE_GLOBAL_QUERY).toContain(
      "attempt.outcome = 'lease_expired'",
    );
    expect(ALERT_LOGOUT_LEASE_GLOBAL_QUERY).not.toContain("lease_expires_at");
  });

  it("counts every terminal lease expiry by completion window, including old deliveries", async () => {
    const asOf = "2035-04-01T12:00:00.000Z";
    const clientId = "logout-lease-boundary-client";
    const deliveryId = await insertDelivery({
      clientId,
      createdAt: at(asOf, -7_200_000),
      status: "delivered",
    });
    await insertAttempt(deliveryId, "lease_expired", at(asOf, -3_600_000), 1);
    await insertAttempt(deliveryId, "lease_expired", at(asOf, -900_000), 2);
    await insertAttempt(deliveryId, "lease_expired", at(asOf, -300_000), 3);
    await insertAttempt(deliveryId, "lease_expired", at(asOf, -1), 4);
    await insertAttempt(deliveryId, "lease_expired", asOf, 5);
    const expiredProcessing = await insertDelivery({
      clientId: "logout-live-expired-lease-client",
      createdAt: at(asOf, -120_000),
      status: "processing",
    });
    await env.PG72_ID_DB.prepare(
      "UPDATE logout_delivery SET lease_expires_at = ? WHERE id = ?",
    )
      .bind(at(asOf, -1), expiredProcessing)
      .run();

    const result = await read(asOf);
    expect(globalObservation(result)?.windows).toEqual({
      "5m": { eligible: 1, leaseExpired: 2, unresolved: 1 },
      "15m": { eligible: 1, leaseExpired: 3, unresolved: 1 },
      "60m": { eligible: 1, leaseExpired: 4, unresolved: 1 },
    });
    expect((await observationForClient(result, clientId))?.windows).toEqual({
      "5m": { eligible: 0, leaseExpired: 2, unresolved: 0 },
      "15m": { eligible: 0, leaseExpired: 3, unresolved: 0 },
      "60m": { eligible: 0, leaseExpired: 4, unresolved: 0 },
    });
    expect(
      (await observationForClient(
        result,
        "logout-live-expired-lease-client",
      ))?.windows["5m"].leaseExpired,
    ).toBe(0);
  });

  it("keeps global evidence when HMAC continuity is unavailable and zero-fills tracked clients", async () => {
    const asOf = "2035-05-01T12:00:00.000Z";
    const trackedClient = "logout-tracked-client";
    const trackedReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "client_hmac",
      trackedClient,
    );
    const withTracked = transformBatchDatabase((results) =>
      replaceResultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.tracked, [{
        subject_ref: trackedReference.value,
        hash_version: 1,
      }])
    );
    const tracked = await read(asOf, { database: withTracked });
    expect(tracked.incomplete).toEqual([]);
    expect(await observationForClient(tracked, trackedClient)).toMatchObject({
      current: {
        currentDead: 0,
        currentUnresolved: 0,
        oldestUnresolvedAgeSeconds: null,
      },
      windows: {
        "5m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
        "15m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
        "60m": { eligible: 0, leaseExpired: 0, unresolved: 0 },
      },
    });

    for (const options of [
      { key: null },
      { key: base64Url(new Uint8Array(32).fill(9)) },
      {
        database: transformBatchDatabase((results) =>
          replaceResultRows(
            results,
            ALERT_LOGOUT_SOURCE_RESULT_INDEX.sentinel,
            [],
          )
        ),
      },
    ]) {
      const result = await read(asOf, options);
      expect(result.incomplete).toEqual([{
        dimensionKind: "client_hmac",
        ruleId: "pgid.logout.delivery_health.v1",
      }]);
      expect(globalObservation(result)).toBeDefined();
      expect(result.observations).toHaveLength(1);
    }
  });

  it("rejects malformed sentinel rows but never exposes their contents", async () => {
    const asOf = "2035-06-01T12:00:00.000Z";
    const marker = "private-sentinel-domain-marker";
    const malformed = transformBatchDatabase((results) =>
      replaceResultRows(results, ALERT_LOGOUT_SOURCE_RESULT_INDEX.sentinel, [{
        domain: marker,
        fingerprint_ref: `${"0".repeat(42)}A`,
        hash_version: 1,
      }])
    );
    const failure = read(asOf, { database: malformed });
    await expect(failure).rejects.toEqual(
      new AlertLogoutSourceRepositoryError("source_invalid"),
    );
    await expect(failure).rejects.not.toThrow(marker);
  });

  it("fails the client dimension closed on a deterministic HMAC collision", async () => {
    const asOf = "2035-06-15T12:00:00.000Z";
    const timestamp = at(asOf, -1_000);
    const firstRawClient = "collision-raw-client-a";
    const secondRawClient = "collision-raw-client-b";
    const forcedSignature = new Uint8Array(32).fill(17);
    const forcedReference = base64Url(forcedSignature);
    const database = transformBatchDatabase((results) => {
      let transformed = replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.sentinel,
        [{
          domain: ALERT_HASH_KEY_SENTINEL_DOMAIN,
          fingerprint_ref: forcedReference,
          hash_version: 1,
        }],
      );
      transformed = replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
        [{
          current_unresolved: 2,
          current_dead: 0,
          oldest_unresolved_created_at: timestamp,
          newest_unresolved_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
      return replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient,
        [firstRawClient, secondRawClient].map((clientId) => ({
          client_id: clientId,
          current_unresolved: 1,
          current_dead: 0,
          oldest_unresolved_created_at: timestamp,
          newest_unresolved_created_at: timestamp,
          invalid_created_at_count: 0,
        })),
      );
    });
    const sign = vi.spyOn(crypto.subtle, "sign").mockResolvedValue(
      forcedSignature.buffer,
    );
    try {
      const result = await read(asOf, { database });
      expect(result.incomplete).toEqual([{
        dimensionKind: "client_hmac",
        ruleId: "pgid.logout.delivery_health.v1",
      }]);
      expect(globalObservation(result)?.current.currentUnresolved).toBe(2);
      expect(result.observations).toHaveLength(1);
      expect(JSON.stringify(result)).not.toContain(firstRawClient);
      expect(JSON.stringify(result)).not.toContain(secondRawClient);
    } finally {
      sign.mockRestore();
    }
  });

  it("enforces type, safe-integer, timestamp, ratio, and nesting contracts", async () => {
    const asOf = "2035-07-01T12:00:00.000Z";
    const currentVariants = [
      { ...emptyCurrentRow(), current_unresolved: "1" },
      { ...emptyCurrentRow(), current_unresolved: 1.5 },
      { ...emptyCurrentRow(), current_unresolved: -1 },
      { ...emptyCurrentRow(), current_unresolved: 1_000_000_001 },
      {
        ...emptyCurrentRow(),
        current_unresolved: 1,
        oldest_unresolved_created_at: "not-a-time",
        newest_unresolved_created_at: "not-a-time",
        invalid_created_at_count: 1,
      },
    ];
    for (const row of currentVariants) {
      const database = transformBatchDatabase((results) =>
        replaceResultRows(
          results,
          ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
          [row],
        )
      );
      const result = await read(asOf, { database });
      expect(result.incomplete).toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });
      expect(globalObservation(result)).toBeUndefined();
    }

    const timestamp = at(asOf, -600_000);
    const invalidDelivery = {
      ...emptyDeliveryRow(),
      eligible_5m: 1,
      unresolved_5m: 1,
      eligible_15m: 1,
      unresolved_15m: 1,
      eligible_60m: 1,
      unresolved_60m: 1,
      oldest_created_at: timestamp,
      newest_created_at: timestamp,
    };
    const inconsistentWindow = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal,
        [invalidDelivery],
      )
    );
    expect((await read(asOf, { database: inconsistentWindow })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });

    const overRatio = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal,
        [{
          ...emptyDeliveryRow(),
          eligible_5m: 1_000_001,
          eligible_15m: 1_000_001,
          eligible_60m: 1_000_001,
          oldest_created_at: at(asOf, -1),
          newest_created_at: at(asOf, -1),
        }],
      )
    );
    expect((await read(asOf, { database: overRatio })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });

    const invalidLease = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.leaseGlobal,
        [{
          ...emptyLeaseRow(),
          lease_expired_5m: 2,
          lease_expired_15m: 1,
          lease_expired_60m: 2,
          oldest_completed_at: at(asOf, -1),
          newest_completed_at: at(asOf, -1),
        }],
      )
    );
    expect((await read(asOf, { database: invalidLease })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });
  });

  it("accepts exact persistence caps and rejects non-finite or contradictory projections", async () => {
    const asOf = "2035-07-10T12:00:00.000Z";
    const timestamp = at(asOf, -1);
    const acceptedCaps = transformBatchDatabase((results) => {
      let transformed = replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
        [{
          current_unresolved: 1_000_000_000,
          current_dead: 1_000_000_000,
          oldest_unresolved_created_at: timestamp,
          newest_unresolved_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
      transformed = replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal,
        [{
          eligible_5m: 1_000_000,
          unresolved_5m: 1_000_000,
          eligible_15m: 1_000_000,
          unresolved_15m: 1_000_000,
          eligible_60m: 1_000_000,
          unresolved_60m: 1_000_000,
          oldest_created_at: timestamp,
          newest_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
      return replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.leaseGlobal,
        [{
          lease_expired_5m: 1_000_000_000,
          lease_expired_15m: 1_000_000_000,
          lease_expired_60m: 1_000_000_000,
          oldest_completed_at: timestamp,
          newest_completed_at: timestamp,
          invalid_completed_at_count: 0,
        }],
      );
    });
    const accepted = await read(asOf, {
      database: acceptedCaps,
      key: null,
    });
    expect(accepted.incomplete).toEqual([{
      dimensionKind: "client_hmac",
      ruleId: "pgid.logout.delivery_health.v1",
    }]);
    expect(globalObservation(accepted)).toMatchObject({
      current: {
        currentDead: 1_000_000_000,
        currentUnresolved: 1_000_000_000,
      },
      windows: {
        "5m": {
          eligible: 1_000_000,
          leaseExpired: 1_000_000_000,
          unresolved: 1_000_000,
        },
      },
    });

    for (const currentUnresolved of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const database = transformBatchDatabase((results) =>
        replaceResultRows(
          results,
          ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
          [{ ...emptyCurrentRow(), current_unresolved: currentUnresolved }],
        )
      );
      expect((await read(asOf, { database })).incomplete).toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });
    }

    const contradictoryCurrent = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
        [{
          current_unresolved: 1,
          current_dead: 2,
          oldest_unresolved_created_at: timestamp,
          newest_unresolved_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      )
    );
    expect((await read(asOf, { database: contradictoryCurrent })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });

    const contradictoryDelivery = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal,
        [{
          eligible_5m: 1,
          unresolved_5m: 2,
          eligible_15m: 1,
          unresolved_15m: 2,
          eligible_60m: 1,
          unresolved_60m: 2,
          oldest_created_at: timestamp,
          newest_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      )
    );
    expect((await read(asOf, { database: contradictoryDelivery })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });

    const extraKey = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
        [{ ...emptyCurrentRow(), unexpected: "fixed-private-marker" }],
      )
    );
    expect((await read(asOf, { database: extraKey })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      });
  });

  it("detects pre-0020 malformed timestamps even when lexical windows hide them", async () => {
    const asOf = "2035-07-15T12:00:00.000Z";
    const triggerNames = [
      "logout_delivery_created_at_insert_guard",
      "logout_delivery_created_at_update_guard",
      "logout_delivery_attempt_completed_at_insert_guard",
      "logout_delivery_attempt_completed_at_update_guard",
    ] as const;
    const triggerRows = await env.PG72_ID_DB.prepare(
      `SELECT name, sql FROM sqlite_schema
        WHERE type = 'trigger'
          AND name IN (?, ?, ?, ?)
        ORDER BY name`,
    )
      .bind(...triggerNames)
      .all<{ name: string; sql: string }>();
    expect(triggerRows.results).toHaveLength(4);
    for (const name of triggerNames) {
      await env.PG72_ID_DB.prepare(`DROP TRIGGER "${name}"`).run();
    }
    try {
      const farLow = "0000-malformed-far-low";
      const farHigh = "zzzz-malformed-far-high";
      const offsetEscape = "2035-07-15T11:59:59+00:00";
      await insertDelivery({
        clientId: "malformed-delivery-low-client",
        createdAt: farLow,
        status: "pending",
      });
      await insertDelivery({
        clientId: "malformed-delivery-high-client",
        createdAt: farHigh,
        status: "dead",
      });
      await insertDelivery({
        clientId: "malformed-delivery-offset-client",
        createdAt: offsetEscape,
        status: "retry",
      });
      const deliveryId = await insertDelivery({
        clientId: "malformed-attempt-timestamp-client",
        createdAt: at(asOf, -1_000),
        status: "delivered",
      });
      await insertAttempt(deliveryId, "lease_expired", at(asOf, -500), 1);
      await env.PG72_ID_DB.prepare(
        "UPDATE logout_delivery_attempt SET completed_at = ? WHERE delivery_id = ?",
      )
        .bind(42, deliveryId)
        .run();

      const integrity = await env.PG72_ID_DB.prepare(
        ALERT_LOGOUT_TIMESTAMP_INTEGRITY_QUERY,
      ).first<Record<string, unknown>>();
      expect(integrity).toEqual({
        invalid_attempt_timestamp_present: 1,
        invalid_delivery_timestamp_present: 1,
      });
      const malformed = await read(asOf);
      expect(malformed.incomplete).toEqual([
        {
          dimensionKind: "global",
          ruleId: "pgid.logout.delivery_health.v1",
        },
        {
          dimensionKind: "client_hmac",
          ruleId: "pgid.logout.delivery_health.v1",
        },
      ]);
      expect(malformed.observations).toEqual([]);
      expect(JSON.stringify(malformed)).not.toContain(farLow);
      expect(JSON.stringify(malformed)).not.toContain(farHigh);
      expect(JSON.stringify(malformed)).not.toContain(offsetEscape);
    } finally {
      await env.PG72_ID_DB.batch([
        env.PG72_ID_DB.prepare("DELETE FROM logout_delivery"),
        env.PG72_ID_DB.prepare(
          "DELETE FROM audit_event WHERE event_type = ?",
        ).bind(TEST_EVENT_TYPE),
      ]);
      for (const trigger of triggerRows.results) {
        await env.PG72_ID_DB.prepare(trigger.sql).run();
      }
    }
  });

  it("rejects future noncanonical delivery and attempt timestamps", async () => {
    const asOf = "2035-07-16T12:00:00.000Z";
    for (const [index, createdAt] of [
      "not-a-time",
      "2035-07-16T11:59:59+00:00",
      "2035-02-30T00:00:00.000Z",
    ].entries()) {
      await expect(insertDelivery({
        clientId: `guarded-invalid-delivery-client-${index}`,
        createdAt,
        status: "pending",
      })).rejects.toThrow("created_at must be canonical");
    }
    const deliveryId = await insertDelivery({
      clientId: "guarded-invalid-attempt-client",
      createdAt: at(asOf, -1_000),
      status: "delivered",
    });
    await expect(env.PG72_ID_DB.prepare(
      "UPDATE logout_delivery SET created_at = ? WHERE id = ?",
    )
      .bind(42, deliveryId)
      .run()).rejects.toThrow("created_at must be canonical");
    await expect(env.PG72_ID_DB.prepare(
      "UPDATE logout_delivery SET created_at = ? WHERE id = ?",
    )
      .bind("2035-07-16T11:59:59+00:00", deliveryId)
      .run()).rejects.toThrow("created_at must be canonical");
    await expect(env.PG72_ID_DB.prepare(
      `INSERT INTO logout_delivery_attempt
        (id, delivery_id, replay_count, attempt_number, lease_id, outcome,
         resulting_status, http_status, error_code, started_at, completed_at)
       VALUES (?, ?, 0, 1, ?, 'lease_expired', 'retry', NULL,
               'lease_expired', ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        deliveryId,
        crypto.randomUUID(),
        at(asOf, -1_000),
        "2035-07-16T11:59:59+00:00",
    )
      .run()).rejects.toThrow("completed_at must be canonical");
    await insertAttempt(deliveryId, "in_flight", null, 1);
    await insertAttempt(deliveryId, "lease_expired", at(asOf, -500), 2);
    await expect(env.PG72_ID_DB.prepare(
      `UPDATE logout_delivery_attempt
          SET outcome = 'lease_expired', resulting_status = 'retry',
              error_code = 'lease_expired', completed_at = ?
        WHERE delivery_id = ? AND outcome = 'in_flight'`,
    )
      .bind(at(asOf, -250), deliveryId)
      .run()).resolves.toMatchObject({ success: true });
    await expect(env.PG72_ID_DB.prepare(
      "UPDATE logout_delivery_attempt SET completed_at = ? WHERE delivery_id = ?",
    )
      .bind(42, deliveryId)
      .run()).rejects.toThrow("completed_at must be canonical");
  });

  it("fails closed when complete client projections cannot reconstruct global evidence", async () => {
    const asOf = "2035-08-01T12:00:00.000Z";
    const clientId = "logout-reconciliation-client";
    await insertDelivery({
      clientId,
      createdAt: at(asOf, -1_000),
      status: "pending",
    });
    const contradictory = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient,
        [],
      )
    );
    const result = await read(asOf, { database: contradictory });
    expect(result.incomplete).toEqual([
      {
        dimensionKind: "global",
        ruleId: "pgid.logout.delivery_health.v1",
      },
      {
        dimensionKind: "client_hmac",
        ruleId: "pgid.logout.delivery_health.v1",
      },
    ]);
    expect(result.observations).toEqual([]);

    const contradictoryFiveMinute = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryClient,
        [{
          client_id: clientId,
          ...emptyDeliveryRow(),
        }],
      )
    );
    expect((await read(asOf, { database: contradictoryFiveMinute })).incomplete)
      .toEqual([{
        dimensionKind: "client_hmac",
        ruleId: "pgid.logout.delivery_health.v1",
      }]);
  });

  it("bounds tracked and source groups before deriving client references", async () => {
    const asOf = "2035-09-01T12:00:00.000Z";
    const trackedOverflow = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.tracked,
        Array.from({ length: 1_001 }, () => ({})),
      )
    );
    const trackedResult = await read(asOf, { database: trackedOverflow });
    expect(trackedResult.incomplete).toEqual([{
      dimensionKind: "client_hmac",
      ruleId: "pgid.logout.delivery_health.v1",
    }]);
    expect(globalObservation(trackedResult)).toBeDefined();

    const sourceOverflow = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient,
        Array.from({ length: 1_001 }, () => ({})),
      )
    );
    const sourceResult = await read(asOf, { database: sourceOverflow });
    expect(sourceResult.incomplete).toEqual(trackedResult.incomplete);
    expect(globalObservation(sourceResult)).toBeDefined();
  });

  it("accepts 1000 client groups and rejects a 1001-client cross-query union", async () => {
    const asOf = "2035-09-15T12:00:00.000Z";
    const timestamp = at(asOf, -1_000);
    const currentRows = Array.from({ length: 1_000 }, (_, index) => ({
      client_id: `bounded-client-${String(index).padStart(4, "0")}`,
      current_unresolved: 1,
      current_dead: 0,
      oldest_unresolved_created_at: timestamp,
      newest_unresolved_created_at: timestamp,
      invalid_created_at_count: 0,
    }));
    const withCurrentGroups = (results: D1Result<Record<string, unknown>>[]) => {
      let transformed = replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentGlobal,
        [{
          current_unresolved: 1_000,
          current_dead: 0,
          oldest_unresolved_created_at: timestamp,
          newest_unresolved_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
      return replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient,
        currentRows,
      );
    };
    const atCap = await read(asOf, {
      database: transformBatchDatabase(withCurrentGroups),
    });
    expect(atCap.incomplete).toEqual([]);
    expect(atCap.observations).toHaveLength(1_001);

    const unionOverflow = transformBatchDatabase((results) => {
      let transformed = withCurrentGroups(results);
      transformed = replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryGlobal,
        [{
          eligible_5m: 1,
          unresolved_5m: 0,
          eligible_15m: 1,
          unresolved_15m: 0,
          eligible_60m: 1,
          unresolved_60m: 0,
          oldest_created_at: timestamp,
          newest_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
      return replaceResultRows(
        transformed,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.deliveryClient,
        [{
          client_id: "bounded-union-overflow-client",
          eligible_5m: 1,
          unresolved_5m: 0,
          eligible_15m: 1,
          unresolved_15m: 0,
          eligible_60m: 1,
          unresolved_60m: 0,
          oldest_created_at: timestamp,
          newest_created_at: timestamp,
          invalid_created_at_count: 0,
        }],
      );
    });
    const overflow = await read(asOf, { database: unionOverflow });
    expect(overflow.incomplete).toEqual([{
      dimensionKind: "client_hmac",
      ruleId: "pgid.logout.delivery_health.v1",
    }]);
    expect(globalObservation(overflow)).toBeDefined();
    expect(overflow.observations).toHaveLength(1);
  });

  it("turns malformed client rows into client-only incomplete evidence", async () => {
    const asOf = "2035-10-01T12:00:00.000Z";
    const rawMarker = "raw-client-row-must-not-leak";
    const corruptClient = transformBatchDatabase((results) =>
      replaceResultRows(
        results,
        ALERT_LOGOUT_SOURCE_RESULT_INDEX.currentClient,
        [{
          client_id: rawMarker,
          ...emptyCurrentRow(),
          current_unresolved: "1",
        }],
      )
    );
    const result = await read(asOf, { database: corruptClient });
    expect(result.incomplete).toEqual([{
      dimensionKind: "client_hmac",
      ruleId: "pgid.logout.delivery_health.v1",
    }]);
    expect(globalObservation(result)).toBeDefined();
    expect(JSON.stringify(result)).not.toContain(rawMarker);
  });

  it("pins every query to the reviewed covering or partial index", async () => {
    const asOf = "2035-11-01T12:00:00.000Z";
    const bindings = [
      at(asOf, -300_000),
      at(asOf, -900_000),
      at(asOf, -3_600_000),
      asOf,
    ] as const;
    const plans = await Promise.all([
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_CURRENT_GLOBAL_QUERY}`,
      ).bind(asOf).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_CURRENT_CLIENT_QUERY}`,
      ).bind(asOf).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_DELIVERY_GLOBAL_QUERY}`,
      ).bind(...bindings).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_DELIVERY_CLIENT_QUERY}`,
      ).bind(...bindings).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_LEASE_GLOBAL_QUERY}`,
      ).bind(...bindings).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_LEASE_CLIENT_QUERY}`,
      ).bind(...bindings).all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_TRACKED_DIMENSIONS_QUERY}`,
      ).bind("local").all<{ detail: string }>(),
      env.PG72_ID_DB.prepare(
        `EXPLAIN QUERY PLAN ${ALERT_LOGOUT_TIMESTAMP_INTEGRITY_QUERY}`,
      ).all<{ detail: string }>(),
    ]);
    const details = plans.map((plan) =>
      plan.results.map(({ detail }) => detail).join("\n")
    );
    for (const detail of details.slice(0, 2)) {
      expect(detail).toContain(
        "logout_delivery_status_client_time_bounded_idx",
      );
      expect(detail).toMatch(/SEARCH logout_delivery\b/);
    }
    for (const detail of details.slice(2, 4)) {
      expect(detail).toContain(
        "logout_delivery_time_client_status_bounded_idx",
      );
      expect(detail).toMatch(/SEARCH logout_delivery\b/);
    }
    for (const detail of details.slice(4, 6)) {
      expect(detail).toContain(
        "logout_delivery_attempt_completion_bounded_idx",
      );
      expect(detail).toMatch(/SEARCH attempt\b/);
    }
    expect(details[6]).toContain("alert_state_tracked_evaluation_idx");
    expect(details[6]).toMatch(/SEARCH alert_state\b/);
    expect(details[7]).toContain(
      "SCAN logout_delivery USING COVERING INDEX logout_delivery_invalid_created_at_bounded_idx",
    );
    expect(details[7]).toContain(
      "SEARCH attempt USING COVERING INDEX logout_delivery_attempt_invalid_completed_at_bounded_idx",
    );
    expect(details[7]).not.toContain(
      "logout_delivery_time_client_status_bounded_idx",
    );
    expect(details[7]).not.toContain(
      "logout_delivery_attempt_completion_bounded_idx",
    );
  });

  it("redacts failures, output, and exact input errors", async () => {
    const asOf = "2035-12-01T12:00:00.000Z";
    const rawClient = "private-client-id-never-output";
    await insertDelivery({
      clientId: rawClient,
      createdAt: at(asOf, -1_000),
      status: "dead",
    });
    const result = await read(asOf);
    const serialized = JSON.stringify(result);
    for (const marker of [
      rawClient,
      "sensitive-rp.example.test",
      "sensitive-sid",
      "sensitive-jti",
      "sensitive-user",
      "sensitive-terminal-detail",
    ]) {
      expect(serialized).not.toContain(marker);
    }

    const unavailable = read(asOf, { database: failingBatchDatabase() });
    await expect(unavailable).rejects.toEqual(
      new AlertLogoutSourceRepositoryError("source_unavailable"),
    );
    for (const marker of [
      "private.example.test",
      "token",
      "jti",
      "sid",
      "client-id",
      "metadata",
      "user@example.test",
    ]) {
      await expect(unavailable).rejects.not.toThrow(marker);
    }

    await expect(readLogoutDeliveryAlertSource(env.PG72_ID_DB, {
      asOf: "not-a-time",
      environment: "local",
      hmacKeyBase64Url: TEST_HMAC_KEY,
    })).rejects.toEqual(new AlertLogoutSourceRepositoryError("invalid_input"));
    await expect(readLogoutDeliveryAlertSource(env.PG72_ID_DB, {
      asOf,
      environment: "invalid" as "local",
      hmacKeyBase64Url: TEST_HMAC_KEY,
    })).rejects.toEqual(new AlertLogoutSourceRepositoryError("invalid_input"));

    const wrongBatchShape = transformBatchDatabase((results) =>
      results.slice(0, -1)
    );
    await expect(read(asOf, { database: wrongBatchShape })).rejects.toEqual(
      new AlertLogoutSourceRepositoryError("source_invalid"),
    );
  });
});
