import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY,
  ALERT_HASH_KEY_SENTINEL_DOMAIN,
  AlertAuditSourceRepositoryError,
  deriveAlertHashKeyFingerprintV1,
  readAuditAlertSources,
  type AuditAlertSourceResult,
} from "../worker/alert-audit-source-repository";
import {
  deriveAlertReferenceV1,
  type AlertRuleObservation,
} from "../worker/alert-rules";
import { createAuthenticatedUser } from "./helpers";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

const TEST_HMAC_KEY = base64Url(
  Uint8Array.from({ length: 32 }, (_, index) => index + 1),
);
const EXPECTED_SENTINEL_FINGERPRINT = base64Url(Uint8Array.from([
  251, 226, 66, 7, 204, 81, 50, 72,
  255, 114, 63, 77, 201, 216, 2, 61,
  10, 84, 157, 246, 79, 36, 220, 95,
  236, 11, 135, 139, 64, 113, 44, 211,
]));

interface InsertAuditInput {
  actorRef?: string | null;
  actorRefHashVersion?: number | null;
  actorUserId?: string | null;
  eventType: string;
  id?: string;
  metadata?: Record<string, string | number | boolean> | null;
  occurredAt: string;
  outcome: "denied" | "failure" | "success";
  subjectId?: string | null;
}

async function insertAudit(input: InsertAuditInput): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, subject_id, outcome, metadata_json,
       occurred_at, actor_ref, actor_ref_hash_version)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      input.id ?? crypto.randomUUID(),
      input.eventType,
      input.actorUserId ?? null,
      input.subjectId ?? null,
      input.outcome,
      input.metadata === undefined || input.metadata === null
        ? null
        : JSON.stringify(input.metadata),
      input.occurredAt,
      input.actorRef ?? null,
      input.actorRefHashVersion ?? null,
    )
    .run();
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
): Promise<AuditAlertSourceResult> {
  return readAuditAlertSources(options.database ?? env.PG72_ID_DB, {
    asOf,
    environment: options.environment ?? "local",
    hmacKeyBase64Url: options.key === undefined ? TEST_HMAC_KEY : options.key,
  });
}

function observation(
  result: AuditAlertSourceResult,
  ruleId: AlertRuleObservation["ruleId"],
  dimensionKind: AlertRuleObservation["dimension"]["kind"],
): AlertRuleObservation | undefined {
  return result.observations.find((candidate) =>
    candidate.ruleId === ruleId && candidate.dimension.kind === dimensionKind
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
          transform(
            await target.batch<Record<string, unknown>>(statements),
          );
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function failingBatchDatabase(): D1Database {
  return new Proxy(env.PG72_ID_DB, {
    get(target, property) {
      if (property === "batch") {
        return async () => {
          throw new Error("database failure included raw-identity-forbidden");
        };
      }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function replaceSentinel(
  results: D1Result<Record<string, unknown>>[],
  replacement: readonly Record<string, unknown>[],
): D1Result<Record<string, unknown>>[] {
  return results.map((result) => {
    const row = result.results[0];
    if (
      row &&
      Object.hasOwn(row, "domain") &&
      Object.hasOwn(row, "fingerprint_ref")
    ) {
      return { ...result, results: [...replacement] };
    }
    return result;
  });
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
      "2026-07-18T00:00:00.000Z",
    )
    .run();
});

describe.sequential("audit alert source repository", () => {
  it("pins the independent key-sentinel vector and fails closed on continuity gaps", async () => {
    const fingerprint = await deriveAlertHashKeyFingerprintV1(TEST_HMAC_KEY);
    expect(fingerprint).toEqual({
      keyVersion: 1,
      value: EXPECTED_SENTINEL_FINGERPRINT,
    });

    const raw = "domain-separation-vector";
    const references = await Promise.all([
      deriveAlertReferenceV1(TEST_HMAC_KEY, "subject_hmac", raw),
      deriveAlertReferenceV1(TEST_HMAC_KEY, "actor_hmac", raw),
      deriveAlertReferenceV1(TEST_HMAC_KEY, "client_hmac", raw),
      deriveAlertReferenceV1(TEST_HMAC_KEY, "reporter_hmac", raw),
    ]);
    expect(new Set([
      fingerprint.value,
      ...references.map(({ value }) => value),
    ]).size).toBe(5);

    const asOf = "2030-01-01T01:00:00.000Z";
    expect((await read(asOf)).incomplete).toEqual([]);

    const expectedHashedIncomplete = [
      "pgid.restricted.sensitive_denied.v1",
      "pgid.recovery.passkey_failure.v1",
      "pgid.passkey.step_up_failure.v1",
      "pgid.admin.sensitive_activity.v1",
      "pgid.admin.directory_volume.v1",
    ];
    expect((await read(asOf, { key: null })).incomplete.map(({ ruleId }) => ruleId))
      .toEqual(expectedHashedIncomplete);
    const wrongKey = base64Url(new Uint8Array(32).fill(42));
    expect((await read(asOf, { key: wrongKey })).incomplete.map(({ ruleId }) => ruleId))
      .toEqual(expectedHashedIncomplete);

    const missingSentinel = transformBatchDatabase((results) =>
      replaceSentinel(results, [])
    );
    expect(
      (await read(asOf, { database: missingSentinel })).incomplete.map(
        ({ ruleId }) => ruleId,
      ),
    ).toEqual(expectedHashedIncomplete);

    const wrongDomain = transformBatchDatabase((results) =>
      replaceSentinel(results, [{
        domain: "pgid.wrong-domain.v1",
        fingerprint_ref: fingerprint.value,
        hash_version: 1,
      }])
    );
    await expect(read(asOf, { database: wrongDomain })).rejects.toEqual(
      new AlertAuditSourceRepositoryError("source_invalid"),
    );

    const corruptSentinel = transformBatchDatabase((results) =>
      replaceSentinel(results, [{
        domain: ALERT_HASH_KEY_SENTINEL_DOMAIN,
        fingerprint_ref: "not-a-canonical-reference",
        hash_version: 1,
      }])
    );
    await expect(read(asOf, { database: corruptSentinel })).rejects.toEqual(
      new AlertAuditSourceRepositoryError("source_invalid"),
    );
  });

  it("uses exact half-open windows without summing nested cohorts", async () => {
    const asOf = "2030-01-02T12:00:00.000Z";
    for (const occurredAt of [
      at(asOf, -3_600_000),
      at(asOf, -900_000),
      at(asOf, -300_000),
      at(asOf, -1),
    ]) {
      await insertAudit({
        eventType: "registration.rate_limited",
        occurredAt,
        outcome: "denied",
      });
    }
    await insertAudit({
      eventType: "registration.rate_limited",
      occurredAt: asOf,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "registration.rate_limited",
      occurredAt: at(asOf, -3_600_001),
      outcome: "denied",
    });
    await insertAudit({
      eventType: "registration.rate_limited",
      occurredAt: at(asOf, -1),
      outcome: "success",
    });
    await insertAudit({
      eventType: "registration.rate_limit_other",
      occurredAt: at(asOf, -1),
      outcome: "denied",
    });

    const result = await read(asOf);
    expect(observation(
      result,
      "pgid.registration.rate_limited.v1",
      "global",
    )).toMatchObject({
      windows: {
        "5m": { count: 2 },
        "15m": { count: 3 },
        "60m": { count: 4 },
      },
    });
    expect(observation(
      result,
      "pgid.registration.denied.v1",
      "global",
    )).toMatchObject({
      windows: {
        "5m": { count: 0 },
        "15m": { count: 0 },
        "60m": { count: 0 },
      },
    });
  });

  it("filters exact event, outcome, metadata, and builds all subject/global audit rules", async () => {
    const asOf = "2030-01-03T12:00:00.000Z";
    const within = at(asOf, -60_000);
    await insertAudit({
      eventType: "registration.challenge_unavailable",
      occurredAt: within,
      outcome: "failure",
    });
    await insertAudit({
      eventType: "registration.challenge_denied",
      occurredAt: within,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "registration.intent_created",
      occurredAt: within,
      outcome: "success",
    });
    await insertAudit({
      eventType: "registration.challenge_unavailable",
      occurredAt: within,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "registration.denied",
      occurredAt: within,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "registration.denied",
      occurredAt: within,
      outcome: "failure",
    });
    await insertAudit({
      eventType: "user.created",
      metadata: { accessLevel: "restricted" },
      occurredAt: within,
      outcome: "success",
    });
    await insertAudit({
      eventType: "user.created",
      metadata: { accessLevel: "standard" },
      occurredAt: within,
      outcome: "success",
    });

    const restrictedSubject = "restricted-source-subject";
    for (const surface of ["provider_link", "users.manage"] as const) {
      await insertAudit({
        eventType: "account.restricted_action_denied",
        metadata: { surface },
        occurredAt: within,
        outcome: "denied",
        subjectId: restrictedSubject,
      });
    }
    await insertAudit({
      eventType: "account.restricted_action_denied",
      metadata: { surface: "unreviewed.surface" },
      occurredAt: within,
      outcome: "denied",
      subjectId: restrictedSubject,
    });

    await insertAudit({
      eventType: "recovery.rate_limited",
      occurredAt: within,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "recovery.entry_denied",
      occurredAt: within,
      outcome: "denied",
    });
    await insertAudit({
      eventType: "recovery.started",
      occurredAt: within,
      outcome: "success",
    });

    const recoverySubject = "recovery-source-subject";
    await insertAudit({
      eventType: "recovery.passkey_failed",
      occurredAt: within,
      outcome: "denied",
      subjectId: recoverySubject,
    });
    await insertAudit({
      eventType: "recovery.completed",
      occurredAt: within,
      outcome: "success",
      subjectId: recoverySubject,
    });

    const passkeySubject = "passkey-source-subject";
    await insertAudit({
      eventType: "passkey.step_up_failed",
      occurredAt: within,
      outcome: "denied",
      subjectId: passkeySubject,
    });
    await insertAudit({
      eventType: "passkey.step_up_succeeded",
      occurredAt: within,
      outcome: "success",
      subjectId: passkeySubject,
    });

    const result = await read(asOf);
    expect(result.incomplete).toEqual([]);
    expect(observation(
      result,
      "pgid.registration.denied.v1",
      "global",
    )).toMatchObject({ windows: { "5m": { count: 1 } } });
    expect(observation(
      result,
      "pgid.registration.challenge_unavailable.v1",
      "global",
    )).toMatchObject({
      windows: { "5m": { denominator: 3, numerator: 1 } },
    });
    expect(observation(
      result,
      "pgid.registration.restricted_created.v1",
      "global",
    )).toMatchObject({ windows: { "5m": { count: 1 } } });
    expect(observation(
      result,
      "pgid.restricted.sensitive_denied.v1",
      "subject_hmac",
    )).toMatchObject({
      windows: { "5m": { count: 2, knownSurfaces: 2 } },
    });
    expect(observation(
      result,
      "pgid.recovery.entry_abuse.v1",
      "global",
    )).toMatchObject({
      windows: { "5m": { denied: 1, rateLimited: 1, started: 1 } },
    });
    expect(observation(
      result,
      "pgid.recovery.passkey_failure.v1",
      "global",
    )).toMatchObject({
      windows: { "5m": { denominator: 2, numerator: 1 } },
    });
    expect(observation(
      result,
      "pgid.recovery.passkey_failure.v1",
      "subject_hmac",
    )).toMatchObject({
      windows: { "5m": { denominator: 2, numerator: 1 } },
    });
    expect(observation(
      result,
      "pgid.passkey.step_up_failure.v1",
      "subject_hmac",
    )).toMatchObject({
      windows: { "5m": { denominator: 2, numerator: 1 } },
    });
  });

  it("merges stored actor references with raw fallback and keeps HMAC domains separate", async () => {
    const asOf = "2030-01-04T12:00:00.000Z";
    const actor = await createAuthenticatedUser(
      `alert-actor-${crypto.randomUUID()}@example.test`,
      "admin",
    );
    const actorReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "actor_hmac",
      actor.userId,
    );
    const subjectReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      actor.userId,
    );
    expect(actorReference.value).not.toBe(subjectReference.value);
    const retiredSensitiveEventId = crypto.randomUUID();
    const retiredDirectoryEventId = crypto.randomUUID();

    await insertAudit({
      actorUserId: actor.userId,
      eventType: "invitation.created",
      occurredAt: at(asOf, -120_000),
      outcome: "success",
    });
    await insertAudit({
      actorRef: actorReference.value,
      actorRefHashVersion: 1,
      actorUserId: actor.userId,
      eventType: "oauth_client.updated",
      occurredAt: at(asOf, -90_000),
      outcome: "success",
    });
    await insertAudit({
      actorRef: actorReference.value,
      actorRefHashVersion: 1,
      actorUserId: actor.userId,
      eventType: "user.sessions_revoked",
      id: retiredSensitiveEventId,
      occurredAt: at(asOf, -60_000),
      outcome: "success",
    });
    await insertAudit({
      actorRef: actorReference.value,
      actorRefHashVersion: 1,
      actorUserId: actor.userId,
      eventType: "user.suspended",
      metadata: { reason: "bootadmin_protected" },
      occurredAt: at(asOf, -30_000),
      outcome: "denied",
    });
    await insertAudit({
      actorUserId: actor.userId,
      eventType: "admin.users_listed",
      occurredAt: at(asOf, -120_000),
      outcome: "success",
    });
    await insertAudit({
      actorRef: actorReference.value,
      actorRefHashVersion: 1,
      actorUserId: actor.userId,
      eventType: "admin.users_listed",
      id: retiredDirectoryEventId,
      occurredAt: at(asOf, -60_000),
      outcome: "success",
    });
    await env.PG72_ID_DB.prepare(
      "UPDATE audit_event SET actor_user_id = NULL WHERE id IN (?, ?)",
    )
      .bind(retiredSensitiveEventId, retiredDirectoryEventId)
      .run();
    await insertAudit({
      eventType: "passkey.step_up_failed",
      occurredAt: at(asOf, -60_000),
      outcome: "denied",
      subjectId: actor.userId,
    });

    const result = await read(asOf);
    const sensitive = observation(
      result,
      "pgid.admin.sensitive_activity.v1",
      "actor_hmac",
    );
    expect(sensitive).toMatchObject({
      dimension: { reference: actorReference },
      windows: { "5m": { protectedDenials: 1, successes: 3 } },
    });
    expect(observation(
      result,
      "pgid.admin.directory_volume.v1",
      "actor_hmac",
    )).toMatchObject({
      dimension: { reference: actorReference },
      windows: { "5m": { count: 2 } },
    });
    expect(observation(
      result,
      "pgid.passkey.step_up_failure.v1",
      "subject_hmac",
    )).toMatchObject({
      dimension: { reference: subjectReference },
    });
    expect(JSON.stringify(result)).not.toContain(actor.userId);
  });

  it("keeps a global cohort usable while a mixed subject cohort is incomplete", async () => {
    const asOf = "2030-01-05T00:00:00.000Z";
    await insertAudit({
      eventType: "passkey.step_up_failed",
      occurredAt: at(asOf, -60_000),
      outcome: "denied",
      subjectId: "known-step-up-subject",
    });
    await insertAudit({
      eventType: "passkey.step_up_failed",
      occurredAt: at(asOf, -30_000),
      outcome: "denied",
    });

    const result = await read(asOf);
    expect(result.incomplete).toContainEqual({
      dimensionKind: "subject_hmac",
      ruleId: "pgid.passkey.step_up_failure.v1",
    });
    expect(observation(
      result,
      "pgid.passkey.step_up_failure.v1",
      "global",
    )).toMatchObject({
      windows: { "5m": { denominator: 2, numerator: 2 } },
    });
    expect(observation(
      result,
      "pgid.passkey.step_up_failure.v1",
      "subject_hmac",
    )).toBeUndefined();
  });

  it("marks missing actor correlation incomplete and rejects mismatched stored provenance", async () => {
    const asOf = "2030-01-05T12:00:00.000Z";
    await insertAudit({
      eventType: "admin.users_listed",
      occurredAt: at(asOf, -30_000),
      outcome: "success",
    });
    const incomplete = await read(asOf);
    expect(incomplete.incomplete).toContainEqual({
      dimensionKind: "actor_hmac",
      ruleId: "pgid.admin.directory_volume.v1",
    });
    expect(observation(
      incomplete,
      "pgid.admin.directory_volume.v1",
      "actor_hmac",
    )).toBeUndefined();

    const actor = await createAuthenticatedUser(
      `alert-corrupt-${crypto.randomUUID()}@example.test`,
      "admin",
    );
    const wrongReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "actor_hmac",
      "different-raw-actor",
    );
    await insertAudit({
      actorRef: wrongReference.value,
      actorRefHashVersion: 1,
      actorUserId: actor.userId,
      eventType: "invitation.created",
      occurredAt: at(asOf, -20_000),
      outcome: "success",
    });
    await expect(read(asOf)).rejects.toEqual(
      new AlertAuditSourceRepositoryError("source_invalid"),
    );
    await expect(read(asOf)).rejects.not.toThrow(actor.userId);
  });

  it("zero-fills only repository-tracked hashed identities", async () => {
    const asOf = "2030-01-06T12:00:00.000Z";
    const trackedReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      "tracked-restricted-subject",
    );
    const dedupeReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      "tracked-restricted-dedupe",
    );
    const completeReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      "complete-restricted-subject",
    );
    const completeDedupeReference = await deriveAlertReferenceV1(
      TEST_HMAC_KEY,
      "subject_hmac",
      "complete-restricted-dedupe",
    );
    const stateId = crypto.randomUUID();
    const completeStateId = crypto.randomUUID();
    const insertTrackedState = (
      id: string,
      dedupeKey: string,
      subjectRef: string,
    ) => env.PG72_ID_DB.prepare(
      `INSERT INTO alert_state
        (id, rule_id, environment, source_kind, dedupe_key, subject_ref,
         hash_version, provider, queue_name, reason, surface,
         window_seconds, metric_name, metric_kind, metric_unit, observed_value,
         observed_numerator, observed_denominator, minimum_sample_count,
         minimum_numerator_count, warning_threshold, critical_threshold,
         secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
         secondary_observed_value, secondary_threshold,
         consecutive_breaches, breach_severity, consecutive_clears,
         current_severity, generation, revision, cooldown_until,
         last_notification_scheduled_at, last_evaluated_at, created_at,
         updated_at)
       VALUES (?, 'pgid.restricted.sensitive_denied.v1', 'preview', 'd1_exact',
               ?, ?, 1, NULL, NULL, NULL, NULL,
               900, 'count', 'count', 'events', 5,
               NULL, NULL, 0, NULL, 5, NULL,
               NULL, NULL, NULL, NULL, NULL,
               1, 'warning', 0, 'none', 0, 0, NULL,
               NULL, ?, ?, ?)`,
    )
      .bind(
        id,
        dedupeKey,
        subjectRef,
        at(asOf, -86_400_000),
        at(asOf, -86_400_000),
        at(asOf, -86_400_000),
      )
      .run();
    await insertTrackedState(
      stateId,
      dedupeReference.value,
      trackedReference.value,
    );
    await insertTrackedState(
      completeStateId,
      completeDedupeReference.value,
      completeReference.value,
    );
    await env.PG72_ID_DB.prepare(
      `UPDATE alert_state
          SET consecutive_breaches = 0, breach_severity = NULL,
              revision = 1, last_evaluated_at = ?, updated_at = ?
        WHERE id = ?`,
    )
      .bind(
        at(asOf, -86_399_000),
        at(asOf, -86_399_000),
        completeStateId,
      )
      .run();

    const result = await read(asOf, { environment: "preview" });
    expect(observation(
      result,
      "pgid.restricted.sensitive_denied.v1",
      "subject_hmac",
    )).toEqual({
      asOf,
      dimension: {
        kind: "subject_hmac",
        reference: trackedReference,
      },
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: {
        "5m": { count: 0, knownSurfaces: 0 },
        "15m": { count: 0, knownSurfaces: 0 },
        "60m": { count: 0, knownSurfaces: 0 },
      },
    });
    expect(JSON.stringify(result)).not.toContain(completeReference.value);
    await env.PG72_ID_DB.prepare(
      "DELETE FROM alert_state WHERE id IN (?, ?)",
    )
      .bind(stateId, completeStateId)
      .run();
  });

  it("bounds ongoing tracked-state reads before compound materialization", async () => {
    expect(ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY).not.toMatch(/row_number/i);
    expect(
      ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY.match(/LIMIT 1001/g),
    ).toHaveLength(5);
    const plan = await env.PG72_ID_DB.prepare(
      `EXPLAIN QUERY PLAN ${ALERT_AUDIT_TRACKED_DIMENSIONS_QUERY}`,
    )
      .bind("production")
      .all<{ detail: string }>();
    const planDetails = plan.results.map(({ detail }) => detail).join("\n");
    expect(
      planDetails.match(/USING INDEX alert_state_tracked_evaluation_idx/g),
    ).toHaveLength(5);
    expect(planDetails).not.toMatch(/\bSCAN alert_state\b/);

    const asOf = "2030-01-06T13:00:00.000Z";
    await env.PG72_ID_DB.prepare(
      `WITH RECURSIVE sequence(value) AS (
         VALUES (1)
         UNION ALL
         SELECT value + 1 FROM sequence WHERE value < 1001
       )
       INSERT INTO alert_state
        (id, rule_id, environment, source_kind, dedupe_key, subject_ref,
         hash_version, provider, queue_name, reason, surface,
         window_seconds, metric_name, metric_kind, metric_unit, observed_value,
         observed_numerator, observed_denominator, minimum_sample_count,
         minimum_numerator_count, warning_threshold, critical_threshold,
         secondary_metric_name, secondary_metric_kind, secondary_metric_unit,
         secondary_observed_value, secondary_threshold,
         consecutive_breaches, breach_severity, consecutive_clears,
         current_severity, generation, revision, cooldown_until,
         last_notification_scheduled_at, last_evaluated_at, created_at,
         updated_at)
       SELECT printf('10000000-0000-4000-8000-%012d', value),
              'pgid.restricted.sensitive_denied.v1', 'production', 'd1_exact',
              printf('%042dA', value), printf('%042dE', value),
              1, NULL, NULL, NULL, NULL,
              900, 'count', 'count', 'events', 5,
              NULL, NULL, 0, NULL, 5, NULL,
              NULL, NULL, NULL, NULL, NULL,
              1, 'warning', 0, 'none', 0, 0, NULL,
              NULL, ?, ?, ?
         FROM sequence`,
    )
      .bind(
        at(asOf, -86_400_000),
        at(asOf, -86_400_000),
        at(asOf, -86_400_000),
      )
      .run();
    const result = await read(asOf, { environment: "production" });
    await env.PG72_ID_DB.prepare(
      "DELETE FROM alert_state WHERE environment = 'production'",
    ).run();
    expect(result.incomplete).toContainEqual({
      dimensionKind: "subject_hmac",
      ruleId: "pgid.restricted.sensitive_denied.v1",
    });
    expect(observation(
      result,
      "pgid.restricted.sensitive_denied.v1",
      "subject_hmac",
    )).toBeUndefined();
  });

  it("accepts canonical ratio caps and isolates one oversized cohort", async () => {
    const asOf = "2030-01-07T11:00:00.000Z";
    const replaceChallengeRatio = (value: number) =>
      transformBatchDatabase((results) => {
        let replaced = false;
        return results.map((result) => {
          const row = result.results[0];
          if (
            !replaced && row && Object.hasOwn(row, "numerator_5m") &&
            Object.hasOwn(row, "denominator_5m")
          ) {
            replaced = true;
            return {
              ...result,
              results: [{
                numerator_5m: value,
                denominator_5m: value,
                numerator_15m: value,
                denominator_15m: value,
                numerator_60m: value,
                denominator_60m: value,
              }],
            };
          }
          return result;
        });
      });
    expect(observation(
      await read(asOf, { database: replaceChallengeRatio(1_000_000) }),
      "pgid.registration.challenge_unavailable.v1",
      "global",
    )).toBeDefined();
    const ratioOverflow = await read(asOf, {
      database: replaceChallengeRatio(1_000_001),
    });
    expect(ratioOverflow.incomplete).toContainEqual({
      dimensionKind: "global",
      ruleId: "pgid.registration.challenge_unavailable.v1",
    });
    expect(observation(
      ratioOverflow,
      "pgid.registration.rate_limited.v1",
      "global",
    )).toBeDefined();

    const replaceRecoveryDenied = (value: number) =>
      transformBatchDatabase((results) =>
        results.map((result) => {
          const row = result.results[0];
          if (!row || !Object.hasOwn(row, "denied_5m")) return result;
          return {
            ...result,
            results: [{
              denied_5m: value,
              denied_15m: value,
              denied_60m: value,
              rate_limited_5m: 0,
              rate_limited_15m: 0,
              rate_limited_60m: 0,
              started_5m: 0,
              started_15m: 0,
              started_60m: 0,
            }],
          };
        })
      );
    expect(observation(
      await read(asOf, { database: replaceRecoveryDenied(1_000_000) }),
      "pgid.recovery.entry_abuse.v1",
      "global",
    )).toBeDefined();
    const recoveryOverflow = await read(asOf, {
      database: replaceRecoveryDenied(1_000_001),
    });
    expect(recoveryOverflow.incomplete).toContainEqual({
      dimensionKind: "global",
      ruleId: "pgid.recovery.entry_abuse.v1",
    });
    expect(observation(
      recoveryOverflow,
      "pgid.registration.denied.v1",
      "global",
    )).toBeDefined();
  });

  it("turns count/group overflow into unknown and redacts source failures", async () => {
    const asOf = "2030-01-07T12:00:00.000Z";
    const countOverflow = transformBatchDatabase((results) => {
      let replaced = false;
      return results.map((result) => {
        const row = result.results[0];
        if (
          !replaced &&
          row &&
          Object.keys(row).length === 3 &&
          Object.hasOwn(row, "count_5m") &&
          Object.hasOwn(row, "count_15m") &&
          Object.hasOwn(row, "count_60m")
        ) {
          replaced = true;
          return {
            ...result,
            results: [{
              count_5m: 1_000_000_001,
              count_15m: 1_000_000_001,
              count_60m: 1_000_000_001,
            }],
          };
        }
        return result;
      });
    });
    expect((await read(asOf, { database: countOverflow })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.registration.rate_limited.v1",
      });

    const combinedOverflow = transformBatchDatabase((results) =>
      results.map((result) => {
        const row = result.results[0];
        if (row && Object.hasOwn(row, "denied_5m")) {
          return {
            ...result,
            results: [{
              denied_5m: 600_000,
              denied_15m: 600_000,
              denied_60m: 600_000,
              rate_limited_5m: 0,
              rate_limited_15m: 0,
              rate_limited_60m: 0,
              started_5m: 600_000,
              started_15m: 600_000,
              started_60m: 600_000,
            }],
          };
        }
        return result;
      })
    );
    expect((await read(asOf, { database: combinedOverflow })).incomplete)
      .toContainEqual({
        dimensionKind: "global",
        ruleId: "pgid.recovery.entry_abuse.v1",
      });

    await insertAudit({
      eventType: "account.restricted_action_denied",
      metadata: { surface: "provider_link" },
      occurredAt: at(asOf, -1),
      outcome: "denied",
      subjectId: "group-overflow-seed",
    });
    const groupOverflow = transformBatchDatabase((results) =>
      results.map((result) => {
        const row = result.results[0];
        if (row && Object.hasOwn(row, "surfaces_5m")) {
          return {
            ...result,
            results: Array.from({ length: 1_001 }, (_, index) => ({
              count_5m: 1,
              count_15m: 1,
              count_60m: 1,
              raw_identity: `bounded-group-${index}`,
              surfaces_5m: 1,
              surfaces_15m: 1,
              surfaces_60m: 1,
            })),
          };
        }
        return result;
      })
    );
    const groupResult = await read(asOf, { database: groupOverflow });
    expect(groupResult.incomplete).toContainEqual({
      dimensionKind: "subject_hmac",
      ruleId: "pgid.restricted.sensitive_denied.v1",
    });
    expect(JSON.stringify(groupResult)).not.toContain("bounded-group-");

    const corruptProjection = transformBatchDatabase((results) => {
      let replaced = false;
      return results.map((result) => {
        const row = result.results[0];
        if (!replaced && row && Object.hasOwn(row, "count_5m")) {
          replaced = true;
          return {
            ...result,
            results: [{ ...row, count_5m: "1" }],
          };
        }
        return result;
      });
    });
    await expect(read(asOf, { database: corruptProjection })).rejects.toEqual(
      new AlertAuditSourceRepositoryError("source_invalid"),
    );
    const unavailable = read(asOf, { database: failingBatchDatabase() });
    await expect(unavailable).rejects.toEqual(
      new AlertAuditSourceRepositoryError("source_unavailable"),
    );
    await expect(unavailable).rejects.not.toThrow("raw-identity-forbidden");
  });
});
