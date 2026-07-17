import { describe, expect, it } from "vitest";

import {
  ALERT_RULE_DEFINITIONS,
  ALERT_RULE_IDS,
  alertWindowsAt,
  evaluateAlertRule,
  isHashedAlertReference,
  type AlertRuleObservation,
  type Windowed,
} from "../worker/alert-rules";

const AS_OF = "2026-07-17T12:00:00.000Z";
const GLOBAL = { kind: "global" } as const;
const REFERENCE = { keyVersion: 1, value: "A".repeat(43) } as const;
const SUBJECT = { kind: "subject_hmac", reference: REFERENCE } as const;
const ACTOR = { kind: "actor_hmac", reference: REFERENCE } as const;
const CLIENT = { kind: "client_hmac", reference: REFERENCE } as const;
const QUEUE = { kind: "queue", queue: "logout_deliveries_dlq" } as const;

function windowed<T>(
  five: T,
  fifteen: T = five,
  sixty: T = fifteen,
): Windowed<T> {
  return { "5m": five, "15m": fifteen, "60m": sixty };
}

function severity(observation: AlertRuleObservation) {
  return evaluateAlertRule(observation).severity;
}

describe("canonical alert rule definitions", () => {
  it("keeps the closed 15-rule registry and provenance exact", () => {
    expect(ALERT_RULE_IDS).toHaveLength(15);
    expect(Object.keys(ALERT_RULE_DEFINITIONS)).toEqual([...ALERT_RULE_IDS]);
    for (const id of ALERT_RULE_IDS) {
      const definition = ALERT_RULE_DEFINITIONS[id];
      expect(definition.id).toBe(id);
      expect(Object.keys(definition.thresholds)).toEqual(["5m", "15m", "60m"]);
      expect(definition.provenance).toBe(
        id === "pgid.queue.dlq_approximate.v1"
          ? "queue_approximate"
          : "d1_exact",
      );
    }
  });

  it("builds canonical half-open UTC window descriptors from injected time", () => {
    expect(alertWindowsAt(AS_OF)).toEqual([
      {
        endExclusive: AS_OF,
        key: "5m",
        minutes: 5,
        startInclusive: "2026-07-17T11:55:00.000Z",
      },
      {
        endExclusive: AS_OF,
        key: "15m",
        minutes: 15,
        startInclusive: "2026-07-17T11:45:00.000Z",
      },
      {
        endExclusive: AS_OF,
        key: "60m",
        minutes: 60,
        startInclusive: "2026-07-17T11:00:00.000Z",
      },
    ]);
    expect(() => alertWindowsAt("2026-07-17T12:00:00Z")).toThrow(
      "canonical UTC ISO",
    );
  });

  it("accepts only v1 43-character base64url HMAC references", () => {
    expect(isHashedAlertReference(REFERENCE)).toBe(true);
    expect(isHashedAlertReference({ keyVersion: 0, value: "A".repeat(43) })).toBe(
      false,
    );
    expect(isHashedAlertReference({ keyVersion: 1, value: "raw-user-id" })).toBe(
      false,
    );
    expect(
      isHashedAlertReference({ keyVersion: 1, value: `${"A".repeat(42)}=` }),
    ).toBe(false);

    const rawSubject = {
      asOf: AS_OF,
      dimension: {
        kind: "subject_hmac",
        reference: { keyVersion: 1, value: "raw-user-id" },
      },
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed({ count: 3, knownSurfaces: 1 }),
    } satisfies AlertRuleObservation;
    expect(() => evaluateAlertRule(rawSubject)).toThrow("versioned HMAC");
  });

  it("evaluates every rule at its exact warning boundary", () => {
    const atBoundary: readonly AlertRuleObservation[] = [
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.rate_limited.v1",
        windows: windowed({ count: 5 }, { count: 0 }, { count: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.denied.v1",
        windows: windowed({ count: 10 }, { count: 0 }, { count: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.challenge_unavailable.v1",
        windows: windowed(
          { denominator: 10, numerator: 2 },
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.restricted_created.v1",
        windows: windowed({ count: 7 }, { count: 0 }, { count: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.restricted.sensitive_denied.v1",
        windows: windowed(
          { count: 3, knownSurfaces: 1 },
          { count: 0, knownSurfaces: 0 },
          { count: 0, knownSurfaces: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.recovery.entry_abuse.v1",
        windows: windowed(
          { denied: 5, rateLimited: 0, started: 1 },
          { denied: 0, rateLimited: 0, started: 0 },
          { denied: 0, rateLimited: 0, started: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.recovery.passkey_failure.v1",
        windows: windowed(
          { denominator: 5, numerator: 3 },
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.passkey.step_up_failure.v1",
        windows: windowed(
          { denominator: 10, numerator: 3 },
          { denominator: 0, numerator: 0 },
          { denominator: 0, numerator: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: CLIENT,
        ruleId: "pgid.oauth.client_report.v1",
        windows: windowed(
          { count: 1, distinctReporters: 1, highRiskCount: 1 },
          { count: 0, distinctReporters: 0, highRiskCount: 0 },
          { count: 0, distinctReporters: 0, highRiskCount: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: ACTOR,
        ruleId: "pgid.admin.sensitive_activity.v1",
        windows: windowed(
          { protectedDenials: 0, successes: 1 },
          { protectedDenials: 0, successes: 0 },
          { protectedDenials: 0, successes: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: ACTOR,
        ruleId: "pgid.admin.directory_volume.v1",
        windows: windowed({ count: 20 }, { count: 0 }, { count: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.security.fanout_gap.v1",
        windows: windowed(
          { missing: 1, oldestMissingAgeSeconds: 300 },
          { missing: 1, oldestMissingAgeSeconds: 0 },
          { missing: 1, oldestMissingAgeSeconds: 0 },
        ),
      },
      {
        asOf: AS_OF,
        dimension: CLIENT,
        ruleId: "pgid.logout.delivery_health.v1",
        windows: windowed(
          {
            dead: 0,
            eligible: 1,
            leaseExpired: 0,
            oldestUnresolvedAgeSeconds: 120,
            unresolved: 1,
          },
          {
            dead: 0,
            eligible: 1,
            leaseExpired: 0,
            oldestUnresolvedAgeSeconds: null,
            unresolved: 0,
          },
          {
            dead: 0,
            eligible: 1,
            leaseExpired: 0,
            oldestUnresolvedAgeSeconds: null,
            unresolved: 0,
          },
        ),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.alert.runtime_health.v1",
        windows: windowed(
          {
            deadOutbox: 0,
            evaluatorAgeSeconds: 180,
            outboxDueAgeSeconds: null,
          },
          {
            deadOutbox: 0,
            evaluatorAgeSeconds: 0,
            outboxDueAgeSeconds: null,
          },
          {
            deadOutbox: 0,
            evaluatorAgeSeconds: 0,
            outboxDueAgeSeconds: null,
          },
        ),
      },
      {
        asOf: AS_OF,
        dimension: QUEUE,
        ruleId: "pgid.queue.dlq_approximate.v1",
        windows: windowed(
          { depth: 1, nonzeroMinutes: 1 },
          { depth: 0, nonzeroMinutes: 1 },
          { depth: 0, nonzeroMinutes: 1 },
        ),
      },
    ];

    const evaluations = atBoundary.map(evaluateAlertRule);
    expect(evaluations.map(({ severity: result }) => result)).toEqual(
      Array(15).fill("warning"),
    );
    const schemaDomains = {
      age_seconds: "seconds",
      boolean: "state",
      consecutive: "samples",
      count: "events",
      ratio: "basis_points",
    } as const;
    for (const evaluation of evaluations) {
      const selected = evaluation.selectedEvidence;
      expect(selected).not.toBeNull();
      if (selected === null) throw new Error("expected selected evidence");
      expect(selected.provenance).toBe(
        evaluation.ruleId === "pgid.queue.dlq_approximate.v1"
          ? "queue_approximate"
          : "d1_exact",
      );
      for (const component of selected.components) {
        expect(component.unit).toBe(schemaDomains[component.kind]);
        expect(Number.isSafeInteger(component.value)).toBe(true);
        expect(Number.isSafeInteger(component.threshold)).toBe(true);
      }
    }
  });

  it("stays below every warning threshold by one exact unit", () => {
    const belowBoundary: readonly AlertRuleObservation[] = [
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.rate_limited.v1",
        windows: windowed({ count: 4 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.denied.v1",
        windows: windowed({ count: 9 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.challenge_unavailable.v1",
        windows: windowed({ denominator: 5, numerator: 1 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.registration.restricted_created.v1",
        windows: windowed({ count: 6 }),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.restricted.sensitive_denied.v1",
        windows: windowed({ count: 2, knownSurfaces: 1 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.recovery.entry_abuse.v1",
        windows: windowed({ denied: 4, rateLimited: 4, started: 1 }),
      },
      {
        asOf: AS_OF,
        dimension: SUBJECT,
        ruleId: "pgid.recovery.passkey_failure.v1",
        windows: windowed({ denominator: 3, numerator: 2 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.passkey.step_up_failure.v1",
        windows: windowed({ denominator: 10, numerator: 2 }),
      },
      {
        asOf: AS_OF,
        dimension: CLIENT,
        ruleId: "pgid.oauth.client_report.v1",
        windows: windowed({ count: 1, distinctReporters: 1, highRiskCount: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: ACTOR,
        ruleId: "pgid.admin.sensitive_activity.v1",
        windows: windowed({ protectedDenials: 0, successes: 0 }),
      },
      {
        asOf: AS_OF,
        dimension: ACTOR,
        ruleId: "pgid.admin.directory_volume.v1",
        windows: windowed({ count: 19 }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.security.fanout_gap.v1",
        windows: windowed({ missing: 1, oldestMissingAgeSeconds: 299 }),
      },
      {
        asOf: AS_OF,
        dimension: CLIENT,
        ruleId: "pgid.logout.delivery_health.v1",
        windows: windowed({
          dead: 0,
          eligible: 6,
          leaseExpired: 0,
          oldestUnresolvedAgeSeconds: 119,
          unresolved: 1,
        }),
      },
      {
        asOf: AS_OF,
        dimension: GLOBAL,
        ruleId: "pgid.alert.runtime_health.v1",
        windows: windowed({
          deadOutbox: 0,
          evaluatorAgeSeconds: 179,
          outboxDueAgeSeconds: 119,
        }),
      },
      {
        asOf: AS_OF,
        dimension: QUEUE,
        ruleId: "pgid.queue.dlq_approximate.v1",
        windows: windowed({ depth: 0, nonzeroMinutes: 14 }),
      },
    ];

    expect(belowBoundary.map(severity)).toEqual(Array(15).fill("none"));
  });

  it("enforces ratio minimum samples and exact subset invariants", () => {
    const insufficient = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.challenge_unavailable.v1",
      windows: windowed({ denominator: 4, numerator: 4 }),
    } satisfies AlertRuleObservation;
    expect(evaluateAlertRule(insufficient).severity).toBe("none");

    const invalid = {
      ...insufficient,
      windows: windowed({ denominator: 4, numerator: 5 }),
    } satisfies AlertRuleObservation;
    expect(() => evaluateAlertRule(invalid)).toThrow("cannot exceed denominator");

    const inconsistentFanout = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.security.fanout_gap.v1",
      windows: windowed({ missing: 0, oldestMissingAgeSeconds: 1 }),
    } satisfies AlertRuleObservation;
    expect(() => evaluateAlertRule(inconsistentFanout)).toThrow(
      "missing count and oldest age must agree",
    );

    const inconsistentLogout = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: windowed({
        dead: 1,
        eligible: 1,
        leaseExpired: 0,
        oldestUnresolvedAgeSeconds: null,
        unresolved: 0,
      }),
    } satisfies AlertRuleObservation;
    expect(() => evaluateAlertRule(inconsistentLogout)).toThrow(
      "subsets cannot exceed",
    );
  });

  it("selects severity, shortest window, and expression order deterministically", () => {
    const criticalBeatsShorterWarning = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.registration.challenge_unavailable.v1",
      windows: windowed(
        { denominator: 10, numerator: 2 },
        { denominator: 0, numerator: 0 },
        { denominator: 30, numerator: 15 },
      ),
    } satisfies AlertRuleObservation;
    expect(evaluateAlertRule(criticalBeatsShorterWarning)).toMatchObject({
      breachedWindows: ["60m"],
      selectedEvidence: {
        denominator: 30,
        kind: "ratio",
        minNumerator: 5,
        minSample: 30,
        numerator: 15,
        provenance: "d1_exact",
        severity: "critical",
        threshold: 5_000,
        unit: "basis_points",
        value: 5_000,
        window: "60m",
      },
      severity: "critical",
    });

    const firstDeclaredClause = {
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed(
        { count: 0, knownSurfaces: 0 },
        { count: 0, knownSurfaces: 0 },
        { count: 20, knownSurfaces: 2 },
      ),
    } satisfies AlertRuleObservation;
    expect(evaluateAlertRule(firstDeclaredClause).selectedEvidence).toMatchObject({
      components: [{ metric: "count", threshold: 20 }],
      metric: "count",
      threshold: 20,
      window: "60m",
    });
  });

  it("marks missing approximate Queue metrics unknown instead of zero", () => {
    const observation = {
      asOf: AS_OF,
      dimension: QUEUE,
      ruleId: "pgid.queue.dlq_approximate.v1",
      windows: windowed({ depth: null, nonzeroMinutes: 30 }),
    } satisfies AlertRuleObservation;
    expect(evaluateAlertRule(observation)).toMatchObject({
      asOf: AS_OF,
      evidence: "unknown",
      immediateCritical: false,
      selectedEvidence: null,
      severity: "none",
    });
  });

  it("makes only durable dead state and evaluator loss immediate critical", () => {
    const deadLogout = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.logout.delivery_health.v1",
      windows: windowed({
        dead: 1,
        eligible: 1,
        leaseExpired: 0,
        oldestUnresolvedAgeSeconds: 0,
        unresolved: 1,
      }),
    } satisfies AlertRuleObservation;
    const evaluatorLost = {
      asOf: AS_OF,
      dimension: GLOBAL,
      ruleId: "pgid.alert.runtime_health.v1",
      windows: windowed({
        deadOutbox: 0,
        evaluatorAgeSeconds: null,
        outboxDueAgeSeconds: null,
      }),
    } satisfies AlertRuleObservation;
    const queueCritical = {
      asOf: AS_OF,
      dimension: QUEUE,
      ruleId: "pgid.queue.dlq_approximate.v1",
      windows: windowed({ depth: 10, nonzeroMinutes: 15 }),
    } satisfies AlertRuleObservation;

    expect(evaluateAlertRule(deadLogout)).toMatchObject({
      breachedWindows: ["5m", "15m", "60m"],
      immediateCritical: true,
      selectedEvidence: { window: "5m" },
      severity: "critical",
    });
    expect(evaluateAlertRule(evaluatorLost)).toMatchObject({
      immediateCritical: true,
      selectedEvidence: {
        kind: "boolean",
        threshold: 1,
        unit: "state",
        value: 1,
      },
      severity: "critical",
    });
    expect(evaluateAlertRule(queueCritical)).toMatchObject({
      immediateCritical: false,
      severity: "critical",
    });
  });

  it("is deterministic for identical observations", () => {
    const observation = {
      asOf: AS_OF,
      dimension: SUBJECT,
      ruleId: "pgid.restricted.sensitive_denied.v1",
      windows: windowed({ count: 20, knownSurfaces: 2 }),
    } satisfies AlertRuleObservation;
    expect(evaluateAlertRule(observation)).toEqual(evaluateAlertRule(observation));
  });
});
