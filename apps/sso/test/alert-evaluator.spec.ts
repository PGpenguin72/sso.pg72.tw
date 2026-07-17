import { describe, expect, it } from "vitest";

import {
  advanceAlertLifecycle,
  inactiveAlertState,
  type AlertLifecycleState,
} from "../worker/alert-evaluator";
import type {
  AlertRuleEvaluation,
  AlertSeverity,
} from "../worker/alert-rules";

const T0 = "2026-07-17T12:00:00.000Z";

function at(minutes: number, seconds = 0): string {
  return new Date(
    new Date(T0).getTime() + minutes * 60_000 + seconds * 1_000,
  ).toISOString();
}

function evaluation(
  asOf: string,
  severity: AlertSeverity,
  immediateCritical = false,
): AlertRuleEvaluation {
  const component = {
    kind: "count",
    metric: "count",
    threshold: 5,
    unit: "events",
    value: 5,
  } as const;
  return {
    asOf,
    breachedWindows: severity === "none" ? [] : ["5m"],
    dimension: { kind: "global" },
    evidence: "known",
    immediateCritical,
    ruleId: "pgid.registration.rate_limited.v1",
    selectedEvidence: severity === "none"
      ? null
      : {
          ...component,
          components: [component],
          provenance: "d1_exact",
          severity,
          window: "5m",
        },
    severity,
  };
}

function unknownEvaluation(asOf: string): AlertRuleEvaluation {
  return {
    asOf,
    breachedWindows: [],
    dimension: { kind: "queue", queue: "alert_deliveries_dlq" },
    evidence: "unknown",
    immediateCritical: false,
    ruleId: "pgid.queue.dlq_approximate.v1",
    selectedEvidence: null,
    severity: "none",
  };
}

function advance(
  previous: AlertLifecycleState,
  severity: AlertSeverity,
  asOf: string,
  immediateCritical = false,
) {
  return advanceAlertLifecycle({
    asOf,
    evaluation: evaluation(asOf, severity, immediateCritical),
    previous,
  });
}

function openedWarning(): AlertLifecycleState {
  const pending = advance(inactiveAlertState(), "warning", at(0));
  return advance(pending.state, "warning", at(1)).state;
}

describe("alert lifecycle evaluator", () => {
  it("opens only after two warning breaches with an observe-only intent", () => {
    const initial = inactiveAlertState();
    const pending = advance(initial, "warning", at(0));
    expect(pending).toEqual({
      intent: null,
      state: {
        ...initial,
        breachSeverity: "warning",
        consecutiveBreaches: 1,
        phase: "pending",
      },
    });

    const openingEvaluation = evaluation(at(1), "warning");
    const opened = advanceAlertLifecycle({
      asOf: at(1),
      evaluation: openingEvaluation,
      previous: pending.state,
    });
    expect(opened.intent).toEqual({
      at: at(1),
      dimension: { kind: "global" },
      evidence: openingEvaluation.selectedEvidence,
      kind: "open",
      mode: "observe_only",
      ruleId: "pgid.registration.rate_limited.v1",
      severity: "warning",
    });
    expect(opened.intent?.kind === "open" && opened.intent.evidence).toBe(
      openingEvaluation.selectedEvidence,
    );
    expect(opened.state).toMatchObject({
      breachSeverity: null,
      consecutiveBreaches: 0,
      lastNotificationAt: at(1),
      openedAt: at(1),
      phase: "active",
      status: "warning",
    });
    expect(initial).toEqual(inactiveAlertState());
  });

  it("opens immediate critical once and otherwise requires two breaches", () => {
    const immediate = advance(inactiveAlertState(), "critical", at(0), true);
    expect(immediate.intent).toMatchObject({
      kind: "open",
      mode: "observe_only",
      severity: "critical",
    });
    expect(immediate.state.status).toBe("critical");

    const pending = advance(inactiveAlertState(), "critical", at(0));
    expect(pending.intent).toBeNull();
    expect(pending.state.phase).toBe("pending");
    expect(advance(pending.state, "critical", at(1)).intent).toMatchObject({
      kind: "open",
      severity: "critical",
    });

    expect(() => advance(inactiveAlertState(), "warning", at(0), true)).toThrow(
      "only a critical evaluation",
    );
  });

  it("escalates an active warning after two critical breaches", () => {
    const warning = openedWarning();
    const pending = advance(warning, "critical", at(2));
    expect(pending.intent).toBeNull();
    expect(pending.state).toMatchObject({
      breachSeverity: "critical",
      consecutiveBreaches: 1,
      phase: "active",
      status: "warning",
    });

    const escalationEvaluation = evaluation(at(3), "critical");
    const escalated = advanceAlertLifecycle({
      asOf: at(3),
      evaluation: escalationEvaluation,
      previous: pending.state,
    });
    expect(escalated.intent).toMatchObject({
      from: "warning",
      kind: "escalate",
      mode: "observe_only",
      severity: "critical",
    });
    expect(
      escalated.intent?.kind === "escalate" && escalated.intent.evidence,
    ).toBe(escalationEvaluation.selectedEvidence);
    expect(escalated.state).toMatchObject({
      lastNotificationAt: at(3),
      phase: "active",
      status: "critical",
    });
  });

  it("resolves after five clears and lets critical bypass the cooldown", () => {
    let state = openedWarning();
    for (let minute = 2; minute <= 5; minute += 1) {
      const clearing = advance(state, "none", at(minute));
      expect(clearing.intent).toBeNull();
      state = clearing.state;
    }
    const resolved = advance(state, "none", at(6));
    expect(resolved.intent).toMatchObject({
      from: "warning",
      kind: "resolve",
      mode: "observe_only",
      severity: "none",
    });
    expect(resolved.state).toEqual({
      ...inactiveAlertState(),
      cooldownUntil: at(36),
    });

    const warningOne = advance(resolved.state, "warning", at(7));
    const warningTwo = advance(warningOne.state, "warning", at(8));
    expect(warningTwo.intent).toBeNull();
    expect(warningTwo.state).toMatchObject({
      cooldownUntil: at(36),
      phase: "pending",
      status: "none",
    });

    const criticalOne = advance(warningTwo.state, "critical", at(9));
    const criticalTwo = advance(criticalOne.state, "critical", at(10));
    expect(criticalTwo.intent).toMatchObject({
      kind: "open",
      severity: "critical",
    });
    expect(criticalTwo.state).toMatchObject({
      cooldownUntil: null,
      phase: "active",
      status: "critical",
    });
  });

  it("reminds warning at 60 minutes and critical at 15 minutes", () => {
    const warning = openedWarning();
    const warningEarly = advance(warning, "warning", at(60, 59));
    expect(warningEarly.intent).toBeNull();
    const warningReminderEvaluation = evaluation(at(61), "warning");
    const warningDue = advanceAlertLifecycle({
      asOf: at(61),
      evaluation: warningReminderEvaluation,
      previous: warningEarly.state,
    });
    expect(warningDue.intent).toMatchObject({
      kind: "remind",
      severity: "warning",
    });
    expect(warningDue.intent?.kind === "remind" && warningDue.intent.evidence)
      .toBe(warningReminderEvaluation.selectedEvidence);

    const criticalPending = advance(inactiveAlertState(), "critical", at(0));
    const critical = advance(criticalPending.state, "critical", at(1));
    const criticalEarly = advance(critical.state, "critical", at(15, 59));
    expect(criticalEarly.intent).toBeNull();
    const criticalReminderEvaluation = evaluation(at(16), "critical");
    const criticalDue = advanceAlertLifecycle({
      asOf: at(16),
      evaluation: criticalReminderEvaluation,
      previous: criticalEarly.state,
    });
    expect(criticalDue.intent).toMatchObject({
      kind: "remind",
      severity: "critical",
    });
    expect(
      criticalDue.intent?.kind === "remind" && criticalDue.intent.evidence,
    ).toBe(criticalReminderEvaluation.selectedEvidence);
  });

  it("holds state on unknown evidence and rejects stale evaluation time", () => {
    const previous = openedWarning();
    expect(
      advanceAlertLifecycle({
        asOf: at(2),
        evaluation: unknownEvaluation(at(2)),
        previous,
      }),
    ).toEqual({ intent: null, state: previous });

    expect(() =>
      advanceAlertLifecycle({
        asOf: at(2),
        evaluation: evaluation(at(1), "warning"),
        previous,
      })
    ).toThrow("exactly match evaluation.asOf");
  });

  it("rejects inactive notification or breach state", () => {
    expect(() =>
      advance(inactiveAlertState(), "none", at(0))
    ).not.toThrow();
    expect(() =>
      advanceAlertLifecycle({
        asOf: at(1),
        evaluation: evaluation(at(1), "none"),
        previous: {
          ...inactiveAlertState(),
          lastNotificationAt: at(0),
        },
      })
    ).toThrow("inactive alert state cannot carry notification or breach state");
    expect(() =>
      advanceAlertLifecycle({
        asOf: at(1),
        evaluation: evaluation(at(1), "none"),
        previous: {
          ...inactiveAlertState(),
          breachSeverity: "warning",
          consecutiveBreaches: 1,
        },
      })
    ).toThrow("inactive alert state cannot carry notification or breach state");
  });

  it("is deterministic and leaves its inputs unchanged", () => {
    const previous = inactiveAlertState();
    const input = {
      asOf: at(0),
      evaluation: evaluation(at(0), "warning"),
      previous,
    };
    const snapshot = structuredClone(input);
    expect(advanceAlertLifecycle(input)).toEqual(advanceAlertLifecycle(input));
    expect(input).toEqual(snapshot);
  });
});
