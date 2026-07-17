import { describe, expect, it } from "vitest";

import {
  advanceAlertLifecycle,
  inactiveAlertState,
  type AlertLifecycleState,
} from "../worker/alert-evaluator";

const T0 = "2026-07-17T12:00:00.000Z";
const GLOBAL = { kind: "global" } as const;
const REFERENCE_A = { keyVersion: 1, value: "A".repeat(43) } as const;
const REFERENCE_B = { keyVersion: 1, value: "E".repeat(43) } as const;
const SUBJECT_A = { kind: "subject_hmac", reference: REFERENCE_A } as const;
const SUBJECT_B = { kind: "subject_hmac", reference: REFERENCE_B } as const;
const CLIENT_A = { kind: "client_hmac", reference: REFERENCE_A } as const;

function at(minutes: number, seconds = 0): string {
  return new Date(
    new Date(T0).getTime() + minutes * 60_000 + seconds * 1_000,
  ).toISOString();
}

function registrationObservation(
  asOf: string,
  severity: "critical" | "none" | "warning",
  warningCount = 5,
) {
  const windows = severity === "critical"
    ? { "5m": { count: 10 }, "15m": { count: 25 }, "60m": { count: 40 } }
    : severity === "warning"
      ? {
          "5m": { count: warningCount },
          "15m": { count: warningCount },
          "60m": { count: warningCount },
        }
      : { "5m": { count: 0 }, "15m": { count: 0 }, "60m": { count: 0 } };
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.registration.rate_limited.v1",
    windows,
  };
}

function runtimeObservation(
  asOf: string,
  evaluatorAgeSeconds: number | null,
  deadOutbox = 0,
) {
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.alert.runtime_health.v1",
    snapshot: {
      deadOutbox,
      evaluatorAgeSeconds,
      outboxDueAgeSeconds: null,
    },
  };
}

function fanoutObservation(asOf: string, missing: number) {
  return {
    asOf,
    dimension: GLOBAL,
    ruleId: "pgid.security.fanout_gap.v1",
    snapshot: {
      missingOlderThan15mCount: 0,
      missingOlderThan5mCount: missing,
    },
  };
}

function unknownQueueObservation(asOf: string) {
  return {
    asOf,
    dimension: { kind: "queue", queue: "alert_deliveries_dlq" },
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot: {
      consecutiveNonzeroSamples: null,
      depth: null,
      nonzeroSinceAt: null,
      sampledAt: null,
    },
  };
}

function knownQueueObservation(
  asOf: string,
  options: {
    consecutiveNonzeroSamples?: number;
    depth?: number;
    nonzeroSinceAt?: string | null;
    queue?: "alert_deliveries_dlq" | "security_events_dlq";
  } = {},
) {
  const depth = options.depth ?? 1;
  return {
    asOf,
    dimension: {
      kind: "queue",
      queue: options.queue ?? "alert_deliveries_dlq",
    },
    ruleId: "pgid.queue.dlq_approximate.v1",
    snapshot: {
      consecutiveNonzeroSamples: options.consecutiveNonzeroSamples ?? (depth === 0 ? 0 : 1),
      depth,
      nonzeroSinceAt: options.nonzeroSinceAt === undefined
        ? (depth === 0 ? null : asOf)
        : options.nonzeroSinceAt,
      sampledAt: asOf,
    },
  };
}

function restrictedObservation(
  asOf: string,
  dimension: typeof SUBJECT_A | typeof SUBJECT_B,
) {
  return {
    asOf,
    dimension,
    ruleId: "pgid.restricted.sensitive_denied.v1",
    windows: {
      "5m": { count: 3, knownSurfaces: 1 },
      "15m": { count: 3, knownSurfaces: 1 },
      "60m": { count: 3, knownSurfaces: 1 },
    },
  };
}

function recoveryPasskeyObservation(
  asOf: string,
  dimension: typeof GLOBAL | typeof SUBJECT_A,
) {
  return {
    asOf,
    dimension,
    ruleId: "pgid.recovery.passkey_failure.v1",
    windows: {
      "5m": { denominator: 3, numerator: 3 },
      "15m": { denominator: 3, numerator: 3 },
      "60m": { denominator: 3, numerator: 3 },
    },
  };
}

function oauthObservation(
  asOf: string,
  evidence: "unknown" | "warning",
) {
  const windows = evidence === "warning"
    ? {
        "5m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
        "15m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
        "60m": { count: 1, distinctReporters: 1, highRiskCount: 1 },
      }
    : {
        "5m": { count: 0, distinctReporters: 0, highRiskCount: 0 },
        "15m": { count: 0, distinctReporters: 0, highRiskCount: 0 },
        "60m": { count: 3, distinctReporters: null, highRiskCount: 3 },
      };
  return {
    asOf,
    dimension: CLIENT_A,
    ruleId: "pgid.oauth.client_report.v1",
    windows,
  };
}

function advance(
  previous: AlertLifecycleState,
  severity: "critical" | "none" | "warning",
  asOf: string,
  warningCount = 5,
) {
  return advanceAlertLifecycle({
    asOf,
    observation: registrationObservation(asOf, severity, warningCount),
    previous,
  });
}

function openedWarning(): AlertLifecycleState {
  const pending = advance(inactiveAlertState(), "warning", at(0));
  return advance(pending.state, "warning", at(1)).state;
}

function openedCritical(): AlertLifecycleState {
  const pending = advance(inactiveAlertState(), "critical", at(0));
  return advance(pending.state, "critical", at(1)).state;
}

describe("alert lifecycle evaluator", () => {
  it("opens only after two warning breaches and retains the exact evidence", () => {
    const initial = inactiveAlertState();
    const pending = advance(initial, "warning", at(0));
    expect(pending.intent).toBeNull();
    expect(pending.state).toMatchObject({
      activeEvidence: null,
      breachEvidence: {
        metricName: "count",
        observedValue: 5,
        severity: "warning",
        threshold: 5,
        windowSeconds: 300,
      },
      breachSeverity: "warning",
      consecutiveBreaches: 1,
      identity: {
        dimension: GLOBAL,
        ruleId: "pgid.registration.rate_limited.v1",
      },
      lastEvaluatedAt: at(0),
      phase: "pending",
      status: "none",
    });

    const restarted = JSON.parse(JSON.stringify(pending.state)) as AlertLifecycleState;
    expect(restarted.breachEvidence).toEqual(pending.state.breachEvidence);
    const opened = advance(restarted, "warning", at(1));
    expect(opened.intent).toMatchObject({
      at: at(1),
      dimension: GLOBAL,
      kind: "open",
      mode: "observe_only",
      ruleId: "pgid.registration.rate_limited.v1",
      severity: "warning",
    });
    expect(opened.state).toMatchObject({
      breachSeverity: null,
      breachEvidence: null,
      consecutiveBreaches: 0,
      lastNotificationAt: at(1),
      openedAt: at(1),
      phase: "active",
      status: "warning",
    });
    expect(opened.state.activeEvidence).toMatchObject({
      metricName: "count",
      observedValue: 5,
      severity: "warning",
    });
    expect(opened.intent?.kind === "open" && opened.intent.evidence)
      .toBe(opened.state.activeEvidence);
    expect(initial).toEqual(inactiveAlertState());
  });

  it("derives immediate policy instead of trusting a caller flag", () => {
    const stale = advanceAlertLifecycle({
      asOf: at(0),
      observation: runtimeObservation(at(0), 301),
      previous: inactiveAlertState(),
    });
    expect(stale.intent).toBeNull();
    expect(stale.state.phase).toBe("pending");
    expect(advanceAlertLifecycle({
      asOf: at(1),
      observation: runtimeObservation(at(1), 301),
      previous: stale.state,
    }).intent).toMatchObject({ kind: "open", severity: "critical" });

    const missing = advanceAlertLifecycle({
      asOf: at(0),
      observation: runtimeObservation(at(0), null),
      previous: inactiveAlertState(),
    });
    expect(missing.intent).toMatchObject({ kind: "open", severity: "critical" });

    const dead = advanceAlertLifecycle({
      asOf: at(0),
      observation: runtimeObservation(at(0), 0, 1),
      previous: inactiveAlertState(),
    });
    expect(dead.intent).toMatchObject({ kind: "open", severity: "critical" });

    expect(() => advanceAlertLifecycle({
      asOf: at(0),
      observation: {
        ...registrationObservation(at(0), "critical"),
        immediateCritical: true,
      },
      previous: inactiveAlertState(),
    })).toThrow("canonical keys");
  });

  it("preserves warning evidence during a pending escalation", () => {
    const warning = openedWarning();
    const warningEvidence = warning.activeEvidence;
    const pending = advance(warning, "critical", at(2));
    expect(pending.intent).toBeNull();
    expect(pending.state).toMatchObject({
      breachEvidence: {
        metricName: "count",
        severity: "critical",
        threshold: 40,
        windowSeconds: 3_600,
      },
      breachSeverity: "critical",
      consecutiveBreaches: 1,
      phase: "active",
      status: "warning",
    });
    expect(pending.state.activeEvidence).toEqual(warningEvidence);

    const restarted = JSON.parse(JSON.stringify(pending.state)) as AlertLifecycleState;
    expect(restarted.breachEvidence).toEqual(pending.state.breachEvidence);
    const escalated = advance(restarted, "critical", at(3));
    expect(escalated.intent).toMatchObject({
      from: "warning",
      kind: "escalate",
      mode: "observe_only",
      severity: "critical",
    });
    expect(escalated.state.activeEvidence).toMatchObject({
      metricName: "count",
      severity: "critical",
      threshold: 40,
      windowSeconds: 3_600,
    });
    expect(escalated.state.breachEvidence).toBeNull();
    expect(escalated.intent?.kind === "escalate" && escalated.intent.evidence)
      .toBe(escalated.state.activeEvidence);
  });

  it("resolves after five clears and lets critical bypass cooldown", () => {
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
      identity: {
        dimension: GLOBAL,
        ruleId: "pgid.registration.rate_limited.v1",
      },
      lastEvaluatedAt: at(6),
    });

    const warningOne = advance(resolved.state, "warning", at(7));
    const warningTwo = advance(warningOne.state, "warning", at(8));
    expect(warningTwo.intent).toBeNull();
    expect(warningTwo.state.phase).toBe("pending");
    expect(warningTwo.state.consecutiveBreaches).toBe(1);

    const criticalOne = advance(warningTwo.state, "critical", at(9));
    const criticalTwo = advance(criticalOne.state, "critical", at(10));
    expect(criticalTwo.intent).toMatchObject({ kind: "open", severity: "critical" });
    expect(criticalTwo.state).toMatchObject({
      cooldownUntil: null,
      phase: "active",
      status: "critical",
    });
  });

  it("refreshes same-severity evidence without changing reminder time", () => {
    const warning = openedWarning();
    const refreshed = advance(warning, "warning", at(2), 6);
    expect(refreshed.intent).toBeNull();
    expect(refreshed.state.lastNotificationAt).toBe(at(1));
    expect(refreshed.state.activeEvidence).toMatchObject({
      observedValue: 6,
      severity: "warning",
    });
  });

  it("never places warning evidence in a critical reminder", () => {
    const critical = openedCritical();
    const reminder = advance(critical, "warning", at(16));
    expect(reminder.intent).toMatchObject({
      kind: "remind",
      severity: "critical",
      evidence: {
        severity: "critical",
        threshold: 40,
        windowSeconds: 3_600,
      },
    });
    expect(reminder.state.activeEvidence).toMatchObject({
      severity: "critical",
      threshold: 40,
    });
    expect(reminder.intent?.kind === "remind" && reminder.intent.evidence)
      .toBe(reminder.state.activeEvidence);
  });

  it("uses 60-minute warning and 15-minute critical reminder intervals", () => {
    const warning = openedWarning();
    expect(advance(warning, "warning", at(60, 59)).intent).toBeNull();
    expect(advance(warning, "warning", at(61)).intent)
      .toMatchObject({ kind: "remind", severity: "warning" });

    const critical = openedCritical();
    expect(advance(critical, "critical", at(15, 59)).intent).toBeNull();
    expect(advance(critical, "critical", at(16)).intent)
      .toMatchObject({ kind: "remind", severity: "critical" });
  });

  it("never auto-resolves a bounded fan-out detector incident", () => {
    let result = advanceAlertLifecycle({
      asOf: at(0),
      observation: fanoutObservation(at(0), 1),
      previous: inactiveAlertState(),
    });
    result = advanceAlertLifecycle({
      asOf: at(1),
      observation: fanoutObservation(at(1), 1),
      previous: result.state,
    });
    expect(result.state.status).toBe("warning");
    const originalEvidence = result.state.activeEvidence;

    for (let minute = 2; minute <= 10; minute += 1) {
      result = advanceAlertLifecycle({
        asOf: at(minute),
        observation: fanoutObservation(at(minute), 0),
        previous: result.state,
      });
      expect(result.intent).toBeNull();
      expect(result.state.status).toBe("warning");
      expect(result.state.consecutiveClears).toBe(0);
      expect(result.state.activeEvidence).toEqual(originalEvidence);
    }

    const reminder = advanceAlertLifecycle({
      asOf: at(61),
      observation: fanoutObservation(at(61), 0),
      previous: result.state,
    });
    expect(reminder.intent).toMatchObject({ kind: "remind", severity: "warning" });
    expect(reminder.state.status).toBe("warning");
  });

  it("holds canonical state on unknown Queue evidence", () => {
    const previous = inactiveAlertState();
    expect(advanceAlertLifecycle({
      asOf: at(2),
      observation: unknownQueueObservation(at(2)),
      previous,
    })).toEqual({ intent: null, state: previous });
  });

  it("binds state identity and rejects cross-wired lifecycle rows", () => {
    const registration = advance(inactiveAlertState(), "warning", at(0)).state;
    expect(() => advanceAlertLifecycle({
      asOf: at(1),
      observation: {
        asOf: at(1),
        dimension: GLOBAL,
        ruleId: "pgid.registration.denied.v1",
        windows: {
          "5m": { count: 10 },
          "15m": { count: 10 },
          "60m": { count: 10 },
        },
      },
      previous: registration,
    })).toThrow("identity");

    const subject = advanceAlertLifecycle({
      asOf: at(0),
      observation: restrictedObservation(at(0), SUBJECT_A),
      previous: inactiveAlertState(),
    }).state;
    expect(() => advanceAlertLifecycle({
      asOf: at(1),
      observation: restrictedObservation(at(1), SUBJECT_B),
      previous: subject,
    })).toThrow("identity");

    const global = advanceAlertLifecycle({
      asOf: at(0),
      observation: recoveryPasskeyObservation(at(0), GLOBAL),
      previous: inactiveAlertState(),
    }).state;
    expect(() => advanceAlertLifecycle({
      asOf: at(1),
      observation: recoveryPasskeyObservation(at(1), SUBJECT_A),
      previous: global,
    })).toThrow("identity");

    const queue = advanceAlertLifecycle({
      asOf: at(0),
      observation: knownQueueObservation(at(0)),
      previous: inactiveAlertState(),
    }).state;
    expect(() => advanceAlertLifecycle({
      asOf: at(1),
      observation: knownQueueObservation(at(1), { queue: "security_events_dlq" }),
      previous: queue,
    })).toThrow("identity");
    expect(() => advanceAlertLifecycle({
      asOf: at(1),
      observation: knownQueueObservation(at(1)),
      previous: {
        ...queue,
        identity: { ...queue.identity, raw: "redacted" },
      },
    })).toThrow("canonical keys");
  });

  it("rejects replayed and out-of-order evaluations before counters advance", () => {
    const pending = advance(inactiveAlertState(), "warning", at(0));
    expect(() => advance(pending.state, "warning", at(0))).toThrow();
    expect(() => advance(pending.state, "warning", at(-1))).toThrow();

    const warning = openedWarning();
    const escalating = advance(warning, "critical", at(2));
    expect(() => advance(escalating.state, "critical", at(2))).toThrow(
      "strictly increasing",
    );

    const clearing = advance(warning, "none", at(2));
    expect(() => advance(clearing.state, "none", at(2))).toThrow(
      "strictly increasing",
    );
  });

  it("treats unknown Queue samples as gaps in every consecutive sequence", () => {
    const firstWarning = advanceAlertLifecycle({
      asOf: at(0),
      observation: knownQueueObservation(at(0)),
      previous: inactiveAlertState(),
    });
    const warningGap = advanceAlertLifecycle({
      asOf: at(1),
      observation: unknownQueueObservation(at(1)),
      previous: firstWarning.state,
    });
    expect(warningGap.state).toMatchObject({
      breachEvidence: null,
      breachSeverity: null,
      consecutiveBreaches: 0,
      lastEvaluatedAt: at(1),
      phase: "inactive",
    });
    const afterWarningGap = advanceAlertLifecycle({
      asOf: at(2),
      observation: knownQueueObservation(at(2)),
      previous: warningGap.state,
    });
    expect(afterWarningGap).toMatchObject({
      intent: null,
      state: { consecutiveBreaches: 1, phase: "pending" },
    });

    const opened = advanceAlertLifecycle({
      asOf: at(1),
      observation: knownQueueObservation(at(1), {
        consecutiveNonzeroSamples: 2,
        nonzeroSinceAt: at(0),
      }),
      previous: firstWarning.state,
    });
    const firstClear = advanceAlertLifecycle({
      asOf: at(2),
      observation: knownQueueObservation(at(2), { depth: 0 }),
      previous: opened.state,
    });
    expect(firstClear.state.consecutiveClears).toBe(1);
    const clearGap = advanceAlertLifecycle({
      asOf: at(3),
      observation: unknownQueueObservation(at(3)),
      previous: firstClear.state,
    });
    expect(clearGap.state.consecutiveClears).toBe(0);
    const afterClearGap = advanceAlertLifecycle({
      asOf: at(4),
      observation: knownQueueObservation(at(4), { depth: 0 }),
      previous: clearGap.state,
    });
    expect(afterClearGap.state.consecutiveClears).toBe(1);

    const criticalCandidate = advanceAlertLifecycle({
      asOf: at(2),
      observation: knownQueueObservation(at(2), { depth: 10 }),
      previous: opened.state,
    });
    expect(criticalCandidate.state).toMatchObject({
      breachSeverity: "critical",
      consecutiveBreaches: 1,
      status: "warning",
    });
    const criticalGap = advanceAlertLifecycle({
      asOf: at(3),
      observation: unknownQueueObservation(at(3)),
      previous: criticalCandidate.state,
    });
    expect(criticalGap.state).toMatchObject({
      activeEvidence: opened.state.activeEvidence,
      breachEvidence: null,
      breachSeverity: null,
      consecutiveBreaches: 0,
      status: "warning",
    });
    const afterCriticalGap = advanceAlertLifecycle({
      asOf: at(4),
      observation: knownQueueObservation(at(4), { depth: 10 }),
      previous: criticalGap.state,
    });
    expect(afterCriticalGap).toMatchObject({
      intent: null,
      state: {
        breachSeverity: "critical",
        consecutiveBreaches: 1,
        status: "warning",
      },
    });
  });

  it("treats incomplete OAuth reporter coverage as an active-safe gap", () => {
    const first = advanceAlertLifecycle({
      asOf: at(0),
      observation: oauthObservation(at(0), "warning"),
      previous: inactiveAlertState(),
    });
    const pendingGap = advanceAlertLifecycle({
      asOf: at(1),
      observation: oauthObservation(at(1), "unknown"),
      previous: first.state,
    });
    expect(pendingGap).toMatchObject({
      intent: null,
      state: {
        breachEvidence: null,
        breachSeverity: null,
        consecutiveBreaches: 0,
        phase: "inactive",
        status: "none",
      },
    });

    const opened = advanceAlertLifecycle({
      asOf: at(1),
      observation: oauthObservation(at(1), "warning"),
      previous: first.state,
    });
    expect(opened.state.status).toBe("warning");
    const activeEvidence = opened.state.activeEvidence;
    const activeGap = advanceAlertLifecycle({
      asOf: at(2),
      observation: oauthObservation(at(2), "unknown"),
      previous: opened.state,
    });
    expect(activeGap).toMatchObject({
      intent: null,
      state: {
        activeEvidence,
        breachEvidence: null,
        breachSeverity: null,
        consecutiveBreaches: 0,
        consecutiveClears: 0,
        lastEvaluatedAt: at(2),
        phase: "active",
        status: "warning",
      },
    });
  });

  it("rejects stale observation time and noncanonical input keys", () => {
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(1), "warning"),
      previous: inactiveAlertState(),
    })).toThrow("exactly match");
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(2), "warning"),
      previous: inactiveAlertState(),
      raw: "redacted",
    })).toThrow("canonical keys");
  });

  it("rejects every invalid runtime state enum and extra evidence key", () => {
    const critical = openedCritical();
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(2), "warning"),
      previous: { ...critical, phase: "bogus", status: "bogus" },
    })).toThrow("phase");
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(2), "warning"),
      previous: {
        ...critical,
        activeEvidence: { ...critical.activeEvidence, raw: "redacted" },
      },
    })).toThrow("canonical keys");
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(2), "warning"),
      previous: { ...critical, breachSeverity: "bogus" },
    })).toThrow("breach severity");
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: registrationObservation(at(2), "warning"),
      previous: {
        ...critical,
        breachEvidence: {
          ...critical.activeEvidence,
          severity: "warning",
        },
      },
    })).toThrow("canonical rule contract");
  });

  it("binds persisted evidence to the exact rule signature", () => {
    const critical = openedCritical();
    const criticalEvidence = critical.activeEvidence;
    if (criticalEvidence === null) throw new Error("expected critical evidence");

    const wrongMetric: AlertLifecycleState = {
      ...critical,
      activeEvidence: {
        ...criticalEvidence,
        metricName: "dead",
        threshold: 1,
      },
    };
    expect(() => advance(wrongMetric, "warning", at(16))).toThrow(
      "canonical rule contract",
    );

    expect(() => advance({
      ...critical,
      activeEvidence: { ...criticalEvidence, windowSeconds: 900 },
    }, "warning", at(16))).toThrow("canonical rule contract");
    expect(() => advance({
      ...critical,
      activeEvidence: { ...criticalEvidence, threshold: 39 },
    }, "warning", at(16))).toThrow("canonical rule contract");

    const recoveryFirst = advanceAlertLifecycle({
      asOf: at(0),
      observation: recoveryPasskeyObservation(at(0), GLOBAL),
      previous: inactiveAlertState(),
    });
    const recovery = advanceAlertLifecycle({
      asOf: at(1),
      observation: recoveryPasskeyObservation(at(1), GLOBAL),
      previous: recoveryFirst.state,
    }).state;
    const recoveryEvidence = recovery.activeEvidence;
    if (recoveryEvidence === null) throw new Error("expected recovery evidence");
    expect(() => advanceAlertLifecycle({
      asOf: at(2),
      observation: recoveryPasskeyObservation(at(2), GLOBAL),
      previous: {
        ...recovery,
        activeEvidence: {
          ...recoveryEvidence,
          minimumNumeratorCount: 2,
          minimumSampleCount: 2,
        },
      },
    })).toThrow("canonical rule contract");

    expect(() => advance({
      ...critical,
      activeEvidence: {
        ...criticalEvidence,
        observedValue: 5,
        secondary: {
          kind: "count",
          metricName: "known_surfaces",
          minimumNumeratorCount: null,
          minimumSampleCount: 0,
          observedDenominator: null,
          observedNumerator: null,
          observedValue: 2,
          threshold: 2,
          unit: "events",
        },
        threshold: 5,
      },
    }, "warning", at(16))).toThrow("canonical rule contract");
  });

  it("bounds persisted clears and cooldowns against state tampering", () => {
    const warning = openedWarning();
    expect(() => advance({
      ...warning,
      consecutiveClears: 999,
    }, "none", at(2))).toThrow("between 0 and 4");

    let state = warning;
    for (let minute = 2; minute <= 5; minute += 1) {
      state = advance(state, "none", at(minute)).state;
    }
    const resolved = advance(state, "none", at(6)).state;
    expect(() => advance({
      ...resolved,
      cooldownUntil: at(600),
    }, "warning", at(7))).toThrow("cooldown");
    expect(() => advance({
      ...resolved,
      cooldownUntil: at(36, 1),
    }, "warning", at(7))).toThrow("cooldown");
  });

  it("is deterministic and leaves all caller inputs unchanged", () => {
    const input = {
      asOf: at(0),
      observation: registrationObservation(at(0), "warning"),
      previous: inactiveAlertState(),
    };
    const snapshot = structuredClone(input);
    expect(advanceAlertLifecycle(input)).toEqual(advanceAlertLifecycle(input));
    expect(input).toEqual(snapshot);
  });
});
