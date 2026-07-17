import {
  ALERT_RULE_POLICY,
  alertWindowsAt,
  type AlertDimension,
  type AlertRuleEvaluation,
  type AlertRuleId,
  type AlertSelectedEvidence,
  type AlertSeverity,
} from "./alert-rules";

type ActiveAlertSeverity = Exclude<AlertSeverity, "none">;
export type AlertLifecyclePhase = "active" | "inactive" | "pending";

export interface AlertLifecycleState {
  breachSeverity: ActiveAlertSeverity | null;
  consecutiveBreaches: number;
  consecutiveClears: number;
  cooldownUntil: string | null;
  lastNotificationAt: string | null;
  openedAt: string | null;
  phase: AlertLifecyclePhase;
  status: AlertSeverity;
}

interface ObserveOnlyIntentBase {
  at: string;
  dimension: AlertDimension;
  mode: "observe_only";
  ruleId: AlertRuleId;
}

export type AlertActionIntent =
  | (ObserveOnlyIntentBase & {
      evidence: AlertSelectedEvidence;
      kind: "open";
      severity: ActiveAlertSeverity;
    })
  | (ObserveOnlyIntentBase & {
      evidence: AlertSelectedEvidence;
      from: "warning";
      kind: "escalate";
      severity: "critical";
    })
  | (ObserveOnlyIntentBase & {
      evidence: AlertSelectedEvidence;
      kind: "remind";
      severity: ActiveAlertSeverity;
    })
  | (ObserveOnlyIntentBase & {
      from: ActiveAlertSeverity;
      kind: "resolve";
      severity: "none";
    });

export interface AlertLifecycleResult {
  intent: AlertActionIntent | null;
  state: AlertLifecycleState;
}

export function inactiveAlertState(): AlertLifecycleState {
  return {
    breachSeverity: null,
    consecutiveBreaches: 0,
    consecutiveClears: 0,
    cooldownUntil: null,
    lastNotificationAt: null,
    openedAt: null,
    phase: "inactive",
    status: "none",
  };
}

function timestampMs(value: string, name: string): number {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${name} must be a canonical UTC ISO timestamp`);
  }
  return timestamp;
}

function addMilliseconds(value: string, milliseconds: number): string {
  return new Date(timestampMs(value, "timestamp") + milliseconds).toISOString();
}

function validateState(state: AlertLifecycleState, asOfMs: number): void {
  if (
    !Number.isSafeInteger(state.consecutiveBreaches) ||
    state.consecutiveBreaches < 0 ||
    !Number.isSafeInteger(state.consecutiveClears) ||
    state.consecutiveClears < 0
  ) {
    throw new Error("alert consecutive counters must be non-negative safe integers");
  }
  if (
    (state.breachSeverity === null) !== (state.consecutiveBreaches === 0)
  ) {
    throw new Error("breach severity and consecutive breach count must agree");
  }
  if (state.consecutiveBreaches > 0 && state.consecutiveClears > 0) {
    throw new Error("breach and clear counters cannot both be active");
  }
  if (state.phase === "inactive") {
    if (
      state.status !== "none" ||
      state.openedAt !== null ||
      state.lastNotificationAt !== null ||
      state.breachSeverity !== null ||
      state.consecutiveBreaches !== 0 ||
      state.consecutiveClears !== 0
    ) {
      throw new Error("inactive alert state cannot carry notification or breach state");
    }
  } else if (state.phase === "pending") {
    if (
      state.status !== "none" ||
      state.openedAt !== null ||
      state.lastNotificationAt !== null ||
      state.breachSeverity === null ||
      state.consecutiveBreaches === 0 ||
      state.consecutiveClears !== 0
    ) {
      throw new Error("pending alert state requires only an unconfirmed breach");
    }
  } else if (
    state.status === "none" ||
    state.openedAt === null ||
    state.lastNotificationAt === null ||
    state.cooldownUntil !== null
  ) {
    throw new Error("active alert state requires notification timestamps and no cooldown");
  }
  if (
    state.phase === "active" &&
    state.breachSeverity !== null &&
    !(state.status === "warning" && state.breachSeverity === "critical")
  ) {
    throw new Error("only an active warning may carry a pending critical breach");
  }
  for (const [name, value] of [
    ["openedAt", state.openedAt],
    ["lastNotificationAt", state.lastNotificationAt],
  ] as const) {
    if (value !== null && timestampMs(value, name) > asOfMs) {
      throw new Error(`${name} cannot be in the future`);
    }
  }
  if (state.cooldownUntil !== null) {
    timestampMs(state.cooldownUntil, "cooldownUntil");
  }
  if (
    state.openedAt !== null &&
    state.lastNotificationAt !== null &&
    timestampMs(state.lastNotificationAt, "lastNotificationAt") <
      timestampMs(state.openedAt, "openedAt")
  ) {
    throw new Error("lastNotificationAt cannot precede openedAt");
  }
}

function validateEvaluation(evaluation: AlertRuleEvaluation): void {
  if (evaluation.evidence === "unknown") {
    if (
      evaluation.severity !== "none" ||
      evaluation.immediateCritical ||
      evaluation.selectedEvidence !== null ||
      evaluation.breachedWindows.length !== 0
    ) {
      throw new Error("unknown alert evidence cannot carry a breach result");
    }
    return;
  }
  if (evaluation.severity === "none") {
    if (
      evaluation.immediateCritical ||
      evaluation.selectedEvidence !== null ||
      evaluation.breachedWindows.length !== 0
    ) {
      throw new Error("clear alert evaluation cannot carry breach evidence");
    }
    return;
  }
  if (
    evaluation.selectedEvidence === null ||
    evaluation.selectedEvidence.severity !== evaluation.severity ||
    !evaluation.breachedWindows.some(
      (window) => window === evaluation.selectedEvidence?.window,
    )
  ) {
    throw new Error("breached alert evaluation requires matching selected evidence");
  }
}

function activeIntentBase(
  evaluation: AlertRuleEvaluation,
  asOf: string,
): ObserveOnlyIntentBase {
  return {
    at: asOf,
    dimension: evaluation.dimension,
    mode: "observe_only",
    ruleId: evaluation.ruleId,
  };
}

function selectedEvidenceFor(
  evaluation: AlertRuleEvaluation,
): AlertSelectedEvidence {
  if (evaluation.selectedEvidence === null) {
    throw new Error("active alert intent requires selected evidence");
  }
  return evaluation.selectedEvidence;
}

function reminderDue(
  state: AlertLifecycleState,
  severity: ActiveAlertSeverity,
  asOfMs: number,
): boolean {
  const last = state.lastNotificationAt ?? state.openedAt;
  if (last === null) return true;
  const interval = severity === "critical"
    ? ALERT_RULE_POLICY.criticalReminderMs
    : ALERT_RULE_POLICY.warningReminderMs;
  return asOfMs - timestampMs(last, "lastNotificationAt") >= interval;
}

function stableActiveResult(
  evaluation: AlertRuleEvaluation,
  state: AlertLifecycleState,
  asOf: string,
  asOfMs: number,
): AlertLifecycleResult {
  const severity = state.status;
  if (severity === "none") {
    throw new Error("stable active result requires an active state");
  }
  const stable: AlertLifecycleState = {
    ...state,
    breachSeverity: null,
    consecutiveBreaches: 0,
    consecutiveClears: 0,
    phase: "active",
  };
  if (!reminderDue(stable, severity, asOfMs)) {
    return { intent: null, state: stable };
  }
  return {
    intent: {
      ...activeIntentBase(evaluation, asOf),
      evidence: selectedEvidenceFor(evaluation),
      kind: "remind",
      severity,
    },
    state: { ...stable, lastNotificationAt: asOf },
  };
}

function startOrContinueBreach(
  state: AlertLifecycleState,
  candidate: ActiveAlertSeverity,
): number {
  return state.breachSeverity === candidate ? state.consecutiveBreaches + 1 : 1;
}

export function advanceAlertLifecycle(input: {
  asOf: string;
  evaluation: AlertRuleEvaluation;
  previous: AlertLifecycleState;
}): AlertLifecycleResult {
  const { asOf, evaluation, previous } = input;
  const asOfMs = timestampMs(asOf, "asOf");
  alertWindowsAt(asOf);
  if (evaluation.asOf !== asOf) {
    throw new Error("lifecycle asOf must exactly match evaluation.asOf");
  }
  validateEvaluation(evaluation);
  validateState(previous, asOfMs);
  if (evaluation.immediateCritical && evaluation.severity !== "critical") {
    throw new Error("only a critical evaluation may bypass breach hysteresis");
  }
  if (evaluation.evidence === "unknown") {
    return { intent: null, state: previous };
  }

  const cooldownUntil = previous.cooldownUntil === null ||
      timestampMs(previous.cooldownUntil, "cooldownUntil") <= asOfMs
    ? null
    : previous.cooldownUntil;
  const state = { ...previous, cooldownUntil };

  if (evaluation.severity === "none") {
    if (state.status === "none") {
      return {
        intent: null,
        state: {
          ...inactiveAlertState(),
          cooldownUntil: state.cooldownUntil,
        },
      };
    }
    const consecutiveClears = state.consecutiveClears + 1;
    if (consecutiveClears < ALERT_RULE_POLICY.clearConsecutive) {
      return {
        intent: null,
        state: {
          ...state,
          breachSeverity: null,
          consecutiveBreaches: 0,
          consecutiveClears,
        },
      };
    }
    const from = state.status;
    return {
      intent: {
        ...activeIntentBase(evaluation, asOf),
        from,
        kind: "resolve",
        severity: "none",
      },
      state: {
        ...inactiveAlertState(),
        cooldownUntil: addMilliseconds(asOf, ALERT_RULE_POLICY.cooldownMs),
      },
    };
  }

  if (state.status === "critical") {
    return stableActiveResult(evaluation, state, asOf, asOfMs);
  }
  if (state.status === "warning" && evaluation.severity === "warning") {
    return stableActiveResult(evaluation, state, asOf, asOfMs);
  }

  const candidate = evaluation.severity;
  const consecutiveBreaches = startOrContinueBreach(state, candidate);
  const required = evaluation.immediateCritical
    ? 1
    : candidate === "critical"
      ? ALERT_RULE_POLICY.criticalConsecutive
      : ALERT_RULE_POLICY.warningConsecutive;
  const pendingState: AlertLifecycleState = {
    ...state,
    breachSeverity: candidate,
    consecutiveBreaches,
    consecutiveClears: 0,
    phase: state.status === "none" ? "pending" : "active",
  };
  if (consecutiveBreaches < required) {
    return { intent: null, state: pendingState };
  }

  if (state.status === "warning" && candidate === "critical") {
    return {
      intent: {
        ...activeIntentBase(evaluation, asOf),
        evidence: selectedEvidenceFor(evaluation),
        from: "warning",
        kind: "escalate",
        severity: "critical",
      },
      state: {
        ...pendingState,
        breachSeverity: null,
        consecutiveBreaches: 0,
        lastNotificationAt: asOf,
        phase: "active",
        status: "critical",
      },
    };
  }

  if (state.status === "none") {
    // A higher-severity incident may open during cooldown; warning re-opens wait.
    if (state.cooldownUntil !== null && candidate === "warning") {
      return { intent: null, state: pendingState };
    }
    return {
      intent: {
        ...activeIntentBase(evaluation, asOf),
        evidence: selectedEvidenceFor(evaluation),
        kind: "open",
        severity: candidate,
      },
      state: {
        ...pendingState,
        breachSeverity: null,
        consecutiveBreaches: 0,
        cooldownUntil: null,
        lastNotificationAt: asOf,
        openedAt: asOf,
        phase: "active",
        status: candidate,
      },
    };
  }

  return stableActiveResult(evaluation, state, asOf, asOfMs);
}
