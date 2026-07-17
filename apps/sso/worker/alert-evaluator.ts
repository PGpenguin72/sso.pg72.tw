import {
  ALERT_RULE_DEFINITIONS,
  ALERT_RULE_POLICY,
  alertWindowsAt,
  evaluateAlertRule,
  parseAlertDimension,
  parseAlertRuleId,
  parseAlertSelectedEvidenceForRule,
  type AlertDimension,
  type AlertRuleEvaluation,
  type AlertRuleId,
  type AlertSelectedEvidence,
  type AlertSeverity,
} from "./alert-rules";

type ActiveAlertSeverity = Exclude<AlertSeverity, "none">;
export type AlertLifecyclePhase = "active" | "inactive" | "pending";

export interface AlertLifecycleIdentity {
  dimension: AlertDimension;
  ruleId: AlertRuleId;
}

export interface AlertLifecycleState {
  activeEvidence: AlertSelectedEvidence | null;
  breachEvidence: AlertSelectedEvidence | null;
  breachSeverity: ActiveAlertSeverity | null;
  consecutiveBreaches: number;
  consecutiveClears: number;
  cooldownUntil: string | null;
  identity: AlertLifecycleIdentity | null;
  lastEvaluatedAt: string | null;
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
    activeEvidence: null,
    breachEvidence: null,
    breachSeverity: null,
    consecutiveBreaches: 0,
    consecutiveClears: 0,
    cooldownUntil: null,
    identity: null,
    lastEvaluatedAt: null,
    lastNotificationAt: null,
    openedAt: null,
    phase: "inactive",
    status: "none",
  };
}

type UnknownRecord = Record<string, unknown>;

function exactRecord(
  value: unknown,
  keys: readonly string[],
  name: string,
): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  const record = value as UnknownRecord;
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw new Error(`${name} must contain only the canonical keys`);
  }
  return record;
}

function timestamp(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new Error(`${name} must be a canonical UTC ISO timestamp`);
  }
  const milliseconds = new Date(value).getTime();
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new Error(`${name} must be a canonical UTC ISO timestamp`);
  }
  return value;
}

function timestampMs(value: string, name: string): number {
  return new Date(timestamp(value, name)).getTime();
}

function nullableTimestamp(value: unknown, name: string): string | null {
  return value === null ? null : timestamp(value, name);
}

function addMilliseconds(value: string, milliseconds: number): string {
  return new Date(timestampMs(value, "timestamp") + milliseconds).toISOString();
}

function counter(value: unknown, name: string, maximum = 10_000): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    throw new Error(`${name} must be an integer between 0 and ${maximum}`);
  }
  return value as number;
}

function activeSeverity(value: unknown, name: string): ActiveAlertSeverity | null {
  if (value === null || value === "warning" || value === "critical") return value;
  throw new Error(`${name} is not supported`);
}

function phase(value: unknown): AlertLifecyclePhase {
  if (value === "active" || value === "inactive" || value === "pending") {
    return value;
  }
  throw new Error("alert lifecycle phase is not supported");
}

function severity(value: unknown): AlertSeverity {
  if (value === "none" || value === "warning" || value === "critical") {
    return value;
  }
  throw new Error("alert lifecycle severity is not supported");
}

function parseIdentity(value: unknown): AlertLifecycleIdentity {
  const record = exactRecord(
    value,
    ["dimension", "ruleId"],
    "alert lifecycle identity",
  );
  const ruleId = parseAlertRuleId(record.ruleId);
  return {
    dimension: parseAlertDimension(
      record.dimension,
      ALERT_RULE_DEFINITIONS[ruleId].dimensions,
    ),
    ruleId,
  };
}

function parseState(value: unknown, asOfMs: number): AlertLifecycleState {
  const record = exactRecord(
    value,
    [
      "activeEvidence",
      "breachEvidence",
      "breachSeverity",
      "consecutiveBreaches",
      "consecutiveClears",
      "cooldownUntil",
      "identity",
      "lastEvaluatedAt",
      "lastNotificationAt",
      "openedAt",
      "phase",
      "status",
    ],
    "alert lifecycle state",
  );
  const identity = record.identity === null ? null : parseIdentity(record.identity);
  const parseEvidence = (
    evidence: unknown,
  ): AlertSelectedEvidence | null => {
    if (evidence === null) return null;
    if (identity === null) {
      throw new Error("alert lifecycle evidence requires a bound identity");
    }
    return parseAlertSelectedEvidenceForRule(evidence, identity.ruleId);
  };
  const state: AlertLifecycleState = {
    activeEvidence: parseEvidence(record.activeEvidence),
    breachEvidence: parseEvidence(record.breachEvidence),
    breachSeverity: activeSeverity(record.breachSeverity, "breach severity"),
    consecutiveBreaches: counter(
      record.consecutiveBreaches,
      "consecutive breaches",
      1,
    ),
    consecutiveClears: counter(record.consecutiveClears, "consecutive clears", 4),
    cooldownUntil: nullableTimestamp(record.cooldownUntil, "cooldownUntil"),
    identity,
    lastEvaluatedAt: nullableTimestamp(record.lastEvaluatedAt, "lastEvaluatedAt"),
    lastNotificationAt: nullableTimestamp(
      record.lastNotificationAt,
      "lastNotificationAt",
    ),
    openedAt: nullableTimestamp(record.openedAt, "openedAt"),
    phase: phase(record.phase),
    status: severity(record.status),
  };
  if ((state.breachSeverity === null) !== (state.consecutiveBreaches === 0)) {
    throw new Error("breach severity and consecutive breach count must agree");
  }
  if (
    (state.breachEvidence === null) !== (state.breachSeverity === null) ||
    (state.breachEvidence !== null &&
      state.breachEvidence.severity !== state.breachSeverity)
  ) {
    throw new Error("breach evidence must match the pending breach severity");
  }
  if (state.consecutiveBreaches > 0 && state.consecutiveClears > 0) {
    throw new Error("breach and clear counters cannot both be active");
  }
  if ((state.identity === null) !== (state.lastEvaluatedAt === null)) {
    throw new Error("alert lifecycle identity and evaluation watermark must agree");
  }
  if (
    state.cooldownUntil !== null &&
    (state.lastEvaluatedAt === null ||
      timestampMs(state.cooldownUntil, "cooldownUntil") -
          timestampMs(state.lastEvaluatedAt, "lastEvaluatedAt") >
        ALERT_RULE_POLICY.cooldownMs)
  ) {
    throw new Error("alert lifecycle cooldown exceeds the canonical interval");
  }
  if (state.phase === "inactive") {
    if (
      state.status !== "none" ||
      state.activeEvidence !== null ||
      state.breachEvidence !== null ||
      state.openedAt !== null ||
      state.lastNotificationAt !== null ||
      state.breachSeverity !== null ||
      state.consecutiveBreaches !== 0 ||
      state.consecutiveClears !== 0 ||
      (state.identity === null && state.cooldownUntil !== null)
    ) {
      throw new Error("inactive alert state cannot carry active evidence");
    }
  } else if (state.phase === "pending") {
    if (
      state.status !== "none" ||
      state.activeEvidence !== null ||
      state.breachEvidence === null ||
      state.identity === null ||
      state.openedAt !== null ||
      state.lastNotificationAt !== null ||
      state.breachSeverity === null ||
      state.consecutiveBreaches === 0 ||
      state.consecutiveClears !== 0
    ) {
      throw new Error("pending alert state requires only an unconfirmed breach");
    }
  } else {
    if (
      state.status === "none" ||
      state.activeEvidence === null ||
      state.activeEvidence.severity !== state.status ||
      state.identity === null ||
      state.openedAt === null ||
      state.lastNotificationAt === null ||
      state.cooldownUntil !== null
    ) {
      throw new Error("active alert state is inconsistent");
    }
    if (
      state.breachSeverity !== null &&
      !(state.status === "warning" && state.breachSeverity === "critical")
    ) {
      throw new Error("only an active warning may carry a pending critical breach");
    }
  }
  for (const [name, value] of [
    ["openedAt", state.openedAt],
    ["lastEvaluatedAt", state.lastEvaluatedAt],
    ["lastNotificationAt", state.lastNotificationAt],
  ] as const) {
    if (value !== null && timestampMs(value, name) > asOfMs) {
      throw new Error(`${name} cannot be in the future`);
    }
  }
  if (
    state.lastEvaluatedAt !== null &&
    ((state.openedAt !== null &&
      timestampMs(state.openedAt, "openedAt") >
        timestampMs(state.lastEvaluatedAt, "lastEvaluatedAt")) ||
      (state.lastNotificationAt !== null &&
        timestampMs(state.lastNotificationAt, "lastNotificationAt") >
          timestampMs(state.lastEvaluatedAt, "lastEvaluatedAt")))
  ) {
    throw new Error("alert lifecycle timestamps cannot exceed its watermark");
  }
  if (
    state.openedAt !== null &&
    state.lastNotificationAt !== null &&
    timestampMs(state.lastNotificationAt, "lastNotificationAt") <
      timestampMs(state.openedAt, "openedAt")
  ) {
    throw new Error("lastNotificationAt cannot precede openedAt");
  }
  return state;
}

function sameDimension(left: AlertDimension, right: AlertDimension): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === "global" && right.kind === "global") return true;
  if (left.kind === "queue" && right.kind === "queue") {
    return left.queue === right.queue;
  }
  if (
    "reference" in left &&
    "reference" in right
  ) {
    return left.reference.keyVersion === right.reference.keyVersion &&
      left.reference.value === right.reference.value;
  }
  return false;
}

function identityFor(evaluation: AlertRuleEvaluation): AlertLifecycleIdentity {
  return {
    dimension: evaluation.dimension,
    ruleId: evaluation.ruleId,
  };
}

function assertSameIdentity(
  previous: AlertLifecycleIdentity,
  current: AlertLifecycleIdentity,
): void {
  if (
    previous.ruleId !== current.ruleId ||
    !sameDimension(previous.dimension, current.dimension)
  ) {
    throw new Error("alert lifecycle identity does not match the observation");
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
  asOfMs: number,
): boolean {
  if (state.status === "none") return false;
  const last = state.lastNotificationAt ?? state.openedAt;
  if (last === null) return true;
  const interval = state.status === "critical"
    ? ALERT_RULE_POLICY.criticalReminderMs
    : ALERT_RULE_POLICY.warningReminderMs;
  return asOfMs - timestampMs(last, "lastNotificationAt") >= interval;
}

function stableActiveResult(
  evaluation: AlertRuleEvaluation,
  state: AlertLifecycleState,
  asOf: string,
  asOfMs: number,
  refreshEvidence: boolean,
): AlertLifecycleResult {
  if (state.status === "none" || state.activeEvidence === null) {
    throw new Error("stable active result requires an active state");
  }
  const evidence = refreshEvidence
    ? selectedEvidenceFor(evaluation)
    : state.activeEvidence;
  if (evidence.severity !== state.status) {
    throw new Error("active evidence must match the incident severity");
  }
  const stable: AlertLifecycleState = {
    ...state,
    activeEvidence: evidence,
    breachEvidence: null,
    breachSeverity: null,
    consecutiveBreaches: 0,
    consecutiveClears: 0,
    phase: "active",
  };
  if (!reminderDue(stable, asOfMs)) return { intent: null, state: stable };
  const intent: AlertActionIntent = {
    ...activeIntentBase(evaluation, asOf),
    evidence,
    kind: "remind",
    severity: state.status,
  };
  return {
    intent,
    state: { ...stable, lastNotificationAt: asOf },
  };
}

function startOrContinueBreach(
  state: AlertLifecycleState,
  candidate: ActiveAlertSeverity,
): number {
  return state.breachSeverity === candidate ? state.consecutiveBreaches + 1 : 1;
}

export function advanceAlertLifecycle(input: unknown): AlertLifecycleResult {
  const record = exactRecord(
    input,
    ["asOf", "observation", "previous"],
    "alert lifecycle input",
  );
  const asOf = timestamp(record.asOf, "asOf");
  const asOfMs = timestampMs(asOf, "asOf");
  alertWindowsAt(asOf);
  const evaluation = evaluateAlertRule(record.observation);
  if (evaluation.asOf !== asOf) {
    throw new Error("lifecycle asOf must exactly match observation.asOf");
  }
  const previous = parseState(record.previous, asOfMs);
  const currentIdentity = identityFor(evaluation);
  if (previous.identity === null) {
    if (evaluation.evidence === "unknown" || evaluation.severity === "none") {
      return { intent: null, state: previous };
    }
  } else {
    assertSameIdentity(previous.identity, currentIdentity);
    if (
      previous.lastEvaluatedAt === null ||
      timestampMs(previous.lastEvaluatedAt, "lastEvaluatedAt") >= asOfMs
    ) {
      throw new Error("alert lifecycle evaluations must be strictly increasing");
    }
  }
  const cooldownUntil = previous.cooldownUntil === null ||
      timestampMs(previous.cooldownUntil, "cooldownUntil") <= asOfMs
    ? null
    : previous.cooldownUntil;
  const state: AlertLifecycleState = {
    ...previous,
    cooldownUntil,
    identity: previous.identity ?? currentIdentity,
    lastEvaluatedAt: asOf,
  };

  if (evaluation.evidence === "unknown") {
    return {
      intent: null,
      state: {
        ...state,
        breachEvidence: null,
        breachSeverity: null,
        consecutiveBreaches: 0,
        consecutiveClears: 0,
        phase: state.status === "none" ? "inactive" : "active",
      },
    };
  }

  const definition = ALERT_RULE_DEFINITIONS[evaluation.ruleId];
  if (evaluation.severity === "none") {
    if (state.status === "none") {
      return {
        intent: null,
        state: {
          ...inactiveAlertState(),
          cooldownUntil: state.cooldownUntil,
          identity: state.identity,
          lastEvaluatedAt: asOf,
        },
      };
    }
    if (definition.resolutionMode === "manual") {
      return stableActiveResult(evaluation, state, asOf, asOfMs, false);
    }
    const consecutiveClears = state.consecutiveClears + 1;
    if (consecutiveClears < ALERT_RULE_POLICY.clearConsecutive) {
      return {
        intent: null,
        state: {
          ...state,
          breachEvidence: null,
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
        identity: state.identity,
        lastEvaluatedAt: asOf,
      },
    };
  }

  if (state.status === "critical") {
    return stableActiveResult(
      evaluation,
      state,
      asOf,
      asOfMs,
      evaluation.severity === "critical",
    );
  }
  if (state.status === "warning" && evaluation.severity === "warning") {
    return stableActiveResult(evaluation, state, asOf, asOfMs, true);
  }

  const candidate = evaluation.severity;
  const breachEvidence = selectedEvidenceFor(evaluation);
  const consecutiveBreaches = startOrContinueBreach(state, candidate);
  const required = evaluation.immediateCritical
    ? 1
    : candidate === "critical"
      ? ALERT_RULE_POLICY.criticalConsecutive
      : ALERT_RULE_POLICY.warningConsecutive;
  const pendingState: AlertLifecycleState = {
    ...state,
    breachEvidence,
    breachSeverity: candidate,
    consecutiveBreaches,
    consecutiveClears: 0,
    phase: state.status === "none" ? "pending" : "active",
  };
  if (consecutiveBreaches < required) {
    return { intent: null, state: pendingState };
  }

  const evidence = breachEvidence;
  if (state.status === "warning" && candidate === "critical") {
    const nextState: AlertLifecycleState = {
      ...pendingState,
      activeEvidence: evidence,
      breachEvidence: null,
      breachSeverity: null,
      consecutiveBreaches: 0,
      lastNotificationAt: asOf,
      phase: "active",
      status: "critical",
    };
    return {
      intent: {
        ...activeIntentBase(evaluation, asOf),
        evidence,
        from: "warning",
        kind: "escalate",
        severity: "critical",
      },
      state: nextState,
    };
  }

  if (state.status === "none") {
    if (state.cooldownUntil !== null && candidate === "warning") {
      return {
        intent: null,
        state: { ...pendingState, consecutiveBreaches: required - 1 },
      };
    }
    const nextState: AlertLifecycleState = {
      ...pendingState,
      activeEvidence: evidence,
      breachEvidence: null,
      breachSeverity: null,
      consecutiveBreaches: 0,
      cooldownUntil: null,
      lastNotificationAt: asOf,
      openedAt: asOf,
      phase: "active",
      status: candidate,
    };
    return {
      intent: {
        ...activeIntentBase(evaluation, asOf),
        evidence,
        kind: "open",
        severity: candidate,
      },
      state: nextState,
    };
  }

  return stableActiveResult(evaluation, state, asOf, asOfMs, false);
}
