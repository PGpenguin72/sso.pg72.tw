export const ALERT_EVALUATOR_SOURCE_IDS = Object.freeze([
  "queue.security_events_dlq",
  "queue.logout_deliveries_dlq",
  "queue.alert_deliveries_dlq",
  "queue.audit_archive_dlq",
  "d1.audit",
  "d1.oauth_client_report",
  "d1.security_fanout_gap",
  "d1.logout_delivery",
  "d1.alert_runtime",
] as const);

export type AlertEvaluatorSourceId =
  (typeof ALERT_EVALUATOR_SOURCE_IDS)[number];
export type AlertEvaluatorSourceStatus =
  | "complete"
  | "invalid"
  | "partial"
  | "unavailable";
export type AlertEvaluatorDecisionDisposition =
  | "applied"
  | "no_state_change"
  | "suppressed_partial";

export interface AlertEvaluatorSourceProofValue {
  incompleteCount: number;
  observationCount: number;
  proofSha256: string;
  sourceId: AlertEvaluatorSourceId;
  status: AlertEvaluatorSourceStatus;
}

export interface AlertEvaluatorDecisionProofValue {
  decisionSha256: string;
  disposition: AlertEvaluatorDecisionDisposition;
  evaluationSha256: string;
  identitySha256: string;
  ordinal: number;
  sourceId: AlertEvaluatorSourceId;
}

const SOURCE_ID_SET = new Set<string>(ALERT_EVALUATOR_SOURCE_IDS);
const SOURCE_STATUS_SET = new Set<string>([
  "complete",
  "invalid",
  "partial",
  "unavailable",
]);
const DECISION_DISPOSITION_SET = new Set<string>([
  "applied",
  "no_state_change",
  "suppressed_partial",
]);
const BASE64URL_SHA256 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("invalid alert run proof");
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw new TypeError("invalid alert run proof");
  }
  return record;
}

function boundedInteger(value: unknown, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new TypeError("invalid alert run proof");
  }
  return value;
}

export function parseAlertEvaluatorSourceId(
  value: unknown,
): AlertEvaluatorSourceId {
  if (typeof value !== "string" || !SOURCE_ID_SET.has(value)) {
    throw new TypeError("invalid alert run proof");
  }
  return value as AlertEvaluatorSourceId;
}

export function parseAlertEvaluatorDigest(value: unknown): string {
  if (typeof value !== "string" || !BASE64URL_SHA256.test(value)) {
    throw new TypeError("invalid alert run proof");
  }
  return value;
}

export function parseAlertEvaluatorSourceProofValue(
  value: unknown,
): AlertEvaluatorSourceProofValue {
  const record = exactRecord(value, [
    "incompleteCount",
    "observationCount",
    "proofSha256",
    "sourceId",
    "status",
  ]);
  const status = record.status;
  if (typeof status !== "string" || !SOURCE_STATUS_SET.has(status)) {
    throw new TypeError("invalid alert run proof");
  }
  const observationCount = boundedInteger(record.observationCount, 10_000);
  const incompleteCount = boundedInteger(record.incompleteCount, 10_000);
  if (
    (status === "complete" && incompleteCount !== 0) ||
    (status === "partial" && incompleteCount === 0) ||
    ((status === "invalid" || status === "unavailable") &&
      (observationCount !== 0 || incompleteCount !== 0))
  ) {
    throw new TypeError("invalid alert run proof");
  }
  return {
    incompleteCount,
    observationCount,
    proofSha256: parseAlertEvaluatorDigest(record.proofSha256),
    sourceId: parseAlertEvaluatorSourceId(record.sourceId),
    status: status as AlertEvaluatorSourceStatus,
  };
}

export function parseAlertEvaluatorDecisionProofValue(
  value: unknown,
): AlertEvaluatorDecisionProofValue {
  const record = exactRecord(value, [
    "decisionSha256",
    "disposition",
    "evaluationSha256",
    "identitySha256",
    "ordinal",
    "sourceId",
  ]);
  const disposition = record.disposition;
  if (
    typeof disposition !== "string" ||
    !DECISION_DISPOSITION_SET.has(disposition)
  ) {
    throw new TypeError("invalid alert run proof");
  }
  return {
    decisionSha256: parseAlertEvaluatorDigest(record.decisionSha256),
    disposition: disposition as AlertEvaluatorDecisionDisposition,
    evaluationSha256: parseAlertEvaluatorDigest(record.evaluationSha256),
    identitySha256: parseAlertEvaluatorDigest(record.identitySha256),
    ordinal: boundedInteger(record.ordinal, 9_999),
    sourceId: parseAlertEvaluatorSourceId(record.sourceId),
  };
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function canonicalDigest(value: unknown): Promise<string> {
  return bytesToBase64url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(JSON.stringify(value)),
      ),
    ),
  );
}

function rejectSparse(values: readonly unknown[]): void {
  for (let index = 0; index < values.length; index += 1) {
    if (!Object.hasOwn(values, index)) {
      throw new TypeError("invalid alert run proof");
    }
  }
}

export async function alertEvaluatorSourceManifestDigest(
  values: readonly AlertEvaluatorSourceProofValue[],
): Promise<string> {
  if (values.length !== ALERT_EVALUATOR_SOURCE_IDS.length) {
    throw new TypeError("invalid alert run proof");
  }
  rejectSparse(values);
  const bySource = new Map(
    values.map((value) => {
      const parsed = parseAlertEvaluatorSourceProofValue(value);
      return [parsed.sourceId, parsed] as const;
    }),
  );
  if (bySource.size !== ALERT_EVALUATOR_SOURCE_IDS.length) {
    throw new TypeError("invalid alert run proof");
  }
  return canonicalDigest([
    "pgid.alert.evaluator.source-manifest.v1",
    ...ALERT_EVALUATOR_SOURCE_IDS.map((sourceId) => {
      const value = bySource.get(sourceId);
      if (!value) throw new TypeError("invalid alert run proof");
      return {
        sourceId: value.sourceId,
        status: value.status,
        observationCount: value.observationCount,
        incompleteCount: value.incompleteCount,
        proofSha256: value.proofSha256,
      };
    }),
  ]);
}

export async function alertEvaluatorDecisionManifestDigest(
  values: readonly AlertEvaluatorDecisionProofValue[],
): Promise<string> {
  if (values.length > 10_000) throw new TypeError("invalid alert run proof");
  rejectSparse(values);
  const parsed = values.map(parseAlertEvaluatorDecisionProofValue);
  const identities = new Set<string>();
  for (const [ordinal, value] of parsed.entries()) {
    if (value.ordinal !== ordinal || identities.has(value.identitySha256)) {
      throw new TypeError("invalid alert run proof");
    }
    identities.add(value.identitySha256);
  }
  return canonicalDigest([
    "pgid.alert.evaluator.decision-manifest.v1",
    ...parsed.map((value) => ({
      ordinal: value.ordinal,
      sourceId: value.sourceId,
      identitySha256: value.identitySha256,
      evaluationSha256: value.evaluationSha256,
      decisionSha256: value.decisionSha256,
      disposition: value.disposition,
    })),
  ]);
}
