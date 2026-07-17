import {
  ADMIN_ACTOR_COMMIT_PREDICATE,
  adminActorCommitBindings,
  type AdminActorCommitGuard,
} from "./admin-commit";

export type AuditOutcome = "success" | "denied" | "failure";

/**
 * Structured audit metadata. Values must never contain tokens, secrets, or
 * PII such as full email addresses; keep them to enums, counters, and IDs.
 */
export type AuditMetadata = Record<string, string | number | boolean>;

export interface SecurityEvent {
  eventId: string;
  eventType: string;
  occurredAt: string;
  outcome: AuditOutcome;
  actorUserId?: string;
  clientId?: string;
  subjectId?: string;
  metadata?: AuditMetadata;
}

export function isSecurityEvent(value: unknown): value is SecurityEvent {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SecurityEvent>;
  return (
    typeof candidate.eventId === "string" &&
    candidate.eventId.length > 0 &&
    typeof candidate.eventType === "string" &&
    candidate.eventType.length > 0 &&
    typeof candidate.occurredAt === "string" &&
    (candidate.outcome === "success" ||
      candidate.outcome === "denied" ||
      candidate.outcome === "failure")
  );
}

export interface WaitUntilContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface RecordAuditInput {
  eventType: string;
  outcome: AuditOutcome;
  actorUserId?: string;
  clientId?: string;
  subjectId?: string;
  metadata?: AuditMetadata;
}

export interface ExistingClientAuditGuard {
  actor: AdminActorCommitGuard;
  clientId: string;
  clientRowId: string;
  /** Omitted for actors with clients.manage_all. */
  expectedOwnerUserId?: string;
  /** Omitted when the mutation does not use optimistic concurrency. */
  expectedUpdatedAt?: string | null;
}

export interface InvitationMutationAuditGuard {
  actorUserId: string;
  email: string;
  invitationId: string;
  role: string;
}

export interface ExistingOAuthReportAuditGuard {
  actor: AdminActorCommitGuard;
  reportId: string;
}

export interface ExistingUserAuditGuard {
  actor: AdminActorCommitGuard;
  expectedAccessLevel: string;
  expectedRole: string | null;
  expectedStatus: string;
  userId: string;
}

/**
 * Writes the success audit only for the exact invitation row produced by the
 * preceding statement in the same D1 batch. Eligibility belongs to that
 * mutation statement; this dependency makes an audit error roll the mutation
 * back while an eligibility no-op leaves neither row behind.
 */
export function auditInsertForInvitationMutationStatement(
  env: Env,
  event: SecurityEvent,
  guard: InvitationMutationAuditGuard,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM invitation
         WHERE id = ?
           AND email_normalized = ?
           AND role = ?
           AND created_by_user_id = ?
      )`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    guard.invitationId,
    guard.email,
    guard.role,
    guard.actorUserId,
  );
}

export function auditInsertForOpenOAuthReportStatement(
  env: Env,
  event: SecurityEvent,
  guard: ExistingOAuthReportAuditGuard,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM oauth_client_report
         WHERE id = ? AND status = 'open'
      )
        AND ${ADMIN_ACTOR_COMMIT_PREDICATE}`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    guard.reportId,
    ...adminActorCommitBindings(guard.actor),
  );
}

export function createAuditEvent(input: RecordAuditInput): SecurityEvent {
  return {
    eventId: crypto.randomUUID(),
    eventType: input.eventType,
    occurredAt: new Date().toISOString(),
    outcome: input.outcome,
    actorUserId: input.actorUserId,
    clientId: input.clientId,
    subjectId: input.subjectId,
    metadata: input.metadata,
  };
}

export function auditInsertStatement(
  env: Env,
  event: SecurityEvent,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
  );
}

export function auditInsertForExistingClientStatement(
  env: Env,
  event: SecurityEvent,
  guard: ExistingClientAuditGuard,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM oauthClient
         WHERE id = ?
           AND clientId = ?
           AND (? IS NULL OR ownerUserId = ?)
           AND (? = 0 OR updatedAt IS ?)
      )
        AND ${ADMIN_ACTOR_COMMIT_PREDICATE}`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    guard.clientRowId,
    guard.clientId,
    guard.expectedOwnerUserId ?? null,
    guard.expectedOwnerUserId ?? null,
    guard.expectedUpdatedAt === undefined ? 0 : 1,
    guard.expectedUpdatedAt ?? null,
    ...adminActorCommitBindings(guard.actor),
  );
}

export function auditInsertForExistingUserStatement(
  env: Env,
  event: SecurityEvent,
  guard: ExistingUserAuditGuard,
): D1PreparedStatement {
  return env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1
          FROM user
         WHERE id = ?
           AND accessLevel = ?
           AND role IS ?
           AND status = ?
      )
        AND ${ADMIN_ACTOR_COMMIT_PREDICATE}`,
  ).bind(
    event.eventId,
    event.eventType,
    event.actorUserId ?? null,
    event.clientId ?? null,
    event.subjectId ?? null,
    event.outcome,
    event.metadata ? JSON.stringify(event.metadata) : null,
    event.occurredAt,
    guard.userId,
    guard.expectedAccessLevel,
    guard.expectedRole,
    guard.expectedStatus,
    ...adminActorCommitBindings(guard.actor),
  );
}

function logSecurityEventEnqueueFailure(
  event: SecurityEvent,
  stage: "queue_send" | "wait_until",
  error: unknown,
): void {
  console.error(
    JSON.stringify({
      event: "security_event_enqueue_failed",
      eventId: event.eventId,
      eventType: event.eventType,
      stage,
      error: error instanceof Error ? error.name : "UnknownError",
    }),
  );
}

export async function enqueueSecurityEvent(
  env: Env,
  event: SecurityEvent,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  if (!executionCtx) {
    await env.SECURITY_EVENTS.send(event);
    return;
  }

  const queued = Promise.resolve()
    .then(() => env.SECURITY_EVENTS.send(event))
    .catch((error: unknown) => {
      logSecurityEventEnqueueFailure(event, "queue_send", error);
    });

  try {
    executionCtx.waitUntil(queued);
  } catch (error) {
    logSecurityEventEnqueueFailure(event, "wait_until", error);
    await queued;
  }
}

export async function recordAudit(
  env: Env,
  input: RecordAuditInput,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  const event = createAuditEvent(input);
  await auditInsertStatement(env, event).run();
  await enqueueSecurityEvent(env, event, executionCtx);
}

export async function consumeSecurityEvents(
  batch: MessageBatch<SecurityEvent>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
    await consumeSecurityEventMessage(message, env);
  }
}

export async function consumeSecurityEventMessage(
  message: Message<SecurityEvent>,
  env: Env,
): Promise<void> {
  try {
    await env.PG72_ID_DB.prepare(
      `INSERT OR IGNORE INTO security_event_delivery
        (event_id, delivered_at)
       VALUES (?, ?)`,
    )
      .bind(message.body.eventId, new Date().toISOString())
      .run();
    message.ack();
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "security_event_delivery_failed",
        eventId: message.body.eventId,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    message.retry();
  }
}
