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

export interface WaitUntilContext {
  waitUntil(promise: Promise<unknown>): void;
}

interface RecordAuditInput {
  eventType: string;
  outcome: AuditOutcome;
  actorUserId?: string;
  clientId?: string;
  subjectId?: string;
  metadata?: AuditMetadata;
}

export async function recordAudit(
  env: Env,
  input: RecordAuditInput,
  executionCtx?: WaitUntilContext,
): Promise<void> {
  const event: SecurityEvent = {
    eventId: crypto.randomUUID(),
    eventType: input.eventType,
    occurredAt: new Date().toISOString(),
    outcome: input.outcome,
    actorUserId: input.actorUserId,
    clientId: input.clientId,
    subjectId: input.subjectId,
    metadata: input.metadata,
  };

  await env.PG72_ID_DB.prepare(
    `INSERT INTO audit_event
      (id, event_type, actor_user_id, client_id, subject_id, outcome,
       metadata_json, occurred_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      event.eventId,
      event.eventType,
      event.actorUserId ?? null,
      event.clientId ?? null,
      event.subjectId ?? null,
      event.outcome,
      event.metadata ? JSON.stringify(event.metadata) : null,
      event.occurredAt,
    )
    .run();

  const queued = env.SECURITY_EVENTS.send(event);
  if (executionCtx) {
    executionCtx.waitUntil(queued);
  } else {
    await queued;
  }
}

export async function consumeSecurityEvents(
  batch: MessageBatch<SecurityEvent>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
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
}
