export interface DurableDeliveryPolicy {
  backoffSeconds: readonly [number, ...number[]];
  maxAttempts: number;
}

export interface DeliveryAttemptOutcome {
  delivered: boolean;
  transient: boolean;
}

export type DeliveryDisposition =
  | { status: "dead" | "delivered" }
  | { delaySeconds: number; status: "retry" };

interface ChangeResult {
  meta: {
    changes: number;
  };
}

export function addIsoSeconds(iso: string, seconds: number): string {
  return new Date(new Date(iso).getTime() + seconds * 1000).toISOString();
}

export function selectDeliveryDisposition(
  attempt: number,
  outcome: DeliveryAttemptOutcome,
  policy: DurableDeliveryPolicy,
): DeliveryDisposition {
  if (outcome.delivered) return { status: "delivered" };
  if (!outcome.transient || attempt >= policy.maxAttempts) {
    return { status: "dead" };
  }

  return {
    delaySeconds:
      policy.backoffSeconds[
        Math.min(attempt - 1, policy.backoffSeconds.length - 1)
      ],
    status: "retry",
  };
}

export function selectExpiredLeaseDisposition(
  attempt: number,
  policy: DurableDeliveryPolicy,
): "dead" | "retry" {
  return attempt >= policy.maxAttempts ? "dead" : "retry";
}

export function allChangedExactlyOnce(
  ...results: readonly (ChangeResult | undefined)[]
): boolean {
  return results.length > 0 && results.every(
    (result) => result?.meta.changes === 1,
  );
}
