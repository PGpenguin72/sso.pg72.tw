import { describe, expect, it } from "vitest";

import {
  addIsoSeconds,
  allChangedExactlyOnce,
  selectDeliveryDisposition,
  selectExpiredLeaseDisposition,
  type DurableDeliveryPolicy,
} from "../worker/durable-delivery";

const LOGOUT_POLICY = {
  backoffSeconds: [10, 30, 120, 300, 900],
  maxAttempts: 5,
} as const satisfies DurableDeliveryPolicy;

describe("durable delivery helpers", () => {
  it("adds lease and retry seconds without changing ISO precision", () => {
    expect(addIsoSeconds("2026-07-17T01:02:03.456Z", 30)).toBe(
      "2026-07-17T01:02:33.456Z",
    );
    expect(addIsoSeconds("2026-07-17T01:02:03.456Z", 900)).toBe(
      "2026-07-17T01:17:03.456Z",
    );
  });

  it.each([
    { attempt: 1, delaySeconds: 10, status: "retry" },
    { attempt: 2, delaySeconds: 30, status: "retry" },
    { attempt: 3, delaySeconds: 120, status: "retry" },
    { attempt: 4, delaySeconds: 300, status: "retry" },
    { attempt: 5, delaySeconds: undefined, status: "dead" },
  ] as const)(
    "selects logout retry disposition for attempt $attempt",
    ({ attempt, delaySeconds, status }) => {
      expect(
        selectDeliveryDisposition(
          attempt,
          { delivered: false, transient: true },
          LOGOUT_POLICY,
        ),
      ).toEqual(
        status === "retry" ? { delaySeconds, status } : { status },
      );
    },
  );

  it.each([1, 2, 3, 4, 5])(
    "selects success and permanent-failure dispositions at attempt %i",
    (attempt) => {
      expect(
        selectDeliveryDisposition(
          attempt,
          { delivered: true, transient: true },
          LOGOUT_POLICY,
        ),
      ).toEqual({ status: "delivered" });
      expect(
        selectDeliveryDisposition(
          attempt,
          { delivered: false, transient: false },
          LOGOUT_POLICY,
        ),
      ).toEqual({ status: "dead" });
    },
  );

  it.each([
    { attempt: 1, status: "retry" },
    { attempt: 2, status: "retry" },
    { attempt: 3, status: "retry" },
    { attempt: 4, status: "retry" },
    { attempt: 5, status: "dead" },
  ] as const)(
    "selects expired-lease disposition at attempt $attempt",
    ({ attempt, status }) => {
      expect(selectExpiredLeaseDisposition(attempt, LOGOUT_POLICY)).toBe(status);
    },
  );

  it.each([
    [],
    [undefined],
    [undefined, 1],
    [1, undefined],
    [0, 1],
    [1, 0],
    [2, 1],
    [1, 2],
    [0, 1, 1],
    [1, 0, 1],
    [1, 1, 0],
    [2, 1, 1],
    [1, 2, 1],
    [1, 1, 2],
  ])("rejects non-exact CAS changes %j", (...changes) => {
    const result = (changes: number | undefined) =>
      changes === undefined ? undefined : { meta: { changes } };
    expect(allChangedExactlyOnce(...changes.map(result))).toBe(false);
  });

  it("accepts one or more exact one-change CAS results", () => {
    const changed = { meta: { changes: 1 } };
    expect(allChangedExactlyOnce(changed)).toBe(true);
    expect(allChangedExactlyOnce(changed, changed)).toBe(true);
    expect(allChangedExactlyOnce(changed, changed, changed)).toBe(true);
  });
});
