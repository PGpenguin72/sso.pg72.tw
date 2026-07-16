import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createAuditEvent,
  enqueueSecurityEvent,
  type WaitUntilContext,
} from "../worker/audit";

function testEvent() {
  return createAuditEvent({
    eventType: "oauth_client.secret_rotated",
    outcome: "success",
    clientId: "queue-test-client",
  });
}

function queueEnv(send: () => Promise<void>): Env {
  return {
    SECURITY_EVENTS: { send },
  } as unknown as Env;
}

function capturingContext(promises: Promise<unknown>[]): WaitUntilContext {
  return {
    waitUntil(promise) {
      promises.push(promise);
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Security event queue fan-out", () => {
  it("contains synchronous Queue.send failures after a response is committed", async () => {
    const event = testEvent();
    const pending: Promise<unknown>[] = [];
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const env = queueEnv(() => {
      throw new Error("sensitive queue failure detail");
    });

    await expect(
      enqueueSecurityEvent(env, event, capturingContext(pending)),
    ).resolves.toBeUndefined();
    await expect(Promise.all(pending)).resolves.toBeDefined();

    expect(log).toHaveBeenCalledOnce();
    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toEqual({
      event: "security_event_enqueue_failed",
      eventId: event.eventId,
      eventType: event.eventType,
      stage: "queue_send",
      error: "Error",
    });
    expect(String(log.mock.calls[0]?.[0])).not.toContain("sensitive");
  });

  it("contains asynchronous Queue.send rejections", async () => {
    const event = testEvent();
    const pending: Promise<unknown>[] = [];
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const env = queueEnv(() => Promise.reject(new TypeError("queue rejected")));

    await expect(
      enqueueSecurityEvent(env, event, capturingContext(pending)),
    ).resolves.toBeUndefined();
    await expect(Promise.all(pending)).resolves.toBeDefined();

    expect(log).toHaveBeenCalledOnce();
    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toMatchObject({
      event: "security_event_enqueue_failed",
      stage: "queue_send",
      error: "TypeError",
    });
  });

  it("awaits the send attempt when waitUntil registration throws", async () => {
    const event = testEvent();
    const send = vi.fn(() => Promise.resolve());
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const executionCtx: WaitUntilContext = {
      waitUntil() {
        throw new Error("context closed");
      },
    };

    await expect(
      enqueueSecurityEvent(queueEnv(send), event, executionCtx),
    ).resolves.toBeUndefined();

    expect(send).toHaveBeenCalledOnce();
    expect(JSON.parse(String(log.mock.calls[0]?.[0]))).toMatchObject({
      event: "security_event_enqueue_failed",
      stage: "wait_until",
      error: "Error",
    });
  });
});
