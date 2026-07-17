import type { Context, MiddlewareHandler } from "hono";

import { readRuntimeConfig } from "./config";

type AppEnv = { Bindings: Env };

export function recoveryDisabledResponse(
  c: Context<AppEnv>,
): Response | null {
  if (readRuntimeConfig(c.env).recoveryEnabled) return null;
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  return c.json({ error: "not_found" }, 404);
}

export const requireRecoveryEnabled: MiddlewareHandler<AppEnv> = async (
  c,
  next,
) => {
  const disabled = recoveryDisabledResponse(c);
  if (disabled) return disabled;
  await next();
};
