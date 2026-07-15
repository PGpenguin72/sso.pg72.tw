/* eslint-disable */
// Optional social-login provider secrets.
//
// `wrangler types` only emits `secrets.required` into the generated Env
// interface (see worker-configuration.d.ts), so the optional providers listed
// under `secrets.optional` in wrangler.jsonc are declared here via interface
// merging. Each is `string | undefined`: a provider activates only when its
// value is configured, so reading a missing one must be a compile-time
// possibility (undefined), never an assumed string. This file is hand-authored
// on purpose and is not overwritten by `wrangler types`.
interface __SocialProviderSecrets {
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  FACEBOOK_CLIENT_ID?: string;
  FACEBOOK_CLIENT_SECRET?: string;
  APPLE_CLIENT_ID?: string;
  APPLE_CLIENT_SECRET?: string;
  APPLE_APP_BUNDLE_IDENTIFIER?: string;
  TELEGRAM_BOT_TOKEN?: string;
}

interface Env extends __SocialProviderSecrets {}

declare namespace Cloudflare {
  interface Env extends __SocialProviderSecrets {}
}
