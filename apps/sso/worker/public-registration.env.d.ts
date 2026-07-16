interface __PublicRegistrationBindings {
  PRIVACY_VERSION?: string;
  TERMS_VERSION?: string;
  TURNSTILE_SECRET_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
}

interface Env extends __PublicRegistrationBindings {}

declare namespace Cloudflare {
  interface Env extends __PublicRegistrationBindings {}
}
