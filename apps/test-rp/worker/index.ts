import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { html } from "hono/html";
import * as oauth from "oauth4webapi";

type AppEnv = { Bindings: Env };

interface RuntimeConfig {
  allowInsecureRequests: boolean;
  clientId: string;
  issuer: URL;
  redirectUri: string;
  rpBaseUrl: string;
}

interface OAuthTransaction {
  id: string;
  state: string;
  code_verifier: string;
  nonce: string;
  redirect_uri: string;
  expires_at: string;
  consumed_at: string | null;
}

interface RelyingPartySession {
  id: string;
  subject: string;
  central_session_id: string | null;
  display_name: string | null;
  email: string | null;
  expires_at: string;
}

function exactOrigin(value: string, name: string): string {
  const url = new URL(value);
  if (url.origin !== value || url.username || url.password) {
    throw new Error(`${name} must be an exact origin`);
  }
  return url.origin;
}

function readConfig(env: Env): RuntimeConfig {
  const environment = env.ENVIRONMENT;
  if (!environment || !["development", "preview", "production"].includes(environment)) {
    throw new Error("Invalid ENVIRONMENT");
  }

  const issuer = new URL(exactOrigin(env.OIDC_ISSUER, "OIDC_ISSUER"));
  const rpBaseUrl = exactOrigin(env.RP_BASE_URL, "RP_BASE_URL");
  const clientId = env.OIDC_CLIENT_ID.trim();
  if (!clientId) throw new Error("Missing OIDC_CLIENT_ID");

  if (environment === "production") {
    if (issuer.href !== "https://sso.pg72.tw/") {
      throw new Error("Production issuer must be https://sso.pg72.tw");
    }
    if (!rpBaseUrl.startsWith("https://")) {
      throw new Error("Production RP_BASE_URL must use HTTPS");
    }
  }

  return {
    allowInsecureRequests: environment === "development",
    clientId,
    issuer,
    redirectUri: `${rpBaseUrl}/callback`,
    rpBaseUrl,
  };
}

function client(config: RuntimeConfig): oauth.Client {
  return {
    client_id: config.clientId,
    token_endpoint_auth_method: "none",
    id_token_signed_response_alg: "EdDSA",
  };
}

function requestOptions(config: RuntimeConfig) {
  return {
    signal: AbortSignal.timeout(8_000),
    ...(config.allowInsecureRequests
      ? { [oauth.allowInsecureRequests]: true as const }
      : {}),
  };
}

async function discover(config: RuntimeConfig): Promise<oauth.AuthorizationServer> {
  const response = await oauth.discoveryRequest(config.issuer, {
    algorithm: "oidc",
    ...requestOptions(config),
  });
  return oauth.processDiscoveryResponse(config.issuer, response);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  const bytes = new Uint8Array(digest);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function cookieNames(config: RuntimeConfig) {
  const secure = !config.allowInsecureRequests;
  return {
    secure,
    session: secure ? "__Host-pg72_test_session" : "pg72_test_session",
    transaction: secure ? "__Host-pg72_test_tx" : "pg72_test_tx",
  };
}

const styles = `
  :root { font-family: Inter, ui-sans-serif, system-ui, sans-serif; color: #17191d; background: #f6f7f9; letter-spacing: 0; }
  * { box-sizing: border-box; }
  body { margin: 0; min-width: 320px; min-height: 100vh; }
  main { width: min(100% - 36px, 720px); margin: 0 auto; padding: 64px 0 90px; }
  header { display: flex; align-items: center; justify-content: space-between; gap: 20px; border-bottom: 1px solid #d9dde2; padding-bottom: 22px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 760; }
  .mark { display: grid; width: 34px; height: 34px; place-items: center; border-radius: 6px; background: #17191d; color: #fff; font-size: 11px; }
  .env { border: 1px solid #d8b663; border-radius: 999px; background: #fff8df; color: #79570b; padding: 5px 9px; font-size: 11px; font-weight: 700; }
  h1 { margin: 52px 0 10px; font-size: 29px; }
  .lead { margin: 0; color: #69707a; line-height: 1.65; }
  .protocol { display: grid; grid-template-columns: 1fr 1fr; margin: 36px 0; border-top: 1px solid #dde1e5; }
  .field { min-width: 0; border-bottom: 1px solid #dde1e5; padding: 17px 12px 17px 0; }
  .field:nth-child(odd) { margin-right: 24px; }
  .field span { display: block; color: #737a84; font-size: 10px; font-weight: 740; text-transform: uppercase; }
  .field strong { display: block; margin-top: 7px; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .actions { display: flex; gap: 10px; }
  a.button { display: inline-flex; min-height: 42px; align-items: center; justify-content: center; border: 1px solid #17191d; border-radius: 6px; background: #17191d; color: #fff; padding: 9px 15px; font-weight: 700; text-decoration: none; }
  a.secondary { border-color: #cfd3d9; background: #fff; color: #272a30; }
  .session { margin-top: 38px; border-left: 3px solid #3c9552; background: #fff; padding: 20px 22px; }
  .session h2 { margin: 0 0 16px; font-size: 17px; }
  .session dl { display: grid; gap: 12px; margin: 0; }
  .session div { display: grid; grid-template-columns: 90px minmax(0, 1fr); gap: 16px; }
  dt { color: #747a83; font-size: 11px; }
  dd { margin: 0; overflow-wrap: anywhere; font-size: 13px; font-weight: 620; }
  .error { margin-top: 34px; border: 1px solid #e1b2b2; border-radius: 6px; background: #fff1f1; color: #8b2626; padding: 14px; }
  @media (max-width: 560px) { .protocol { grid-template-columns: 1fr; } .field:nth-child(odd) { margin-right: 0; } .actions { flex-direction: column; } .session div { grid-template-columns: 1fr; gap: 4px; } }
`;

function page(
  config: RuntimeConfig,
  session?: RelyingPartySession | null,
  error?: string,
) {
  return html`<!doctype html>
    <html lang="zh-Hant">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="light" />
        <title>PG72 OIDC Test RP</title>
        <style>${styles}</style>
      </head>
      <body>
        <main>
          <header>
            <div class="brand"><span class="mark">RP</span>OIDC Test RP</div>
            <span class="env">Phase 0</span>
          </header>
          <h1>${session ? "OIDC session established" : "PG72 ID protocol check"}</h1>
          <p class="lead">Authorization Code + PKCE S256</p>
          <div class="protocol">
            <div class="field"><span>Issuer</span><strong>${config.issuer.href.replace(/\/$/, "")}</strong></div>
            <div class="field"><span>Client</span><strong>${config.clientId}</strong></div>
            <div class="field"><span>Redirect URI</span><strong>${config.redirectUri}</strong></div>
            <div class="field"><span>Session storage</span><strong>D1 + HttpOnly cookie</strong></div>
          </div>
          ${error ? html`<div class="error">${error}</div>` : ""}
          ${session
            ? html`<section class="session">
                  <h2>Validated identity</h2>
                  <dl>
                    <div><dt>Subject</dt><dd>${session.subject}</dd></div>
                    <div><dt>SID</dt><dd>${session.central_session_id ?? "not returned"}</dd></div>
                    <div><dt>Name</dt><dd>${session.display_name ?? "not returned"}</dd></div>
                    <div><dt>Email</dt><dd>${session.email ?? "not returned"}</dd></div>
                    <div><dt>Expires</dt><dd>${session.expires_at}</dd></div>
                  </dl>
                </section>
                <div class="actions" style="margin-top: 18px">
                  <a class="button secondary" href="/logout">End RP session</a>
                  <a class="button" href="/login">Run again</a>
                </div>`
            : html`<div class="actions">
                <a class="button" href="/login">Sign in with PG72 ID</a>
              </div>`}
        </main>
      </body>
    </html>`;
}

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  await next();
  c.header("Cache-Control", "no-store");
  c.header(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  );
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
});

app.get("/health", (c) => c.json({ status: "ok", service: "pg72-test-rp" }));

app.get("/", async (c) => {
  const config = readConfig(c.env);
  const names = cookieNames(config);
  const token = getCookie(c, names.session);
  let session: RelyingPartySession | null = null;

  if (token) {
    const hash = await sha256(token);
    session = await c.env.TEST_RP_DB.prepare(
      `SELECT id, subject, central_session_id, display_name, email, expires_at
         FROM rp_session
        WHERE token_hash = ? AND expires_at > ?
        LIMIT 1`,
    )
      .bind(hash, new Date().toISOString())
      .first<RelyingPartySession>();
  }

  return c.html(page(config, session));
});

app.get("/login", async (c) => {
  const config = readConfig(c.env);
  const as = await discover(config);
  if (!as.authorization_endpoint) {
    return c.html(page(config, null, "Discovery did not return an authorization endpoint."), 502);
  }

  const state = oauth.generateRandomState();
  const nonce = oauth.generateRandomNonce();
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
  const transactionId = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000);

  await c.env.TEST_RP_DB.batch([
    c.env.TEST_RP_DB.prepare(
      `DELETE FROM oauth_transaction
        WHERE expires_at <= ? OR consumed_at IS NOT NULL`,
    ).bind(now.toISOString()),
    c.env.TEST_RP_DB.prepare(
      `INSERT INTO oauth_transaction
        (id, state, code_verifier, nonce, redirect_uri, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      transactionId,
      state,
      codeVerifier,
      nonce,
      config.redirectUri,
      expiresAt.toISOString(),
      now.toISOString(),
    ),
  ]);

  const names = cookieNames(config);
  setCookie(c, names.transaction, transactionId, {
    httpOnly: true,
    maxAge: 10 * 60,
    path: "/",
    sameSite: "Lax",
    secure: names.secure,
  });

  const authorizationUrl = new URL(as.authorization_endpoint);
  authorizationUrl.searchParams.set("client_id", config.clientId);
  authorizationUrl.searchParams.set("redirect_uri", config.redirectUri);
  authorizationUrl.searchParams.set("response_type", "code");
  authorizationUrl.searchParams.set("scope", "openid profile email offline_access");
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set("code_challenge_method", "S256");
  authorizationUrl.searchParams.set("state", state);
  authorizationUrl.searchParams.set("nonce", nonce);

  return c.redirect(authorizationUrl.href, 302);
});

app.get("/callback", async (c) => {
  const config = readConfig(c.env);
  const names = cookieNames(config);
  const transactionId = getCookie(c, names.transaction);
  deleteCookie(c, names.transaction, { path: "/", secure: names.secure });

  if (!transactionId) {
    return c.html(page(config, null, "Missing OIDC transaction cookie."), 400);
  }

  const now = new Date().toISOString();
  const transaction = await c.env.TEST_RP_DB.prepare(
    `SELECT id, state, code_verifier, nonce, redirect_uri, expires_at, consumed_at
       FROM oauth_transaction
      WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
      LIMIT 1`,
  )
    .bind(transactionId, now)
    .first<OAuthTransaction>();

  if (!transaction) {
    return c.html(page(config, null, "OIDC transaction expired or was already used."), 400);
  }

  const consumed = await c.env.TEST_RP_DB.prepare(
    `UPDATE oauth_transaction
        SET consumed_at = ?
      WHERE id = ? AND consumed_at IS NULL`,
  )
    .bind(now, transaction.id)
    .run();
  if (consumed.meta.changes !== 1) {
    return c.html(page(config, null, "OIDC transaction replay was rejected."), 400);
  }

  try {
    const as = await discover(config);
    const clientMetadata = client(config);
    const callbackParameters = oauth.validateAuthResponse(
      as,
      clientMetadata,
      new URL(c.req.url),
      transaction.state,
    );

    const tokenResponse = await oauth.authorizationCodeGrantRequest(
      as,
      clientMetadata,
      oauth.None(),
      callbackParameters,
      transaction.redirect_uri,
      transaction.code_verifier,
      requestOptions(config),
    );
    const tokens = await oauth.processAuthorizationCodeResponse(
      as,
      clientMetadata,
      tokenResponse,
      { expectedNonce: transaction.nonce, requireIdToken: true },
    );

    await oauth.validateApplicationLevelSignature(
      as,
      tokenResponse,
      requestOptions(config),
    );
    const claims = oauth.getValidatedIdTokenClaims(tokens);
    if (!claims) throw new Error("Validated ID token claims were not returned");

    const userInfoResponse = await oauth.userInfoRequest(
      as,
      clientMetadata,
      tokens.access_token,
      requestOptions(config),
    );
    const userInfo = await oauth.processUserInfoResponse(
      as,
      clientMetadata,
      claims.sub,
      userInfoResponse,
    );

    const sessionToken = oauth.generateRandomState();
    const sessionHash = await sha256(sessionToken);
    const sessionId = crypto.randomUUID();
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + 12 * 60 * 60 * 1000);
    const name = typeof userInfo.name === "string" ? userInfo.name : null;
    const email = typeof userInfo.email === "string" ? userInfo.email : null;
    const centralSessionId =
      typeof claims.sid === "string" ? claims.sid : null;

    await c.env.TEST_RP_DB.prepare(
      `INSERT INTO rp_session
        (id, token_hash, subject, central_session_id, display_name, email,
         expires_at, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        sessionId,
        sessionHash,
        claims.sub,
        centralSessionId,
        name,
        email,
        expiresAt.toISOString(),
        createdAt.toISOString(),
        createdAt.toISOString(),
      )
      .run();

    setCookie(c, names.session, sessionToken, {
      httpOnly: true,
      maxAge: 12 * 60 * 60,
      path: "/",
      sameSite: "Lax",
      secure: names.secure,
    });

    return c.redirect("/", 303);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "oidc_callback_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    return c.html(page(config, null, "OIDC response validation failed."), 400);
  }
});

app.get("/logout", async (c) => {
  const config = readConfig(c.env);
  const names = cookieNames(config);
  const token = getCookie(c, names.session);
  if (token) {
    await c.env.TEST_RP_DB.prepare("DELETE FROM rp_session WHERE token_hash = ?")
      .bind(await sha256(token))
      .run();
  }
  deleteCookie(c, names.session, { path: "/", secure: names.secure });
  return c.redirect("/", 303);
});

app.onError((error, c) => {
  console.error(
    JSON.stringify({ event: "rp_unhandled_error", error: error.name }),
  );
  const config = readConfig(c.env);
  return c.html(page(config, null, "Test RP request failed."), 500);
});

export default app;
