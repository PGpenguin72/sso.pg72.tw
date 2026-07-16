# 跑通 OIDC 登入流程

這一頁用 `oauth4webapi` 走完一次完整登入。可運作的完整範例是 `apps/test-rp/worker/index.ts`；使用其他語言或 library 時，仍須遵守本頁相同的 discovery、state / nonce、PKCE S256、issuer / audience / 簽章驗證與後端 session 契約。

## 前置

已有 `client_id`（confidential 另有 `client_secret`）與精確 redirect URI。

## 步驟 1：抓 discovery

```ts
import * as oauth from "oauth4webapi";

const issuer = new URL("https://sso.pg72.tw");
const as = await oauth.processDiscoveryResponse(
  issuer,
  await oauth.discoveryRequest(issuer, { algorithm: "oidc" }),
);
```

## 步驟 2：發起授權（產生並保存 state / nonce / PKCE）

在**後端**產生 `state`、`nonce`、`code_verifier` 並保存（例如存 D1 交易紀錄），瀏覽器只拿到一個 HttpOnly 交易 cookie。

```ts
const state = oauth.generateRandomState();
const nonce = oauth.generateRandomNonce();
const codeVerifier = oauth.generateRandomCodeVerifier();
const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

await saveTransaction({ state, nonce, codeVerifier, redirectUri });

const url = new URL(as.authorization_endpoint!);
url.searchParams.set("client_id", clientId);
url.searchParams.set("redirect_uri", redirectUri);
url.searchParams.set("response_type", "code");
url.searchParams.set("scope", "openid profile email offline_access");
url.searchParams.set("code_challenge", codeChallenge);
url.searchParams.set("code_challenge_method", "S256");
url.searchParams.set("state", state);
url.searchParams.set("nonce", nonce);
// 302 導向 url.href
```

使用者接著在 PGID 完成 Google 或 Passkey 登入，並在 consent 畫面授權。

## 步驟 3：Callback——驗 state、換 token、驗 ID token

PGID 會帶 `code` / `state` / `iss` 導回你的 redirect URI。

```ts
const tx = await loadAndConsumeTransaction(transactionId); // 一次性，重放即拒絕

const client: oauth.Client = {
  client_id: clientId,
  // public client：token_endpoint_auth_method: "none"
  id_token_signed_response_alg: "EdDSA",
};

// 驗 state 與 authorization response（含 iss）
const params = oauth.validateAuthResponse(as, client, new URL(request.url), tx.state);

// public 用 oauth.None()；confidential 用 oauth.ClientSecretPost(clientSecret)
const clientAuth = oauth.ClientSecretPost(clientSecret);

const tokenResponse = await oauth.authorizationCodeGrantRequest(
  as, client, clientAuth, params, tx.redirectUri, tx.codeVerifier,
);

const tokens = await oauth.processAuthorizationCodeResponse(
  as, client, tokenResponse,
  { expectedNonce: tx.nonce, requireIdToken: true },
);
await oauth.validateApplicationLevelSignature(as, tokenResponse);

const claims = oauth.getValidatedIdTokenClaims(tokens);
if (!claims) throw new Error("missing id token claims");
```

`oauth4webapi` 已內建 issuer / audience / nonce / 簽章 / PKCE 驗證，不要自己手寫 JWT 驗證。

## 步驟 4：取 UserInfo 並檢查 email_verified

```ts
const userInfo = await oauth.processUserInfoResponse(
  as, client, claims.sub,
  await oauth.userInfoRequest(as, client, tokens.access_token),
);

if (userInfo.email && userInfo.email_verified !== true) {
  throw new Error("email not verified");
}
```

## 步驟 5：以 sub 建立本機 session

```ts
if (typeof claims.sid !== "string" || claims.sid.length === 0) {
  throw new Error("missing central session id");
}

await createLocalSession({
  subject: claims.sub,                                   // 主鍵：不可變
  sid: claims.sid,
  email: typeof userInfo.email === "string" ? userInfo.email : null,
});
```

* 用 `sub` 對應你服務裡的帳號，不要用 email。
* 建立你服務自己的 server-side session（host-only、`Secure`、`HttpOnly` cookie），保存 nonempty `sid` + `sub`；ID token 缺少 `sid` 時中止 callback，不建立本機 session。
* token 存後端，不進 `localStorage`。

## 錯誤處理

* 使用者取消 → authorization response 帶 `error=access_denied`，優雅顯示並讓他重試。
* `state` 不符 / 交易過期 / 重放 → 中止並要求重新登入。
* token 端點 `invalid_grant`（code 過期或已用）、`invalid_client`（認證失敗）→ 依情況重試或回報。
* 不要在錯誤訊息洩漏帳號是否存在；log 遮蔽 token / code / 完整 email / IP。

## Refresh 與登出

* 有 `offline_access` 時會拿到 refresh token（30 天、rotation）。每次 refresh 後改存新的 refresh token 並丟棄舊的。原 central session 不存在、過期或不再屬於同一 user 時，PGID 以 `invalid_grant` fail closed。
* 登出：先清你服務自己的 session。每個 user ID token 都帶 central `sid`；PGID 的 visited-client ledger/durable delivery 已在 local source 完成，但 migration、Queue/DLQ 與各 RP receiver 尚未 rollout。Client 設定 `backchannelLogoutUri` 時，依 [Back-Channel Logout](backchannel-logout.md) 驗完整 logout token、以 `jti` 冪等並依 `sid` 刪除本機 sessions。`enableEndSession` 只控制 client 能否呼叫 `end_session_endpoint`，不控制 `sid` claim。

## 下一步

[Consent 與 Scopes](consent-and-scopes.md)
