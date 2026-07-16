# 串接總覽

這一章帶開發者從零把服務接上 PGID。需要實作端點與參數時，接著看 [跑通 OIDC 登入流程](oidc-flow.md)。

## PGID 是哪一種身分提供者

PGID 是標準的 **OAuth 2.1 / OpenID Connect** 身分提供者：

* Issuer：`https://sso.pg72.tw`
* Flow：Authorization Code + PKCE S256（唯一支援的瀏覽器登入流程）
* Discovery：`https://sso.pg72.tw/.well-known/openid-configuration`
* ID token 簽章：EdDSA（用 JWKS 驗章）

任何符合規範的 OIDC client library（`oauth4webapi`、`openid-client`、Authlib、各語言 SDK）都能接。

## 整體流程（心智模型）

```text
你的服務(RP)  →  導使用者到 PGID authorize 端點
PGID          →  使用者登入(Google/Passkey) + consent 授權
PGID          →  帶 code 導回你的 redirect_uri
你的服務(後端) →  用 code + PKCE verifier 換 token
你的服務(後端) →  驗 ID token、取 UserInfo、以 sub 建立本機 session
```

關鍵原則：

* **後端交換 code**：token 交換在你的伺服器端做，token 不進瀏覽器 `localStorage`。
* **以 `sub` 識別使用者**：不可變的帳號 ID 才是主鍵，email 只作一次性綁定。
* **自己的 session**：登入後建立你服務自己的 server-side session（host-only cookie），保存中央 `sid` 與 `sub`。

## 你需要準備什麼

1. 一個由 PGID 管理員 / developer 建立的 **OAuth client**（見[建立 OAuth Client](register-client.md)）。
2. 一個精確的 **redirect URI**（production 必須 HTTPS）。
3. 後端能保存 client secret（confidential client）或走 public client（無 secret）。

## 三個步驟

1. [建立 OAuth Client](register-client.md)：拿到 `client_id`（與 confidential 的一次性 `client_secret`）。
2. [跑通 OIDC 登入流程](oidc-flow.md)：實作 authorize → callback → token → userinfo。
3. [Consent 與 Scopes](consent-and-scopes.md)：理解授權畫面與你會拿到的 claim。

## 邊界

* **無 dynamic client registration**：client 由管理員明確建立。
* **redirect URI 精確比對**：不允許 wildcard。
* **consent 不可略過**：使用者一定會看到授權畫面。
* **不要送 `resource` 參數**：PGID 目前會拒絕（回 `invalid_target`）。

想直接看可運作範例：`apps/test-rp/worker/index.ts`（`oauth4webapi` 的 public client）。
