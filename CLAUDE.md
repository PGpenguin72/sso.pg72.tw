# PGID 實作守則

本檔案是 coding-agent 與 contributor 的精簡守則。完整且唯一的架構規格是 [`codex.md`](./codex.md)；若本檔案、issue、舊程式或註解與 `codex.md` 衝突，以 `codex.md` 為準，並在同一變更中修正過期文件。

## 已確認產品邊界

- Issuer 固定為 `https://sso.pg72.tw`。
- SSO 由 PG72 自行掌控，不使用 Cloudflare Access 作登入或授權層。
- v1 日常登入主力是 Google 與 Passkey。
- v1 程式另支援 Discord、GitHub、Facebook、Apple、Telegram 社群登入作為額外選項；只有設定對應 secret 的 provider 才會啟用，未設定時自動隱藏且不影響 Google/Passkey。
- v1 不提供密碼、Email OTP 或 TOTP 登入。
- Production `REGISTRATION_MODE` 目前是 `invite`。公開註冊程式路徑與測試已備妥，但必須在 `codex.md` §9.2 的安全 gate 通過並由 owner 明確切換後才可開啟；邀請功能在兩種模式都保留。
- Public path 的 Google 首次登入只接受 verified email；Passkey 註冊仍需先有帳號與已登入 session。文件不得把「程式已備妥」寫成「已公開」。
- 必須支援裝置 session、單一/全部撤銷、全域登出、audit 與管理員停權。
- 不共用 `Domain=.pg72.tw` cookie。所有 app 使用 OIDC redirect 與自己的 host-only session。
- Email 不是使用者主鍵；所有服務以不可變 OIDC `sub` 識別使用者。
- Dynamic client registration 關閉。Client、redirect URI 與 scopes 由管理員明確建立。

## Canonical 技術方向

- Cloudflare Workers + D1。
- TypeScript + Hono + React + Workers Static Assets。
- Better Auth + `@better-auth/oauth-provider` + `@better-auth/passkey`。
- OAuth 2.1 / OpenID Connect Authorization Code + PKCE S256。
- Cloudflare Queues 處理 back-channel logout delivery 與 audit fan-out。
- Workers Rate Limiting binding 處理安全節流；不使用 KV 作精確 rate-limit counter。
- D1 是 session/token revocation 的 source of truth；Queue 不是。

截至 2026-07-15，已查詢 npm stable tag：

- `better-auth@1.6.23`
- `@better-auth/oauth-provider@1.6.23`
- `1.7` 仍為 RC，不可用於 production auth core。

真正安裝時必須重新查詢 stable tag 與 security advisories。Core 與所有 `@better-auth/*` plugins 使用 exact pin、相同 patch line，不使用 `^` 或 `~`。

目前 `@better-auth/oauth-provider@1.6.23` 有 Moderate `GHSA-p2fr-6hmx-4528`，stable `1.6.x` 尚無修補版。依 [`SECURITY.md`](./SECURITY.md) 保持單一 audience 並在 Worker 拒絕所有 RFC 8707 `resource` 參數；不得移除補償控制，直到已修正的 stable 版本完成 migration 與 protocol regression。

## Better Auth GO/NO-GO

在建立完整 UI 或遷移 production app 前，必須先完成最小 Worker + D1 + test RP prototype，驗證：

- Google -> SSO -> RP 完整 OIDC flow。
- Passkey 在 OAuth authorize flow 中能登入並正確返回 RP。
- PKCE、nonce、state、issuer、audience、redirect URI 與 code replay protection。
- Revocation、introspection、key rotation 與 JWKS cache。
- 取消中的 requests 與 isolate reuse 不會讓 auth endpoints 永久 hang。

目前上游 open risks：

- Better Auth #8081：Passkey + OAuth Provider authorize flow。
- Better Auth #10315：Cloudflare Worker aborted request 可能污染 isolate lazy promise。
- Better Auth #4203：secondary storage TTL/session 行為。

不可把 issue comment 中的 workaround 直接當正式設計。Workaround 必須固定為可追蹤的 package patch、附 regression test，並在每次升級重新驗證。Prototype 不通過時停止 Workers 方案，依 `codex.md` 改用 VPS runtime，同時保留相同 Issuer 與 RP contract。

## Workers 規則

- 新 Worker 使用 `wrangler.jsonc`。
- 新專案 `compatibility_date` 使用建立當日日期，啟用 `nodejs_compat`。
- 使用 `wrangler types` 產生 binding types，不手寫 `Env`，不用 `any` 或 double cast 掩蓋型別問題。
- Better Auth 以 request-scoped factory 從 `c.env` 建立；不可把 request state 或 D1 binding 放入 module-level mutable singleton。
- 每個 Promise 必須 `await`、`return` 或交給 `ctx.waitUntil()`。
- Session、token、revocation 與 audit source-of-truth 寫入必須在回應前完成，不能只丟進 `waitUntil()`。
- Worker-to-Worker 使用 Service Bindings；Cloudflare storage 使用 bindings，不在 Worker 內呼叫 Cloudflare REST API。
- 大型或未知大小 body 必須 streaming，不呼叫無上限的 `response.text()` / `arrayBuffer()`。
- 不使用 `passThroughOnException()`。
- Token、code、session ID 與 security nonce 使用 Web Crypto，不使用 `Math.random()`。
- Production 開啟 structured logs/traces；任何 token、secret、authorization code、Passkey challenge、完整 Email/IP 都要 redaction。
- Secret 使用 Wrangler secrets/Secrets Store，不放在 `wrangler.jsonc`、D1、source、log 或 client bundle。

## Auth 與 Session 規則

- Passkey RP ID 是 `sso.pg72.tw`，expected origin 是 `https://sso.pg72.tw`；不得擴大成 `pg72.tw`。
- 關閉 implicit account linking；同 Email 帳號只能在已登入 session 中明確連結。
- OIDC clients 精確比對 HTTPS redirect URI，production 不允許 wildcard。
- 現行第一方 confidential RP 在 token endpoint 使用 `client_secret_post`；Better Auth `1.6.23` 的 HTTP Basic 互通問題未有可追蹤 patch 與 regression test 前，不改回 `client_secret_basic`。
- Web app callback 在 backend 交換 code；token 不進 `localStorage`。
- App 使用 server-side session + `Secure`、`HttpOnly`、host-only cookie。
- RP session 保存中央 `sid` 與 `sub`。
- 每個第一方 RP 實作冪等 back-channel logout endpoint，以 `jti` 去重。
- 管理服務即時檢查中央撤銷狀態且 fail closed；公開服務撤銷 cache 上限 30 秒。
- Recovery codes 只作一次性復原，不是日常登入方式。

## 專案 Ownership

第一方，可直接修改與遷移：

- `原專案代碼/copy.pg72.tw`
- `原專案代碼/link.pg72.tw`
- `原專案代碼/upload.pg72.tw`
- XUGOU fork：`原專案代碼/status.pg72.tw`

上游研究用原始碼，不預設維護 fork：

- File Browser：`原專案代碼/file.pg72.tw`
- Roundcube：`原專案代碼/webmail.pg72.tw`

File Browser/Roundcube production 部署必須從鎖定版本、checksum/image digest 的 upstream stable release 自行打包。優先使用設定、plugin、adapter 或 gateway；未經明確決策，不修改上游 auth core。

## 目前 Migration Blockers

### Copy

- Production 已切換至 PGID OIDC；六位數訪客碼依產品決策保留，且必須與 PGID 使用者、Email、`sub` 保持分離。
- 以不可變 issuer `sub` 綁定 PGID 身分；Email 不參與授權或訪客/SSO 合併。
- Token vault、Web Crypto 訪客碼與登出撤銷修正已部署；仍待 owner 實機確認登出，中央 `sid` 與 back-channel logout 尚未完成。

### Link

- Production 已切換至 PGID：`oauth4webapi` BFF、PKCE/state/nonce、stable `sub` session、一次性 verified-email binding 與安全 error response。
- 舊 `owner_email` 暫作綁定後固定的 local ownership key；中央 `sid`、back-channel logout 與完整 Production GO 仍未完成。

### Status / XUGOU

- 本機整合已完成：OIDC BFF + D1 opaque session，已移除 browser JWT/localStorage 與 password login surface。
- Browser、public status、admin、agent push 已分離；agent registration token 使用獨立 HMAC secret。
- 尚待 Preview D1 與 back-channel logout。

### Upload

- 本機整合已完成：Cloudflare Access/`DEV_MODE` 已移除，Admin 改 Authlib OIDC + SQLite session + Origin/CSRF。
- 公開 upload code、session token 與 streaming flow 保持獨立；尚待 VPS Preview。

### File Browser

- 使用 upstream stable package。
- 使用 proxy auth 時，gateway 必須 strip/overwrite identity header，origin 不可被繞過。

### Roundcube

- 現有 `1.8-git` snapshot 不可直接部署。
- 上游已提供 Generic OIDC、PKCE、JWKS 與 back-channel logout，優先用原生設定。
- IMAP/SMTP 是否可免密碼取決於 mail backend 的 XOAUTH2/OAUTHBEARER 支援，不能只靠 Web UI OIDC 假設。
- Mail Path A 的 PGID introspection email claim 已本地實作並測試，但尚未 production 部署/驗證；VPS/mail cutover 仍需 owner 在場的維護窗口。

## Security Gate

目前是已部署的 invite beta，不是公開註冊或完整 Production GO。切換 public、宣告完整 Production GO 或聲明 gate 完成前至少通過：

- TypeScript typecheck、lint、unit 與 integration tests。
- `@cloudflare/vitest-pool-workers` workerd tests。
- OIDC protocol negative tests 與 replay tests。
- SAST、dependency audit、secret scan、IaC/config scan。
- DAST 覆蓋 auth、OIDC、admin、gateway 與 logout endpoints。
- Request-abort/isolate regression、併發與 rate-limit tests。
- Backup restore、key rotation、session revoke、Queue retry/DLQ 演練。
- 無未處理的 Critical/High finding；Medium 必須有 owner、期限與補救措施。

任何人都不能保證系統必然「通過所有漏洞測試」。本專案的要求是把可測試的安全條件寫成自動化 gate，並在公開前安排獨立 review，而不是用文件聲明取代驗證。
