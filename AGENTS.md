# AGENTS.md

本檔指引在 PGID 公開 source repository 工作的 coding agent。產品、架構與安全設計以 [`codex.md`](./codex.md) 為 canonical；若程式、issue、註解或本檔衝突，以 `codex.md` 為準，並在同一變更修正過期文件。

## 先讀什麼

1. [`CLAUDE.md`](./CLAUDE.md)：精簡實作守則。
2. [`codex.md`](./codex.md)：完整產品、協議、資料與 rollout 規格。
3. [`SECURITY.md`](./SECURITY.md)：公開回報方式與 release gates。
4. [`CONTRIBUTING.md`](./CONTRIBUTING.md) 與 [`README.md`](./README.md)：本機 setup、workspace 與 contributor 流程。
5. 要改 auth 行為時，讀 `apps/sso/worker/index.ts`、`auth.ts`、`config.ts` 及相應 tests。
6. 要改 protocol、migration、continuity 或 archive 時，讀 [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) 與相關 [`docs/runbooks/`](./docs/runbooks/) 文件。

## Repository 範圍

- 本 repo 只維護 PGID source：`apps/sso`、`apps/test-rp`、`scripts`、`security`、`docs`、`wiki` 與 `patches`。
- `apps/sso` 是 Worker、React 帳號中心、D1 migrations 與 workerd tests。
- `apps/test-rp` 是獨立 OIDC protocol RP；不能把它當 production RP。
- `scripts` 與 `security` 保留 source assurance 與歷史 public-readiness contracts；其中的 security/DAST 工具目前不得由 agent 執行。
- 不把其他服務的 source、部署 ownership 或 legacy migration 工作帶入此 repo。

## 安全工作流程

- 只在獨立 git worktree 工作；開始前檢查 `git status`，保留所有不相關變更。
- 變更保持單一主題；不要順手重排 lockfile、生成檔或無關 metadata。
- 不執行 `git push`、`wrangler deploy`、remote D1、remote Queue/R2、secret mutation 或其他遠端狀態變更。
- Production、live login、isolated Preview、remote smoke、restore、rotation、Queue/DLQ/R2 drill 都須 owner 事前明確授權。
- 沒有授權時只使用 source-local、loopback、synthetic 資料；不得帶入 Cloudflare credentials。
- 不以 issue workaround 取代設計；需要 workaround 時固定為可追蹤 patch 並加入 regression test。
- Commit 保持邏輯清楚並使用英文 message；不要硬編碼或強制指定 contributor trailer。

## 測試授權邊界

- Owner 已明確禁止任何 agent、principal 或 subagent 執行、要求、委派、排程或提示任何資安測試或 security scanner，直到 owner 日後以新的明確指令重新授權。
- 禁止範圍包含 SAST、DAST、active/adversarial scan、fuzz、attack simulation、penetration/pentest prompt、credential guessing、load/stress/rate-exhaustion、fault injection，以及對 local、Preview、staging 或 production 的 live security probe。
- 目前只允許一般 typecheck、lint、unit、integration、build，以及部署必要的最小非對抗性 health check。歷史 workflow、task、report、gate 或 runbook 不能推導出重新授權。
- 既有安全 gate 保持 deferred/blocked，不得因目前禁止測試而標記為通過或豁免。

## 本機驗證

- 以目前 [`package.json`](./package.json) scripts 為準，不從舊文件複製 command 或 test count。
- 一般程式變更先跑 `pnpm check`；它涵蓋 workspace 現行 typecheck、tests 與 builds。
- `pnpm security:tools:install`、`pnpm security:check`、`pnpm dast:local` 與 continuity/load/security drills 目前全部禁止由 agent 執行；只保留為 deferred historical contracts。
- 純文件變更檢查 Markdown 結構、相對連結、`wiki/SUMMARY.md` inventory 與 `git diff --check`。
- 無法執行應有 gate 時要如實列出未驗證項目，不得把部分或舊結果寫成通過。

## Auth 與註冊不變條件

- 產品名一律 **PGID**；Issuer 固定為 `https://sso.pg72.tw`。
- PGID 自行掌控 authentication，不以 Cloudflare Access 取代登入或授權層。
- 日常登入是 Google 與 Passkey；不新增密碼、Email OTP 或 TOTP。
- Optional social provider 只有 secret/config 完整時啟用；未設定時 fail closed 並隱藏入口。
- Email 不是主鍵；所有 RP 以不可變 OIDC `sub` 識別使用者。
- 關閉 implicit account linking；同 Email 不自動合併，provider link 必須由已登入的 `standard` account 明確完成。
- `(providerId, accountId)` 只能有一個 owner；併發 ownership 由 D1 constraint 決定，不用 read-then-insert 猜 winner。
- 現行 registration policy 維持 `invite`；只有 `codex.md` §9.2 全部 gate 與 owner 核准部署後才能切換 `public`。
- 所有新帳號都經 verified-email enrollment；public 建帳只由 verified Google 首次登入進入。
- Telegram 無 verified email，只能登入已明確連結的既有 active account；不得建立 placeholder-email account。
- Passkey 註冊需既有帳號與 authenticated session；public-created account 初始為 `restricted`，invited/bootstrap account 為 `standard`。
- `restricted` 與 lifecycle status 分離；敏感管理寫入必須重讀並在同一 D1 batch 重驗 actor/session/account snapshot。
- Passkey RP ID 固定 `sso.pg72.tw`，expected origin 固定 `https://sso.pg72.tw`，不得放寬到 parent domain。

## OIDC 與 Session 不變條件

- 使用 Authorization Code + PKCE S256；驗證 `state`、`nonce`、issuer、audience、redirect URI 與 code replay。
- Dynamic client registration 關閉；client、scope 與 redirect URI 由管理員明確建立。
- Production redirect URI 必須完整精確 HTTPS 比對，不允許 wildcard；local callback 使用獨立 development client。
- 現行 confidential RP token authentication 是 `client_secret_post`；沒有 tracked patch、regression 與 RP migration 不改成 `client_secret_basic`。
- 保持單一 audience，authorize/token 邊界拒絕所有 RFC 8707 `resource` 參數，直到 canonical 補償控制正式退出。
- RP 在 backend 交換 code；token 不進 `localStorage` 或 JavaScript-readable cookie。
- 每個 app 建立自己的 server-side session 與 `Secure`、`HttpOnly`、host-only cookie，不設 `Domain=.pg72.tw`。
- User ID token 必須有 nonempty central `sid`；RP session 保存 `sid` 與 `sub`。
- Authorization-code/refresh grant 必須綁定同一 user 的 live central session；D1 是 session/token/revocation source of truth。
- Back-channel logout receiver 驗證完整 token contract，以 `jti` 冪等去重，並將 receipt 與 session deletion 原子 commit。
- Mail introspection 只允許 `pgid-mail-introspect` 查 `pg72-webmail` opaque access token，且要求 live session、`email` scope、active verified-email user；不得擴張到 JWT、refresh token或其他 client pair。

## Secret、Log 與 Crypto

- Secret 只放 Wrangler secrets / Secrets Store，不進 source、`wrangler.jsonc`、D1 明文、client bundle、log、issue、文件或聊天。
- 不提交 `.dev.vars`、production D1 export、私鑰備份、Cloudflare credential 或含個資的 fixture。
- Token、code、session ID、nonce、invitation/recovery credential 與 client secret 使用 Web Crypto；不用 `Math.random()`。
- 只儲存協議允許的 hash/encrypted value；一次性 secret/raw recovery code 只回一次且使用 `no-store`。
- Log、audit、Queue、telemetry 與 operator view 遮蔽 token、authorization code、session ID、secret、Passkey challenge、recovery credential、credential ID、完整 Email 與完整 IP。
- Error response 不洩漏帳號存在性、token 狀態、secret 或內部 exception。

## Workers、D1、Queue 與 R2

- 新 Worker 使用 `wrangler.jsonc`、建立當日 `compatibility_date` 與 `nodejs_compat`。
- 用 `wrangler types` 產生 binding types；不手寫 `Env`，不用 `any` 或 double cast 掩蓋 binding 問題。
- Better Auth 用 request-scoped factory 從 `c.env` 建立，不保存 module-level mutable request/D1 state。
- 每個 Promise 都要 `await`、`return` 或明確交 `ctx.waitUntil()`；source-of-truth 寫入必須在 response 前完成。
- Cloudflare resource 使用 bindings/Service Bindings；Worker 不呼叫 Cloudflare REST API；未知或大型 body/response 必須 streaming。
- 不使用 `passThroughOnException()`；security dependency 或 D1 狀態不明時 fail closed。
- 所有 schema 變更走 ordered D1 migration；不用 interactive transaction，原子多寫採 D1 batch、guarded CAS 與 idempotency key。
- 不重寫可能已套用的 migration；先確認 migration ordering、Worker schema dependency、duplicate preflight 與 rollback/forward-fix 設計。
- Migration 檔存在只證明 source state，不證明 Preview/production 已套用；遠端 ledger 必須由 owner-authorized operation重新確認。
- `0024_audit_archive_r2_evidence_guard.sql` 目前只能視為 source 中的 forward guard；不得預先宣稱 deployed、verified 或 complete。
- Queue 是 at-least-once；consumer 需冪等。D1 `audit_event` 與 session/token state 才是 truth，Queue 不能取代它們。
- Global logout 有專用 durable D1 delivery ledger；一般 security-event Queue 仍是 post-commit best effort，不能混淆保證。
- R2 archive repository/writer、pure restore verifier、migration 與 local proof 不等於 runtime wiring；KEK custody、authenticated trusted-manifest provenance、binding、Queue/Cron、remote proof、restore sink/exercise 與外部備份未完成前維持 `dependency_missing`。

## Dependency 與 Patch

- `better-auth` 與所有 `@better-auth/*` 使用 exact pin、同一 patch line；production auth core 不使用 beta/RC。
- 升級前查 current stable 與 advisories，core/plugins 一起評估 schema、migration、補償控制與完整 protocol regression。
- [`patches/@better-auth__oauth-provider@1.6.23.patch`](./patches/@better-auth__oauth-provider@1.6.23.patch) 是 exact-version contract；不得機械搬到其他版本。
- 不用 `allowUnusedPatches` 隱藏 mismatch；只有 audited stable upstream 提供全部等價行為、clean frozen install 與完整 gates 通過後才能移除。
- Lockfile、workspace lifecycle policy、patch set 與 release artifact identity 是受審查輸入；不要自動學習、重寫或放寬其 allowlist/digest。

## 文件狀態語言

- 明確區分 `source present`、本輪 `local verified`、isolated Preview evidence 與 deployed production behavior。
- Local test、migration file、runbook 或 pure module 不代表 binding、scheduler、remote migration、operator alert 或 restore 已完成。
- 不引用易過期的 test 數、commit SHA、artifact digest、npm 查詢日期或部署快照作永久規則。
- Protocol、endpoint、claim 或參數變更時，同步更新 [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) 與相關 `wiki/` 頁面。
- Public/Production GO 宣稱必須符合 [`SECURITY.md`](./SECURITY.md) 與 `codex.md` §9.2；文件不能代替安全驗證或 owner approval。
