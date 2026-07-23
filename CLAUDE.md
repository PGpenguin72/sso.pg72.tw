# PGID 實作守則

本檔是本 public source repo 的精簡 coding 守則。完整且唯一的架構規格是 [`codex.md`](./codex.md)；若本檔、程式、issue 或註解衝突，以 `codex.md` 為準並同步修正過期文件。

## 工作邊界

- 先讀 [`codex.md`](./codex.md)、[`SECURITY.md`](./SECURITY.md)、[`CONTRIBUTING.md`](./CONTRIBUTING.md) 與相關程式/tests。
- Repo 範圍是 `apps/sso`、`apps/test-rp`、`scripts`、`security`、`docs`、`wiki`、`patches`；不要帶入其他服務 ownership 或 legacy source。
- 在獨立 worktree 工作，先看 `git status`，保留 unrelated changes，變更只聚焦一個主題。
- 不 push、不 deploy、不執行 remote D1/Queue/R2/secret mutation，也不改 production/Preview 狀態。
- Live、isolated Preview、remote smoke/restore/rotation/drill 只有 owner 事前明確授權才能執行。
- 無授權時只用 local loopback、synthetic data 且不載入 Cloudflare credentials。
- 一般驗證只允許 typecheck、lint、unit、integration、build，以及部署必要的最小非對抗性 health check。
- Owner 已禁止所有 agent 執行、要求、委派、排程或提示任何 security test/scanner，包括 SAST、DAST、fuzz、對抗/攻擊模擬、pentest、load/stress/rate-exhaustion、fault injection 與任何環境的 live security probe。歷史 security/release workflow 目前全部 deferred，只有 owner 日後新的明確指令可以重新授權。
- 不硬編碼 test count、commit SHA、artifact digest、npm 查詢日期、部署快照或指定 co-author trailer。

## 產品與 Registration

- 產品名是 **PGID**；Issuer 固定 `https://sso.pg72.tw`，不用 Cloudflare Access 取代 SSO。
- 日常登入是 Google + Passkey；不新增密碼、Email OTP 或 TOTP。
- Optional providers 只有 config/secret 完整時啟用；缺失時隱藏並 fail closed。
- Email 不是主鍵；所有 RP 使用不可變 `sub`。不因相同 Email implicit link 或合併帳號。
- Provider identity 只有一個 owner；以 D1 unique constraint 決定併發結果，不用 read-then-insert。
- Registration 維持 `invite`；`public` 只有 `codex.md` §9.2 全部通過且 owner 核准部署後才能啟用。
- 所有新帳號需要 verified-email enrollment；public 建帳只接受 verified Google。
- Telegram 只能登入已明確連結的既有 active account；不得建立 placeholder-email user。
- Passkey enrollment 需要既有帳號與 authenticated session。
- Public-created account 初始 `restricted`；invited/bootstrap account 為 `standard`。Restriction 不等於 suspension。
- Restricted sensitive action 與所有 management/developer writes 必須在 committing D1 batch 重驗 live session、active/standard account 與 permission snapshot。
- Passkey RP ID 是 `sso.pg72.tw`，expected origin 是 `https://sso.pg72.tw`；不可放寬。

## OIDC 與 Session

- 使用 Authorization Code + PKCE S256，完整驗證 state、nonce、issuer、audience、redirect URI 與 replay。
- Dynamic client registration 關閉；production redirect URI 精確 HTTPS 比對，不允許 wildcard。
- Confidential RP 現行使用 `client_secret_post`；未有 tracked patch、tests 與 migration 不切換 auth method。
- 保持單一 audience，authorize/token 拒絕 RFC 8707 `resource`，直到 canonical 控制正式退出。
- Backend 交換 code；token 不進 `localStorage` 或 JavaScript-readable cookie。
- 各 app 使用自己的 server-side session 與 `Secure`、`HttpOnly`、host-only cookie，不共用 parent-domain cookie。
- User ID token 帶 nonempty `sid`；RP session 保存 `sid` + `sub`。
- Code/refresh grant 綁定同 user 的 live central session；D1 是 session/token/revocation truth。
- RP back-channel logout 以 `jti` 冪等，receipt 與 local session deletion 原子 commit。
- Mail cross-client introspection 只限 `pgid-mail-introspect` -> `pg72-webmail` opaque access token，並要求 live session、`email` scope、active verified-email user。

## Secret 與 Worker

- Secret 只放 Wrangler secrets / Secrets Store；不進 source、config、D1 明文、bundle、log、文件、issue 或聊天。
- 不提交 `.dev.vars`、remote D1 export、私鑰、Cloudflare credential 或 production data。
- Token、code、session ID、nonce、client secret、invitation/recovery credential 使用 Web Crypto，不用 `Math.random()`。
- Log/audit/Queue/telemetry 遮蔽 token、code、session、secret、Passkey challenge、recovery data、credential ID、完整 Email/IP。
- Better Auth 由 request-scoped factory 從 `c.env` 建立；不放 module-level mutable request/D1 state。
- Binding types 由 `wrangler types` 產生；不用手寫 `Env`、`any` 或 double cast 掩蓋錯誤。
- Promise 必須 `await`、`return` 或明確交 `ctx.waitUntil()`；auth/audit source-of-truth 在 response 前 commit。
- 使用 Cloudflare bindings/Service Bindings，不從 Worker 呼叫 Cloudflare REST API；大或未知 body 要 streaming。
- 不用 `passThroughOnException()`；security state 不明時 fail closed。

## D1、Queue、R2 與 Migration

- Schema 只透過 ordered migration 改變；D1 原子多寫使用 batch/guarded CAS，不依賴 interactive transaction。
- 不重寫可能已套用的 migration；Worker rollout 必須先滿足其 schema dependency、preflight 與 rollback/forward-fix 設計。
- Duplicate identity/credential preflight 若有結果就停止；不得自動刪除、合併或重指派 owner。
- Migration 檔存在只是 source state，不能宣稱遠端已套用；remote ledger 只能由 owner-authorized check 確認。
- `0024_audit_archive_r2_evidence_guard.sql` 不得預先描述成 deployed、verified 或 complete。
- Queue 是 at-least-once，consumer 必須冪等；D1 state 與 `audit_event` 才是 source of truth。
- Global logout 的 durable D1 ledger 與一般 post-commit best-effort security Queue 是不同保證，不可混寫。
- Archive source、D1 repository、pure R2 writer/restore verifier 或 local proof 不代表 runtime wiring。
- KEK custody、authenticated trusted-manifest provenance、R2 binding、Queue/Cron、remote proof、restore sink/exercise 與 external backup 未完成前，encrypted archive 維持 `dependency_missing`。

## Dependency 與文件

- `better-auth` 與所有 `@better-auth/*` exact pin 同一 patch line；production auth core 不用 beta/RC。
- 升級 core/plugins 必須一起檢查 advisory、schema/migration、補償控制與 protocol regressions。
- [`patches/@better-auth__oauth-provider@1.6.23.patch`](./patches/@better-auth__oauth-provider@1.6.23.patch) 不可機械搬版，也不可用 `allowUnusedPatches` 隱藏 mismatch。
- 只有 audited stable upstream 提供全部等價 contract、clean frozen install 與完整 gates 通過後才可移除 patch。
- 明確區分 source present、本輪 local verified、isolated Preview evidence 與 deployed production behavior。
- Protocol、endpoint、claim 或參數變更時同步更新 [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) 與相關 `wiki/`。
- 文件與 runbook 不能把未接線 module、pending restore、local pass 或 migration file 寫成 operational、deployed 或 Production GO。
- Security claim 與 public rollout 以 [`SECURITY.md`](./SECURITY.md) 和 `codex.md` §9.2 為 gate，不能用文件宣告取代驗證。
