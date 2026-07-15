# AGENTS.md

指引給在此 repo 工作的 coding agent。聚焦「如何在這裡安全工作」。產品規格與安全設計以 [`codex.md`](./codex.md) 為單一事實來源；[`CLAUDE.md`](./CLAUDE.md) 是精簡實作守則。本檔與它們呼應，衝突時以 `codex.md` 為準，並在同一變更修正過期文件。

## 先讀什麼

1. [`CLAUDE.md`](./CLAUDE.md)——精簡守則與產品邊界。
2. [`codex.md`](./codex.md)——完整架構規格（canonical）。
3. [`handoff.md`](./handoff.md)——現況、runbook 與 rollback。
4. 要動 auth 行為前，讀 `apps/sso/worker/index.ts`、`apps/sso/worker/auth.ts`、`apps/sso/worker/config.ts`。

## 工作流程

- **在 worktree 工作**：於獨立 git worktree 進行變更，不直接在主 checkout 上改。
- **不要 push**：不執行 `git push`；提交後由 owner 決定推送。
- **不要碰 production**：不跑 `wrangler deploy`、任何 remote/production 指令，或改動 production 狀態。遠端部署與 D1 remote 操作由 owner 執行。
- **邏輯分明的 commit**：每個 commit 聚焦單一主題，英文 commit message，結尾加：

  ```text
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  ```

- **提交前驗證**：改到 `apps/sso` 或 `apps/test-rp` 的程式碼時，跑：

  ```bash
  pnpm --filter @pg72/id check       # typecheck + workerd tests + build
  pnpm --filter @pg72/test-rp test   # RP 協議測試
  ```

  純文件變更不需跑測試，但要確認 markdown 結構、連結與（wiki 的）SUMMARY 對得上檔案。

## 不可碰的邊界

- **不改 `原專案代碼/`**：那是各服務的獨立 repo 與 migration 輸入，本 workspace 不修改、不建置。（且已被 `.gitignore` 排除。）
- **不改上游 auth core**：File Browser / Roundcube 從鎖定的 upstream stable release 打包，優先用設定 / gateway。
- **不動這些既定決策**（見 `handoff.md` §2）：不用 Cloudflare Access 取代 SSO；不開 dynamic client registration；不為第一方 client 略過 consent；不移除 Copy 的六位數訪客碼；不以 email 合併訪客與 SSO 身分；Preview 與 production 不共用 Cloudflare 帳號 / D1 / secret。

## Migration 規則

- Email 不是主鍵；所有服務以不可變 OIDC `sub` 識別使用者。email 只作一次性 verified binding。
- OIDC client、redirect URI、scope 由管理員 / developer 明確建立；redirect URI 精確 HTTPS 比對，不允許 wildcard。
- RP 在後端交換 code，建立自己的 host-only server-side session（存 `sid` + `sub`）；token 不進 `localStorage`。
- 一次移一個服務過 Preview gate，再談 production cutover，把 blast radius 控制在單一 RP。
- 不把 issue 的 workaround 直接當正式設計；workaround 要固定成可追蹤 patch + regression test。

## Secret 規則

- Secret 只放 Wrangler secrets / Secrets Store，**不**進 `wrangler.jsonc`、D1 明文、原始碼、log、commit、issue 或聊天。
- 文件只寫 secret 的**名稱**，不寫值。
- Token、code、session ID、security nonce、client secret 用 Web Crypto，不用 `Math.random()`。
- Log / telemetry 遮蔽 token、authorization code、Passkey challenge、client secret 與完整 email / IP。
- 不把 `.dev.vars`、D1 匯出、私鑰備份或 Cloudflare 認證檔放進 repo。

## Workers 規則（重點；完整見 `codex.md` §5.1）

- 新 Worker 用 `wrangler.jsonc`、當日 `compatibility_date`、`nodejs_compat`。
- Better Auth 用 request-scoped factory 從 `c.env` 建立，不放 module-level mutable singleton。
- 每個 Promise 要 `await` / `return` / 交 `ctx.waitUntil()`；session/token/revocation/audit 的 source-of-truth 寫入在回應前完成。
- 用 `wrangler types` 產生 binding 型別，不手寫 `Env`、不用 `any` 掩蓋。
- 不用 `passThroughOnException()`。
- `better-auth` 與所有 `@better-auth/*` exact pin、同一 patch line；不單獨升級某一個；不使用 beta/RC 作 production auth core。

## 文件變更

- 產品名一律 **PGID**。
- 端點 / 版本 / 參數以程式碼現況為準，不杜撰不存在的端點；改到協議行為時同步更新 [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) 與 [`wiki/`](./wiki/SUMMARY.md)。
- 不用文件聲明取代安全驗證；公開 / production 宣稱前的 gate 見 `codex.md` §9.2 與 [`SECURITY.md`](./SECURITY.md)。
