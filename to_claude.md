# PGID Codex -> Claude Handoff

> 建立時間：2026-07-16 15:28 CST（Asia/Taipei）
> 接手對象：Claude / 下一位 coding agent
> Repository：`/Users/pgpenguin72/sso.pg72.tw`
> Canonical 規格：[`codex.md`](./codex.md)
>
> 這份文件記錄 **local repository truth**。本輪沒有執行 `git push`、
> `wrangler deploy`、remote D1、Cloudflare production mutation、secret-store
> mutation、Roundcube/Dovecot/VPS 變更。

## 1. 一句話狀態

Mail Path A 的 PGID-side prerequisite 已經安全整合到本地 `main`，完整
SSO/test-RP gate 已通過；但 production 尚未部署，migration `0013` 尚未有
remote 套用紀錄，`pgid-mail-introspect` 尚未 provision，mail VPS 尚未
cutover，而且真正的 Passkey step-up 仍是 production blocker。

目前應先完成 `/private/tmp/pgid-mail-docs` 的文件校對、commit 與本地
cherry-pick；**不要開始 production rollout**。

## 2. 不可違反的工作規則

先讀根目錄 [`AGENTS.md`](./AGENTS.md)、[`CLAUDE.md`](./CLAUDE.md)、
[`codex.md`](./codex.md)、[`handoff.md`](./handoff.md)。摘要如下：

- 在獨立 git worktree 工作，不直接手改主 checkout。
- 不執行 `git push`；由 owner 決定何時推送。
- 不執行 `wrangler deploy`、`--remote` D1、production/Cloudflare/VPS mutation。
- 不修改或建置 `原專案代碼/`；它是獨立 repo/migration input。
- 不揭露或提交 secret、token、code、session ID、private key、完整 email/IP。
- 不改既定產品決策：不用 Cloudflare Access 取代 PGID、不開 dynamic client
  registration、不略過 consent、不移除 Copy 六位數訪客碼、不用 email 合併
  身分、Preview/production 不共用帳號/D1/secret。
- 程式 commit 要單一主題，英文 message，並附：

  ```text
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  ```

- 改到 `apps/sso` 或 `apps/test-rp` 後，至少跑：

  ```bash
  pnpm --filter @pg72/id check
  pnpm --filter @pg72/test-rp test
  ```

## 3. 本地 main 已完成的 commits

主 checkout 在這份 handoff commit 前是 `69118ad`。以下三個成果已在
`main`，不要重複 cherry-pick source worktree 的等價 commits：

| Main commit | 內容 |
| --- | --- |
| `4a44b43` | `Standardize confidential clients on secret post` |
| `9efdece` | `Authorize scoped mail token introspection` |
| `69118ad` | `Reconcile docs with invite beta state` |

來源 worktree 對應如下，**不要再合併一次**：

| Worktree / commit | 狀態 |
| --- | --- |
| `/private/tmp/pgid-client-secret-post` / `14d2a327` | 已以 `4a44b43` 進 main |
| `/private/tmp/pgid-introspection-mail-v2` / `6063fee` | 已以 `9efdece` 進 main |
| `/private/tmp/pgid-docs-truth` / `48071f0` | 已以 `69118ad` 進 main |
| `/private/tmp/pgid-introspection-email` / `df8c5d0` | 舊且有缺陷，禁止合併 |

主 checkout 原有未追蹤項目：

```text
.claude/
morden_dark.txt
```

它們屬 owner/既有工作，請保留，不要清除、reset 或納入本任務 commit。

## 4. 已完成的 runtime 行為

### 4.1 Confidential client auth

- Confidential clients 正式契約統一為 `client_secret_post`。
- Discovery 精確宣告：
  - token：`none`、`client_secret_post`
  - introspection：`client_secret_post`
  - revocation：`none`、`client_secret_post`
- Local migration `apps/sso/migrations/0013_confidential_client_secret_post.sql`
  只正規化 metadata，不旋轉 secret、不改 grant/token。
- 最新既有 production 紀錄仍只到 migration `0012`；本輪未查 remote。

### 4.2 Fixed Mail introspection boundary

唯一 delegated pair 固定為：

```text
introspection client: pgid-mail-introspect
token-owning client:  pg72-webmail
token type:           opaque access token only
```

Mail active response還要求：

- token 未過期/撤銷，target client enabled；
- token 保有 live central session；
- scopes 含 `email`；
- user row 仍存在、`status=active`、`emailVerified=true`；
- email 非空。

JWT、ID token、refresh token、其他 client pair、missing session/scope/user/
verified email 都不 delegated，回 RFC 7662 inactive。

成功 mail response allowlist 只有：

```text
active client_id scope iss exp iat email email_verified
```

其中 `iss`/`exp`/`iat` 只在 provider 有值時出現；刻意不回 `sub`、`sid`、
`token_type`。Email 只供 Dovecot legacy mailbox username lookup，不改變其他
PGID/RP 必須以 immutable `sub` 作主鍵的規則。

### 4.3 Request/response boundary

`POST /oauth2/introspect`：

- 只接受 exact `application/x-www-form-urlencoded` media type（可有合法參數）；
- body 上限 4096 bytes；
- 拒絕任何 `Authorization` header / Basic；
- `client_id`、`client_secret`、`token`、`token_type_hint` 四個欄位各自
  不可重複；
- `token_type_hint` 只是 lookup 順序提示，miss 時仍查另一種 token；
- invalid/expired/revoked/unauthorized token 在 client 認證成功後回 exact
  HTTP 200 `{"active":false}`；
- invalid client 全域正規化為 HTTP 401 `invalid_client`；
- response 帶 `Cache-Control: no-store`、`Pragma: no-cache`。

Dedicated limiter：

| Binding | Namespace | Limit | Key |
| --- | --- | --- | --- |
| `INTROSPECTION_IP_RATE_LIMITER` | `1004` | 1200 / 60s | source IP |
| `INTROSPECTION_CLIENT_RATE_LIMITER` | `1005` | 600 / 60s | `mail|other` client class + IP |

拒絕回 429；binding exception fail closed 回 503。Cloudflare Rate Limit binding
是 per-location、permissive/eventually consistent，只是 abuse throttle，不是
精確全域 quota 或認證/撤銷 source of truth。

### 4.4 Exact dependency patch

Tracked patch：

```text
patches/@better-auth__oauth-provider@1.6.23.patch
```

由 `pnpm-workspace.yaml` `patchedDependencies` exact 綁定，lockfile 有 patch
hash；`.gitattributes` 對 `*.patch` 關閉一般 source whitespace rule，因 unified
diff 的 tab-indented context line 本來就需要空白 marker。

Patch 提供：

- 預設仍 same-client 的 opt-in cross-client opaque access-token hook；
- hook 可看到 token owner、scopes、resolved user、validated live session ID；
- RFC 7662 `APIError.status` inactive 修正；
- wrong `token_type_hint` fallback；
- pairwise `sub` 以 token-owning client 解；
- malformed/缺 `kid`/unknown `kid`/signature/claim/expired 等 token-controlled
  JOSE errors 回 inactive；未知或 JWKS/infrastructure error 保持 server error。

PGID default signer 會寫 non-empty `kid`；測試另覆蓋 rotation grace 期間兩把
JWKS + no-`kid` token，防止 `JWKSMultipleMatchingKeys` 被攻擊者穩定打成 500。

不要把 patch 機械搬到其他版本，也不要用 `allowUnusedPatches`。只有 pinned
stable upstream 提供全部等價行為、移除 patch 後 clean frozen install 與完整
protocol tests 都通過，才可移除。

### 4.5 System-client lifecycle

Endpoint：

```text
POST /api/admin/clients/provision-mail-introspector
```

條件：

- valid PGID session cookie；
- exact same-origin `Origin == AUTH_BASE_URL`；
- `clients.manage_all`；
- session `createdAt` 在過去 10 分鐘內，future/stale 都拒絕。

Endpoint 沒有 request fields；4 KiB admin body limit 內的 body 目前會被忽略。
建立的 client 是 unowned、hash-only、無 redirect/scope/token-issuing grant 的
service client；`urn:pg72:grant-type:introspection-only` 只是防 provider 套用
預設 grant 的 sentinel。Plaintext secret 只回一次，D1 只存 suffix hash。

`pgid-mail-introspect` 與 `pg72-webmail` 是 reserved IDs。Developer 不能 claim；
system-client lifecycle 只允許 manage-all actor。所有 client mutation 都要求
fresh-session age gate。

**重要：fresh session 不是 reauthentication，也不是 Passkey step-up。**
真正 Passkey step-up 尚未實作，是 production provisioning/rotation blocker。

### 4.6 Atomic audit、ownership 與 Queue

- Client create/provision/trust/rotate/status/delete 的 D1 mutation 與
  `audit_event` insert 在同一 D1 batch。
- Mutation guard 綁 immutable `oauthClient.id + clientId`；developer 再綁
  expected `ownerUserId`。這封住 owner account delete/orphan 與同 clientId
  delete/recreate 的 TOCTOU。
- Status/delete 的 token、refresh token、authorization-code cleanup 與 audit
  也使用同一 guard，不會誤傷 replacement row。
- D1 `audit_event` 是 source of truth。
- Queue 是 D1 commit 後的 best-effort fan-out。`Queue.send` sync throw、Promise
  rejection、`waitUntil` throw 都有 redacted handling，不能讓已 commit 的
  one-time secret create/rotation 回 500。

尚未有 D1 transactional outbox/replayer。Queue 在接受前失敗可能漏掉 fan-out，
但 D1 audit row 保留。若文件聲稱已有可靠補送，必須修正；full Production GO
前應決定 outbox/reconciliation/alerting。

## 5. 已完成的驗證

在 `/private/tmp/pgid-introspection-mail-v2`、commit `6063fee`（main 等價
`9efdece`）完成：

```bash
pnpm install --offline --frozen-lockfile
pnpm --filter @pg72/id check
pnpm --filter @pg72/test-rp test
```

結果：

- SSO：13 test files、166 tests passed；typecheck + production build passed。
- test RP：1 test file、4 protocol tests passed。
- Focused audit/introspection/admin：3 files、39 tests passed。
- `git diff --check` passed。
- Build 完成後掃描 `apps/sso/dist`，沒有 `.dev.vars` / `.dev.vars.*`。
- Frozen offline install 成功，tracked provider patch 可由 lockfile 重建。
- Secret-pattern review 只命中 tracked non-working placeholder 名稱，沒有真值。

Final read-only subagent reviews 對以下項目均回報無 High/Medium blocker：

- immutable client/owner guard、D1 batch/audit result indexes；
- Queue post-commit secret response / floating Promise；
- opaque fallback、JOSE/kid classification、hint fallback；
- fixed pair、live session、verified email、minimal allowlist；
- trigger/spy/JWKS key cleanup 與 TOCTOU interposer test hygiene。

## 6. 尚未提交的 docs worktree

Worktree：

```text
/private/tmp/pgid-mail-docs
branch: codex/mail-introspection-docs
base before this handoff: 69118ad
```

這份 `to_claude.md` 會單獨 commit；下列其他文件仍保持 **uncommitted**，讓
接手者完成 review 後另做 docs-only commit：

```text
CLAUDE.md
README.md
SECURITY.md
codex.md
docs/api/PGID-integration.md
docs/integration-plans/roundcube.md
handoff.md
patches/README.md
wiki/SUMMARY.md
wiki/developers/consent-and-scopes.md
wiki/developers/register-client.md
wiki/faq.md
wiki/developers/mail-introspection.md   # new, currently untracked
```

三條 subagent 工作：

1. Canonical docs（完成）：`codex.md`、`CLAUDE.md`、`SECURITY.md`。
2. Handoff/runbook（完成）：`README.md`、`handoff.md`、Roundcube plan。
3. Developer/API/wiki（約 80% 時被 user 要求 handoff 而中止）：API §5.4、
   patch removal gate、FAQ、新 wiki page 與 SUMMARY 已寫，但尚未由 root 完成
   最終 link/truth review。

目前 `git diff --check` 對 tracked diff clean；新 wiki page 尚需一併檢查與
stage。Stale `尚未實作/驗證` 只剩 `handoff.md` 歷史原文，前面已有 explicit
superseded banner，這是刻意保留歷史，不應直接刪除。

## 7. Docs 接手時先修/確認的項目

不要直接 `git add -A && commit`。先逐項確認：

1. **Queue 語意**：canonical draft 有「告警/補送」措辭；目前只有 D1 audit
   + redacted log/best-effort Queue，沒有 durable outbox/replayer。不得暗示可靠
   補送已完成，應把它列為 Production GO debt。
2. **Secret incident 順序**：draft 某些段落寫「disable -> rotate -> update ->
   verify -> re-enable」。Disabled client 無法做真正 introspection smoke；較精確
   是 disable -> rotate -> 更新 secret store/Dovecot -> 維護窗口 re-enable ->
   立即 smoke，失敗就 re-disable/rollback。
3. **JWT 措辭範圍**：`JWT/refresh inactive` 是 mail delegated caller 的規則；
   不要誤寫成 generic same-client introspection 永遠不支援 JWT。
4. **New wiki page**：確認 `wiki/developers/mail-introspection.md` 所有相對 links、
   `wiki/SUMMARY.md` entry、API anchor 都正確。
5. **Examples**：範例只能寫 secret 名稱/placeholder，不能有真 secret/token；
   active allowlist 不可加入 `token_type`、`sub`、`sid`。
6. **Provision body**：runtime 是「沒有 request fields、4 KiB 內 body ignored」，
   不是嚴格要求 Content-Length 0；文件可建議空 body，但別宣稱非空一定拒絕。
7. **Passkey step-up**：current `<10m` gate 不是 reauth；runbook 必須把真正
   step-up 放在 deploy/provision 前，不能以 fresh session 宣稱 production-ready。
8. **Production truth**：local code/tests 已完成，但未 deploy、未 provision、
   production D1 最新紀錄只有 `0012`、VPS 未 cutover、本輪未 remote query。
9. **Historical handoff**：不要重寫 archived operational record；保留舊
   `client_secret_basic`、Not Yet Done、mail 尚未實作原文時，必須有 current
   superseded banner。
10. **Canonical 內容**：不要在 `codex.md`/`CLAUDE.md`/`SECURITY.md` 寫短期
    branch hash或 test count；精確 `9efdece`、166/4 可留在 dated `handoff.md`。

建議搜尋：

```bash
cd /private/tmp/pgid-mail-docs
git status --short
git diff --check
rg -n 'df8c5d0|149 SSO|149 tests|checked-out file is ignored|INTROSPECTION_RATE_LIMITER' \
  CLAUDE.md codex.md SECURITY.md README.md handoff.md docs wiki patches
rg -n '尚未實作/驗證|client_secret_basic|Not Yet Done' handoff.md
```

第一個搜尋 current docs 應無命中；第二個只允許有 superseded banner 的歷史
archive 命中。

## 8. 精確下一步

### A. 完成 docs-only commit

1. 在 `/private/tmp/pgid-mail-docs` 讀完整 diff與新 wiki page。
2. 修正 §7 的語意問題。
3. 驗證 Markdown headings、relative links、wiki SUMMARY 與檔案存在性。
4. 跑 `git diff --check` 與 stale-state `rg`。
5. 只 stage 上述 docs 檔案（`to_claude.md` 已是獨立 handoff commit）。
6. 建議 commit：

   ```text
   Document scoped mail introspection rollout

   Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
   ```

7. 確認 commit 不含 secret、`.dev.vars`、dist、D1 export、private key。

### B. 整合 docs 回本地 main

1. 主 checkout 必須仍只看到既有 untracked `.claude/`、`morden_dark.txt`。
2. Cherry-pick docs-only commit；不要 merge/reapply `df8c5d0`、`6063fee`、
   `48071f0`、`14d2a327`。
3. Combined main 再跑：

   ```bash
   pnpm install --offline --frozen-lockfile
   pnpm --filter @pg72/id check
   pnpm --filter @pg72/test-rp test
   find apps/sso/dist -type f \( -name '.dev.vars' -o -name '.dev.vars.*' \) -print
   git status --short
   ```

4. Expected：SSO 166、RP 4、dist secret scan 無輸出；status 只保留 owner 的
   兩個既有 untracked paths。
5. 不 push。

### C. Production rollout（現在不要執行）

只有 owner 明確授權且以下 blocker 關閉後，才按 `handoff.md` 新 runbook：

1. 先實作/測試/獨立審查真正 Passkey step-up；
2. 唯讀確認 production `pg72-webmail` exact metadata；
3. private D1 backup / Time Travel checkpoint；
4. owner verify/apply migration `0013`；
5. deploy Worker + namespaces `1004`/`1005` bindings；
6. same-origin、manage-all、fresh + Passkey step-up provision service client；
7. 立即把一次性 secret 存 approved secret store/VPS config；
8. production 只做正常 active/inactive/401 smoke；429/503 只在 isolated Preview/
   controlled local 測，禁止 flood/break production；
9. owner maintenance window 才做 Roundcube/Dovecot XOAUTH2 cutover。

Rollback 必須先恢復 legacy mail auth 或停用 introspector，確認 mail 可用後才
rollback Worker。`0013` 通常不 reverse；若 secret 疑似外洩，保持 disabled、
rotate、更新 secret config，在 maintenance window re-enable + smoke，失敗立即
re-disable/rollback。

## 9. 已知未完成的更大議題

這些不是本輪應順手擴 scope 的工作，但必須保留在安全 gate：

- 真正 Passkey step-up for high-risk client operations；
- central `sid` propagation；
- replay-safe back-channel logout / RP receivers / visit ledger；
- Queue pre-acceptance durable outbox/replayer 與 DLQ/alert drills；
- signing-key rotation、D1 restore、recovery/break-glass drills；
- independent OIDC/security review、DAST/SAST/secret/IaC gates；
- Preview 與 production 完全分離。

先前 source inventory 指出 Better Auth session ID 可作 `sid`，但 ID token `sid`
目前受 `enableEndSession` 影響；access/refresh 對 session FK 是 `ON DELETE SET
NULL`。建議未來依序做：always-emitted ID-token `sid` patch/test -> RP visit ledger
-> central revoke + validated backchannel URI -> durable outbox/logout token -> Queue/
DLQ -> idempotent RP receiver -> rollout。不要在 docs 收尾 commit 混入這批程式。

## 10. 交接完成條件

Claude 可在下列全部成立時關閉這份 handoff：

- docs worktree 的 13 個 pending files 已完成 truth/link review；
- docs-only commit 已帶 required footer；
- commit 已 cherry-pick 到本地 main；
- combined main 的 frozen install、SSO 166、RP 4、dist secret scan 通過；
- main 沒有新增非預期 dirty/untracked 檔；
- 沒有 push、deploy、remote D1 或 production/VPS mutation；
- final 回報清楚區分 local completed 與 production not done。
