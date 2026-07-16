# PGID Orchestration Handoff

> 更新時間：2026-07-16 18:23 CST（Asia/Taipei）  
> 停止原因：owner 要求停止目前工作並留下交接  
> Canonical 規格：[`codex.md`](./codex.md)  
> 工作守則：[`AGENTS.md`](./AGENTS.md)、[`CLAUDE.md`](./CLAUDE.md)  
> 本文件是 point-in-time 交接，不取代 `codex.md`。

## 1. 最重要的接手位置

目前應從這個 worktree 接手：

```text
worktree: /private/tmp/claude-pgid-completion
branch:   claude-project-completion
feature integration HEAD: f074492358f2a3c64c74328848a1dd40bf0fca11
branch tip: this handoff is committed immediately after f074492; use git log for its hash
```

在建立本文件前，該 worktree 是 clean。`f074492` 已整合：

- Mail Path A 既有 baseline；
- local Vite optional social-provider secret 載入修正；
- 真正的 Passkey client-mutation step-up；
- Telegram verified-email enrollment boundary；
- provider identity 全域唯一 ownership（migration `0015`）；
- user ID token 的 central `sid` contract 與 test-RP fail-closed 行為。

主 checkout **不是**本輪整合成果所在位置：

```text
worktree: /Users/pgpenguin72/sso.pg72.tw
branch:   main
HEAD:     6fbffcea74d977d4b4c506f90e65dca19a15cf6d
```

主 checkout 保留 owner/通訊變更，不能 reset、清除或誤納入功能 commit：

```text
 M to_claude.md
 M to_codex.md
?? morden_dark.txt
```

## 2. 已整合 commits

整合 branch 在原 baseline `6fbffce` 之後的主要 commits：

| Commit | 內容 |
| --- | --- |
| `d058f60` | local Vite serve 模式可讀 optional provider `.dev.vars`，production build 不注入 |
| `aedf166` | Passkey step-up 設計紀錄 |
| `d79e8a1` | Passkey step-up Worker / D1 flow |
| `120f7b1` | account-center Passkey step-up UI |
| `4e8159a` | 真實 P-256 assertion 與 security boundary tests |
| `fbabaf0` | step-up finalization ordering hardening |
| `a0e4d12` | clean test-RP environment 修正 |
| `9efd5a8` | step-up orphan audit 同 transaction 清理 |
| `a3e85dd` | test-RP type generation 修正 |
| `e977afa` | Passkey rollout 文件 |
| `f041593` | Passkey final verification record |
| `d6b739c` | Telegram 未連結身分不得自行註冊 |
| `a3992e8` | `(providerId, accountId)` 唯一 ownership 與 race fix |
| `f074492` | OIDC user ID token central `sid` contract |

Passkey 原始交付 branch 是：

```text
/private/tmp/codex-passkey-step-up
branch codex/passkey-step-up
HEAD 74b2f56
```

它的 10 個 source commits 已全部 cherry-pick 成上表的 `aedf166` 到
`f041593`，不要再從 source branch 重複合併。

## 3. 已完成行為

### 3.1 Passkey step-up

- migration `0014_passkey_step_up.sql`；
- challenge 兩分鐘、一次性、綁 user + central session；
- exact origin、RP ID、credential ownership，強制 user verification；
- counter CAS 後，以同一 D1 transaction 寫 guarded audit、session timestamp、
  conditional orphan-audit delete；正常 changes 為 `[1,1,0]`；
- create/trust/rotate/status/delete/provision 六條 client mutation 同時保留
  fresh-session gate 並新增 Passkey step-up gate；
- account center 五個可見 client mutation 都在原 mutation fetch 前完成 ceremony；
- 沒有 bootadmin bypass，也沒有虛構的 recovery/break-glass flow。

若 Google 與所有 Passkey 都遺失，目前 runtime 沒有自助 recovery。設計、審核與
演練仍是 full Production GO gate。

### 3.2 Telegram enrollment 與 identity ownership

- Telegram 沒有 verified email，未連結 Telegram identity 在 `invite` 與
  `public` mode 都會被限流、redacted audit、generic 403；
- 不建立 placeholder user/account/session，不設 cookie；
- 已明確連結的 legacy identity 仍可登入；suspended user 不會拿到 session；
- migration `0015_account_provider_identity_unique.sql` 建立
  `UNIQUE(providerId, accountId)`；
- link 使用 `INSERT OR IGNORE`、檢查 `meta.changes`、重新讀取 owner；
- 兩個 user 併發搶同一 identity 時，恰好一個 200、一個 409、資料庫一筆 row；
- `handoff.md` 已有 production duplicate preflight，任何 duplicate row 都必須停止
  rollout，不可由 migration 自動選 owner。

### 3.3 Central `sid` contract（B1）

Tracked exact patch：

```text
patches/@better-auth__oauth-provider@1.6.23.patch
```

目前 patch 同時保留 Mail introspection hunks，並新增：

- 所有 user ID token 都帶 nonempty central `sid`，不受
  `enableEndSession` 影響；該設定只 gate end-session endpoint；
- ID token 缺 session 時，在任何 token write 前 fail closed；
- authorization code 的 session 必須存在、未過期且屬於同一 user；
- refresh grant 必須保有 live、same-user central session；
- detached、expired、user-mismatched refresh introspection 回 inactive；
- refresh rotation 保留相同 `sid` 與 `auth_time`；
- client-credentials grant 不建立 user session，也不回 ID token / `sid`。

Test RP 在 userinfo 與本機 session write 之前要求 nonempty `sid`，且首頁查詢排除
legacy `central_session_id IS NULL` rows。

重要邊界：B1 不是 global logout。session validation、token writes 與 concurrent
session deletion 還不是單一 D1 transaction；opaque access-token central revoke、
visited-client ledger、durable delivery、RP receiver 都屬 B2。

### 3.4 Optional provider local config

`apps/sso/vite.config.ts` 在 local serve only 補出 optional binding names，讓
Wrangler loader 能從 ignored `.dev.vars` 讀 Discord/GitHub/Facebook/Apple/Telegram
設定。production build 不會加入這些空 vars，也沒有把 secret 值寫進 source。

## 4. 已完成驗證

### 4.1 各交付 branch 的完整 gate

Passkey source branch：

- frozen offline install：pass；
- SSO：183/183 tests（14 files）+ typecheck + production build；
- test RP：4/4 + typecheck + dry-run build；
- isolated local D1：`0001` 到 `0014`；
- diff、dist `.dev.vars*`、secret scan：pass；
- desktop 1440x900 / mobile 390x844 UI smoke：pass。

Telegram/provider identity source branch：

- SSO：170/170 tests（13 files）+ typecheck + build；
- Telegram focused：14/14；
- test RP：4/4；
- diff、secret、dist scans：pass。

SID source branch：

- frozen offline install：pass；
- SID focused：11/11；
- SSO：177/177 tests（14 files）+ typecheck + production build；
- test RP：11/11 + typecheck；
- tampered ID-token signature 被 end-session 拒絕且 session 保留；
- patch hash / Mail semantic hunks / diff / dist scans：pass。

### 4.2 整合 branch 已跑的 focused gate

在 `f074492`：

```text
SSO sid.spec.ts + telegram.spec.ts: 25/25 pass
test-RP protocol suite:             11/11 pass
git diff --check:                   pass
```

乾淨 worktree 沒有 `.dev.vars` 時，第一次 focused run 因 required local bindings
未定義而在初始化失敗；只提供 core names 但未提供 local `AUTH_BASE_URL` 時又被
exact-origin gate 拒絕。最後使用明確的 local test placeholders（不讀取、不複製
private secret file）與完整 local runtime vars 後，25/25 通過。

不要把前兩次環境失敗誤判成 runtime regression。下一位應優先修 hermetic gate
（見 §7），使乾淨 checkout 不需要人工準備型別或 env 才能跑規定指令。

### 4.3 尚未跑的最終整合 gate

owner 要求停止前，以下 **尚未**在 `f074492` 完成：

- `pnpm install --offline --frozen-lockfile` 的最後一次整合重跑；
- `pnpm --filter @pg72/id check` 全套整合結果；
- `pnpm --filter @pg72/test-rp test` 之外的 final typecheck/build；
- fresh isolated D1 `0001` 到 `0015`；
- final dist/secret/dependency/config scan；
- final desktop/mobile UI smoke；
- full release handoff commit。

因此不能把 constituent branch 的數字寫成「combined full gate 已完成」。

## 5. 被中止的 B2 工作

owner 在 18:23 CST 要求停止。下列 subagents 已 interrupt，`to_claude.md` 的
background `tail -F` watcher 也已停止。

### 5.1 Storage / D1 draft

```text
worktree: /private/tmp/claude-logout-storage
branch:   claude-logout-storage
base:     a3992e8（注意：早於 SID integration f074492）
status:   untracked apps/sso/migrations/0016_logout_revocation_outbox.sql
```

該 `0016` 只有中途 SQL 草稿，未 commit、未測試、未 review，不可 cherry-pick 或
視為完成。草稿意圖是：

- 新增無 session/user/client cascade FK 的 `rp_session_visit` snapshot；
- rebuild `logout_delivery`，移除 client `ON DELETE CASCADE`；
- `BEFORE DELETE ON session` trigger 原子寫 revocation audit/outbox、刪 access
  tokens、revoke refresh tokens、刪 authorization codes、清 visit ledger；
- jti 由未來 request-path Web Crypto hook 提供，SQL 不產 security nonce。

接手前先把 branch rebase/重建到 `f074492`，逐行 review migration，再用真實
workerd D1 實證 single delete、DELETE MANY、user FK cascade、fault rollback。

### 5.2 Test-RP receiver

```text
worktree: /private/tmp/claude-logout-rp
branch:   claude-logout-rp
base:     f074492
status:   clean，沒有修改或 commit
```

原定範圍是 migration `0002_backchannel_logout.sql`、`POST /backchannel-logout`、
`jose@6.2.3` exact dependency、真實 Ed25519/JWKS 驗證、receipt `jti` 冪等與完整
negative tests。完全尚未開始，應從 clean branch 重新指派。

### 5.3 Final docs remediation

```text
worktree: /private/tmp/claude-doc-truth-final
branch:   claude-doc-truth-final
base:     f074492
status:   clean，沒有修改或 commit
```

原定修正 release audit findings，尚未開始。

### 5.4 Codex negative-test branch

```text
worktree: /private/tmp/codex-test-rp-negative
branch:   codex/test-rp-negative
HEAD:     74b2f56
status:   clean，沒有修改或 commit
```

Codex 曾準備補 replay/wrong-audience/resource negatives，但收到 `to_codex.md`
指令後已立即停止，避免和 SID test-RP 變更撞線。不要以為這個 branch 有額外交付。

## 6. B2 已完成的 read-only 設計

沒有 runtime code，但已完成一次 evidence-based design review。建議最小安全方案：

1. Provider exact patch 在 authorization-code token writes 前加入 awaited hook，寫入
   `(sid, client_id, WebCrypto jti, validated HTTPS backchannel URI snapshot, shard)`；
   hook failure 不可回 token，token write failure後留下 harmless false-positive visit
   可以接受。
2. D1 session delete trigger 使 central session delete、OAuth access/refresh/code
   revoke、audit、durable delivery 同一 SQLite transaction；admin raw delete 與 user
   cascade 也必須覆蓋。
3. Rebuild outbox 時移除會因 client delete 清掉 delivery 的 cascade FK，保存 endpoint
   snapshot；client metadata 修改/刪除後仍能送原已授權 session 的 logout。
4. Commit 後立即送專用 logout Queue。D1 CAS lease 處理 Queue accept 前 crash；Queue
   payload 只放 opaque delivery ID，不放 sid/JWT/URI。
5. Cloudflare Cron 最快一分鐘，只靠 Cron 無法保證 `codex.md` 的 30 秒目標。建議
   16/32 shard Durable Object alarms 每 5-10 秒短期 replay，Cron 每分鐘 watchdog。
6. Consumer 從 D1 重讀 snapshot、確認 central session 已不存在，再用 Better Auth
   `auth.api.signJWT` 與現有 EdDSA JWKS 簽短效 logout token。相同 delivery 固定同一
   `jti`，RP 200 後 consumer crash 可安全重送。
7. RP 驗 signature/alg/kid/iss/aud/iat/exp/jti/events/sid，拒 nonce；`typ` 缺省可接受，
   若存在必須是 `logout+jwt`。同一 `jti` + 同 sid replay 回 200；同一 jti + 不同 sid
   回 400；首次按 sid 刪全部對應 local sessions。
8. `/sign-out` 與 provider end-session 現在會吞 session delete error，B2 必須改為
   delete/outbox failure 不清 cookie、不回成功。admin suspend/revoke/delete 也需 pre-arm
   replayer，但 D1 trigger 才是 source of truth。

官方行為已在 2026-07-16 查證：Cloudflare Queue 是 at-least-once、DLQ 需明確
配置；Cron 最快每分鐘；Durable Object alarm 是 at-least-once，throw 後 2 秒起始
exponential backoff、最多 6 次。實作時仍應重新查最新官方文件。

## 7. Release audit 尚未修正

唯讀 audit 已完成，以下都沒有 code/doc fix：

### High

1. **Release gate 不 hermetic、無 CI**
   - `.gitignore` 忽略 `worker-configuration.d.ts`，但 SSO tsconfig 依賴它；
   - SSO `check` 不先跑 `cf-typegen`；乾淨 checkout 可能先 typecheck fail；
   - test-RP `check` 不跑 protocol tests；root `check` 因而不完整；
   - repo 沒有 tracked CI/SAST/secret/IaC gate。
2. **失效的 production 操作授權**
   - `agentlog.md` 與 `msg.md` 仍像是允許 agent 直接 flip public / deploy；
   - 應加 superseded historical banner，現行權限只依 AGENTS/codex，禁止自動
     deploy、remote D1、public flip。
3. **Roundcube Path A token 驗證錯誤**
   - `docs/integration-plans/roundcube.md` 多處把 opaque `pg72_at_` access token 寫成
     可用 JWKS 本地驗；Path A 必須走 scoped introspection，JWKS 只驗 ID/logout JWT。

### Medium

4. `handoff.md` 現行區下半部仍有 Passkey/`0014` in-progress、worktree、QA 舊敘述；
5. `wiki/users/getting-started.md`、`wiki/faq.md` 把 invite-only production 寫得像
   verified Google email 可直接註冊；
6. `SECURITY.md` accepted Moderate `GHSA-p2fr-6hmx-4528` 沒有明確 deadline；建議
   policy deadline：`2026-10-16` 或 full Production GO / 下一個修正版 stable upgrade
   前，以最早者為準；
7. Google 只有 sign-in redirect / registration helper tests，缺真 callback
   success、existing user、cancel、provider error regression；
8. `agentlog.md`、`msg.md`、`handoff.md` 有完整 VPS IP、個人 Cloudflare email/
   account IDs，需保留歷史語意但遮蔽值。

### Low

9. `docs/design-system.md` 依賴未 tracked `morden_dark.txt`，且把已排除的 Status
   列入 scope；
10. frontend `/about` 與 `docs/about-PGID.md` 漂移，仍顯示禁用名稱
    `PGID（PG72 ID）`、過度宣稱所有服務皆已接入、沒有清楚標示 invite-only beta。

Audit 同時確認：tracked secret pattern 無命中；dependency audit 是 0 Critical、
0 High、1 個已接受 Moderate；Wrangler config 沒有發現新的明顯 schema/binding
錯誤。

## 8. 建議接手順序

1. 從 `f074492` 建新的整合 worktree，或明確繼續
   `/private/tmp/claude-pgid-completion`；不要直接改主 checkout。
2. 確認本文件的 handoff commit 與 integration status，不要把其他 worktree 草稿一起帶入。
3. Review storage draft，不直接採用；先補真 D1 trigger/cascade/fault tests。
4. 平行實作 clean test-RP back-channel receiver。
5. 在 storage schema 穩定後實作 provider pre-token visit hook、session delete
   fail-closed、專用 Queue/DLQ、DO alarm replay、Cron watchdog與 admin paths。
6. 整合 B2 後再修 §7 文件/CI/Google callback coverage，避免同時衝突
   `auth.ts`、provider patch、test-RP 與 protocol docs。
7. 跑 hermetic final gate：offline frozen install、typegen、SSO full check、test-RP
   full test/typecheck/build、fresh D1 全 migrations、diff/secret/dist/dependency/config
   scans、desktop/mobile UI smoke。
8. 只把 local completion 寫成 local completion。Production migration、deploy、
   secret provisioning、mail cutover、real-provider smoke、DAST、法務核定、復原演練與
   independent review 都由 owner 執行。

## 9. Production 明確未完成

- 沒有 `git push`，repo 仍沒有 Git remote；
- 沒有 `wrangler deploy`、remote D1、Cloudflare/VPS/secret-store mutation；
- production D1 最新既有紀錄仍只到 `0012`；local `0013`、`0014`、`0015` 都未
  remote 套用；
- Passkey step-up、Telegram enrollment fix、provider uniqueness、central `sid` 都只在
  local integration branch；
- `pgid-mail-introspect` 未 provision，Mail Path A 未 cutover；
- central visited-client ledger、back-channel logout、DLQ/redrive/alerting 未完成；
- Copy/Link/Status/Upload/File/Roundcube 等 RP 尚未逐一完成 replay-safe receiver 與
  Preview/production drill；
- public registration 未核准，production config 仍是 `REGISTRATION_MODE=invite`；
- recovery/break-glass、rotation/restore drill、independent review、DAST/SAST/secret/
  IaC automation、法務文件有效日期仍是 full Production GO gate；
- File Browser upstream security blocker應由 owner 在 rollout 前重新查證，不可只依
  這份 point-in-time handoff。

## 10. 通訊與 watcher 狀態

- 主 checkout 的 `to_claude.md`、`to_codex.md` 是未提交通訊紀錄，保留；
- `to_claude.md` background watcher session 已在 owner 要求停止後以 Ctrl-C 關閉；
- Codex 已完成 Passkey source branch；之後的 test-RP negative branch是 clean、無成果；
- 我曾在 `to_codex.md` 請 Codex做 B2 read-only反證，但停止前沒有收到新的 findings；
- 下次若重新啟動 watcher，避免同時有多個 `tail -F` orphan process。

## 11. Agent 使用紀錄

| Agent / channel | 任務 | 結果 |
| --- | --- | --- |
| Codex via `to_codex.md` | Passkey step-up | 完成 source HEAD `74b2f56`，已全數整合 |
| `code_audit` | Telegram enrollment + identity uniqueness | 完成 `768b99e`、`c5bf6c4`，整合為 `d6b739c`、`a3992e8` |
| `spec_backlog` | Central `sid` B1 | 完成 `9cb72d5`，整合為 `f074492` |
| `passkey_status` | Passkey獨立 review + B2 read-only design | review通過；B2只有設計，無 code |
| `release_audit` | release/doc/security audit | findings見 §7；後續修正任務被中止，worktree clean |
| `logout_storage` | B2 D1 storage spike | 被中止；只有未測、未提交 `0016` SQL 草稿 |
| `logout_rp` | test-RP back-channel receiver | 被中止；worktree clean，未開始 |

所有 agent 在本文件建立前均已停止或完成，沒有應繼續等待的執行 session。
