# PGID SSO 架構規格

> 狀態：Canonical Architecture Baseline
> 最後更新：2026-07-18
> 服務名稱：PGID
> Issuer：`https://sso.pg72.tw`

## 0. Phase 0 實作狀態

截至 2026-07-18，repository source 包含 SSO Worker、React 帳號中心、D1 migrations `0001`–`0021`、Google/Passkey、可選社群登入、OAuth 2.1 Provider、四級角色、邀請/停權/audit/client 管理、ID-token central `sid` contract、durable global logout ledger/outbox/Queue delivery、Mail Path A introspection prerequisite、Passkey client-mutation step-up、Telegram verified-email enrollment boundary、全域 provider-identity 唯一 ownership、Turnstile-backed public-registration intent、版本化法律同意紀錄、公開新帳號 restricted access 與 abuse-response runbook、預設關閉且 hash-only 的 recovery-code/Passkey replacement flow、observability `0020` schema、pure alert rule/evaluator/parser、尚未接入 Worker entry point/scheduler 的 evaluator runtime-status/lease/bootstrap 與 alert state/incident/outbox CAS repositories、十項 `audit_event` 規則、OAuth client report 規則、global fan-out gap 規則與 logout delivery health 規則的 bounded source repositories，以及 pure audit-archive record/envelope crypto contract 與 schema-only `0021` archive ledger，另有使用 `oauth4webapi` 的獨立 test RP。每個 release candidate 都必須重跑本 repository 的 typecheck、workerd suite、production build 與 test RP protocol gate；本地通過不得寫成遠端已部署。

`0013_confidential_client_secret_post.sql` 將既有 confidential client metadata 正規化為 `client_secret_post`；它不旋轉 secret、不改 grant/token。`0014_passkey_step_up.sql` 新增 session step-up timestamp 與短效 challenge table。兩者都不代表 production 已套用；現有 deployment record 仍只確認 production D1 至 `0012`，必須由 owner 在維護窗口依序確認與執行。

`0015_account_provider_identity_unique.sql` 以 `(providerId, accountId)` 全域唯一索引保證每個外部 provider identity 只有一個 PGID owner。套用前必須執行下列唯讀 duplicate preflight；若有任何結果就停止，不得由 migration 自動挑選或刪除 owner。依賴此 invariant 的 Worker 不得早於 `0015` 部署。

`0016_public_registration_intent.sql` 新增短效、一次性 public-registration intent、user 初次法律同意欄位與不可變 history。新增欄位已納入 Better Auth user schema，因此任何含此變更的 Worker 都必須在部署前先套用 `0016`；migration 可在 `invite` 模式下先套用，且本身不會開啟公開註冊。

`0017_restricted_account_access.sql` 新增獨立於 lifecycle status 的 `user.accessLevel`、既有資料 `standard` default/backfill，以及 restricted role/provider-link/client-owner D1 guards。任何含 restricted request guard 的 Worker 都必須在部署前先套用 `0017`；migration 可在 `invite` 模式下先套用且不會改變現有 production 註冊模式。Production 尚未套用 `0017` 或部署此 Worker。

`0018_global_logout.sql` 新增 client back-channel URI、實際 `(sid, client_id)` visit ledger、durable logout delivery/attempt evidence 與 access-token visit trigger；舊而未被 runtime 使用的 delivery table 會保留為 `logout_delivery_legacy_0018`。任何含 global-logout Worker 的環境都必須先套用 `0018`，並 provision 專用 logout Queue/DLQ。Production 尚未套用 `0018`、部署此 Worker、provision 專用 Queue，或完成任何 production RP receiver 驗收。

`0019_recovery_codes.sql` 新增 recovery code set、一次性 code hash、獨立短效 recovery session 與 Passkey registration challenge；既有使用者不會自動取得 recovery code。Migration 不會自行啟用功能，runtime 仍由 `RECOVERY_MODE` 控制。Production deployment record 仍只確認至 `0012`，尚未套用 `0019`、綁定 recovery limiter、啟用 recovery、完成獨立 review 或執行 lost-device/rollback drill。

`0020_alert_observability.sql` 只新增 redacted alert state、incident、immutable Email delivery snapshot/attempt 與 runtime-status schema，並加入 nullable persistent audit actor/OAuth reporter HMAC reference、immutable alert-key continuity sentinel，以及 audit/OAuth/logout 的 bounded evaluator indexes。Actor/reporter ref 首次寫入必須同列保有 raw FK；之後 account deletion 才可用既有 `ON DELETE SET NULL` 清除 raw FK 並保留 immutable ref。Migration 本身不執行 backfill、建立 sentinel row、排程 evaluator、傳送 Queue/Email 或提供 operator endpoint。Repository 另有 pure versioned rule definitions、deterministic evaluator、exact repository-projection parser、負責 evaluator runtime 初始化、lease acquire/renew、terminal success/failure exact CAS、immutable first-success `INSERT ... SELECT` bootstrap 與 exact projection read 的 D1 repository、把一個 pure evaluator decision 以 revision CAS 原子寫入 `alert_state`、`security_alert` 與 canonical `alert_outbox` snapshot 的 D1 repository、只涵蓋 registration/restricted/recovery/Passkey/admin 十項 `audit_event` 規則的 bounded source repository、`pgid.oauth.client_report.v1` 的 bounded source repository、`pgid.security.fanout_gap.v1` 的 global bounded source repository，以及 `pgid.logout.delivery_health.v1` 的 bounded source repository。Audit source 將 ratio/recovery denominator domain 固定在 `1,000,000`，並以 partial index 和每規則 `LIMIT 1001` 讀取仍需持續評估的 tracked identity；OAuth source 以 exact half-open 5/15/60-minute windows 讀取 total/high-risk/reporter evidence，使用分離的 client/reporter HMAC domain，並讓缺失 reporter provenance 的 distinct count 保持 nullable；fan-out source 以 exact half-open one-hour lookback 比對 `audit_event.id` 與 `security_event_delivery.event_id`，只產生 global、strict older-than-five/fifteen-minute aggregate，對非 canonical source timestamp、錯誤 projection 與不一致 cohort fail closed；logout source 以同一 awaited D1 batch 檢查 sparse invalid-timestamp indexes，分開讀取所有 `created_at < asOf` 的 current unresolved/dead 狀態、delivery-created half-open cohorts 與 terminal `lease_expired` attempt-completed cohorts，保留 global 與 `client_hmac` 維度，並在完整 client projection無法重建 global aggregate 時 fail closed。這六個 repository 都有 Workerd regression，但未由 Worker entry point 或 scheduler 匯入。Fan-out source 不建立通用 durable security-event delivery、replayer 或 Queue wiring，logout source 也不改變既有 delivery、replay、Queue 或 Cron 保證。Queue source、Cron、dedicated alert Queue/DLQ、Email Service adapter、admin API/UI 與同輪 execution proof 仍未實作。Actor/reporter coverage 不完整、sentinel missing/mismatch、fan-out evidence 或 logout projection 不可信時必須保持 unknown/blocked，observability dependency 因此只能是 `source_present_unverified`，不能標記 `verified`。

同一個尚未部署的 `0020` source 另為 `audit_event.occurred_at`、`oauth_client_report.created_at`、`logout_delivery.created_at` 與 non-null `logout_delivery_attempt.completed_at` 建立只包含 non-canonical row 的單欄 partial index，並以 `BEFORE INSERT`/timestamp `UPDATE` guard 阻止未來壞資料。Audit、OAuth、fan-out 與 logout repository 都在同一 D1 batch 的 lexical window 前，以 `INDEXED BY` sparse index 的 bounded `EXISTS ... LIMIT 1` 證明全域 timestamp coverage；任何 legacy corruption 或錯誤 projection 都只回 redacted `source_invalid`，不能產生 known zero。正常空 index 只走 covering probe；legacy row 可更新成 canonical UTC millisecond text 後離開 index。`0021` 在 archive capture/backfill 配發 sequence 前另以 parent `audit_event.id` primary-key lookup 重驗 canonical time，未修復 row 會使整個 backfill statement abort，而不是依錯誤字典序固化。這些仍只是 local migration/repository contract，不代表 production 已套用或 observability 已接線。

Local source 也包含 pure audit-archive record/envelope crypto contract：canonical record 保存 nullable actor reference/version，且 header、manifest 與 AES-GCM AAD 綁定 `checkpointFromSequence`。Schema-only `0021_audit_archive.sql` 已提供 monotonic source ledger、immutable batch membership、archive-key sentinel schema 與 trigger-coupled D1 finalization/checkpoint/BLOB cleanup，但這仍不是 encrypted R2 archive implementation。Disabled repository、KEK custody、R2 create-only writer/bounded restore、Queue/DLQ、Cron redrive、retention exercise 與 Cloudflare 之外的 backup 仍未實作，所以 `encrypted_r2_archive` 必須維持 `dependency_missing`。完整 source boundary 見 [`docs/runbooks/alert-observability.md`](./docs/runbooks/alert-observability.md) 與 [`docs/runbooks/audit-archive.md`](./docs/runbooks/audit-archive.md)。

### 0.1 Provider Identity Migration Preflight

在 owner-controlled maintenance window 內、套用 `0015` 之前，對 production D1 執行：

```sql
SELECT providerId, accountId, COUNT(*) AS copies
FROM account
GROUP BY providerId, accountId
HAVING COUNT(*) > 1;
```

必須回傳零列。若有任何 duplicate，停止 rollout，獨立審查受影響的使用者與 audit evidence；不得自動刪除、重新指派或合併 identity owner。之後先建立 private backup / Time Travel checkpoint，於隔離 Preview 驗證後才依序套用 `0013`、`0014`、`0015`、`0016`、`0017`、`0018`、`0019`。

### 0.2 Recovery Credential Migration Preflight

`0019` 將 `passkey.credentialID` 收緊為全域唯一。套用前由 owner 對目標 D1 執行唯讀 preflight：

```sql
SELECT credentialID, COUNT(*) AS copies
FROM passkey
GROUP BY credentialID
HAVING COUNT(*) > 1;
```

必須回傳零列。任何 duplicate 都停止 `0019` rollout，保留 private evidence 並獨立審查 credential ownership；不得讓 migration 或 coding agent 自動刪除、重新指派或合併 Passkey。Provider identity 與 Passkey preflight 都通過、backup/checkpoint 完成後，才可在隔離 Preview 依序驗證 pending migrations。

既有公開部署紀錄顯示 `pg72-id` 已部署至 `https://sso.pg72.tw`，production D1 已套用至 `0012`，Copy 與 Link 也已切換 production traffic 至 PGID。這些紀錄建立了「已部署 invite beta」現況，但仍不是完整 Production GO：global logout 與 recovery-code path 只在 local source 完成，`RECOVERY_MODE` 維持 disabled，Preview/production migration、專用 Queue/DLQ、各 RP receiver、外部告警、完整復原演練與其他 §9.2 gate 尚未完成。任何 maintenance operation 前都必須由授權 operator 重新驗證實際遠端版本與 migration 狀態。

Preview 必須使用獨立 Cloudflare account、D1、queue、secret、domain、Google callback 與 Rate Limiting namespace，不得以 production D1 或 production secret 代替 Preview。

SSO 的 Cloudflare Vite build 包含 post-build cleanup，production/preview artifact 不保留 plugin 為 `vite preview` 複製的 `.dev.vars*`。

Production `REGISTRATION_MODE` 目前仍是 `invite`。`public` 程式路徑與 workerd regression tests 已備妥：所有新帳號都必須通過 verified-email enrollment gate，Google 首次登入要求 verified email，Telegram 因不提供 email 而只能登入已明確連結的既有帳號；邀請功能保留，新帳號建立使用獨立 per-IP `REGISTRATION_RATE_LIMITER`，suspended/deleted 使用者仍由 session 建立檢查擋下。Local source 另要求 exact-hostname/action Turnstile 驗證、版本化 Terms/Privacy 明確同意、一次性 intent，以及公開新帳號持久化 `restricted` access。受限帳號保留普通登入、帳號與 OIDC 使用，但 provider linking 與 PGID developer/admin/client management 皆 fail closed。完整安全 gate 尚未完成，未完成項目列於 §9.2；只有 owner 明確核准並部署設定變更後才算開啟公開註冊。

Repository source 包含 Mail Path A 所需的 PGID introspection prerequisite。它只允許固定的 `pgid-mail-introspect` 查詢簽發給 `pg72-webmail` 的 opaque access token，且 token 必須保有 live central session、`email` scope，以及 active、verified-email user；完整契約見 §10.5。這項結果尚未部署、尚未 provision system client，也未經 production 驗證；Dovecot/Postfix/Roundcube 的 VPS cutover 仍須 owner 在場的維護窗口，不得因本地測試通過而直接套用。

2026-07 的 dependency audit 另發現 `GHSA-p2fr-6hmx-4528`：Better Auth stable `1.6.x` 未綁定 RFC 8707 resource indicator 與原 authorization grant。Phase 0 保持單一 `validAudiences`，並在 Worker 邊界拒絕 authorize/token 的所有 `resource` 參數；v1 不以 resource indicator 作授權邊界。詳細 owner、補償控制與 exit condition 見 [`SECURITY.md`](./SECURITY.md)。第一個包含修正的 stable release 發布後，必須讓 core/plugins 一起升級、重產 migration 並重跑完整 protocol suite。

## 1. 背景

PG72 目前有多個需要登入的網站，每個服務各自使用 Google OAuth、Cloudflare Access、本機帳密或自有 session。這造成以下問題：

- 使用者要重複登入，且每個服務的帳號識別方式不同。
- 沒有統一的使用者 ID、角色、停權與存取政策。
- 無法集中查看或撤銷裝置 session。
- 無法可靠地從所有服務登出。
- 登入與安全事件散落在各服務，缺乏統一稽核紀錄。
- 未來開放任何人註冊時，帳號生命週期與濫用防護會更難管理。

本專案要建立由 PG72 自行掌控的身分系統，不使用 Cloudflare Access 作為登入或授權層。Cloudflare 仍作為執行、資料、網路與防護基礎設施使用。

## 2. 已確認需求

- 現行 production 採邀請制；公開註冊程式路徑保留，只有 §9.2 gate 通過且 owner 明確核准部署後才切換。
- 公開註冊的完整安全 gate 尚未全部完成，未完成項目必須持續列於 §9.2 並如實維護。
- 第一階段登入方式為 Google 與 Passkey。
- 優先部署於 Cloudflare Workers 與 D1。
- SSO 核心使用自己的網域、介面、使用者資料、政策與簽章金鑰。
- 必須支援單一裝置撤銷、其他裝置撤銷、全部裝置撤銷及全域登出。
- 必須提供登入紀錄、安全稽核、管理員停權與遠端撤銷。
- 後續新增的服務應能以標準 OIDC 接入。
- 無法原生使用 OIDC 的服務，改用自有 auth gateway 或可信任 proxy header。

## 3. 目標與非目標

### 3.1 目標

- 建立標準 OAuth 2.1 / OpenID Connect Provider。
- 所有服務以相同、不可變的 `sub` 識別同一使用者。
- 提供 Google 登入與 WebAuthn/Passkey。
- 提供中央帳號中心、裝置管理、應用程式授權與安全紀錄。
- 提供標準 OIDC discovery、JWKS、authorization、token、userinfo、introspection、revocation 與 logout endpoints。
- 所有第一方服務遵守共同 session 與 back-channel logout contract。
- 初期可完全在 Workers/D1 執行，不要求新增 VPS。
- 保留將來把 IdP runtime 遷移到 VPS 的可能性，但 Issuer 網域保持不變。

### 3.2 非目標

- 不自行手寫 OAuth、OIDC、JWT 或 WebAuthn 密碼學實作。
- 不建立跨所有 `*.pg72.tw` 共用的 domain cookie。
- 不把 Email 當成永久使用者主鍵。
- 第一階段不支援密碼登入、Email OTP 或 TOTP。日常登入主力為 Google 與 Passkey；Discord、GitHub、Facebook、Apple、Telegram 社群登入為額外選項（owner 決策，2026-07-16），各 provider 未設定 secret 時自動隱藏。
- 第一階段不開放第三方開發者動態註冊 OAuth clients。
- SSO 負責 authentication；各應用程式仍負責自己的業務 authorization。
- 瀏覽器 SSO 不自動解決 IMAP、SMTP 或其他非 HTTP 協議驗證。

## 4. 現況盤點

| 服務 | Ownership | 現有狀況 | 預定整合方式 | 狀態 |
| --- | --- | --- | --- | --- |
| `copy.pg72.tw` | 第一方 | Next.js / NextAuth、6 位數訪客碼、D1 | PGID OIDC client；訪客碼保持獨立 | Production live；PGID delivery 只在 local source，Copy receiver/rollout 待完成 |
| `link.pg72.tw` | 第一方 | Cloudflare Pages / D1，具有 user/admin | BFF OIDC client，保留應用內角色 | Production live；PGID delivery 只在 local source，Link receiver/rollout 待完成 |
| `status.pg72.tw` | 維護中的 XUGOU fork | Workers / D1 / agent push | OIDC BFF + server-side session；agent auth 分離 | 本機整合與 10 tests 完成；待 Preview D1 |
| `upload.pg72.tw/admin` | 第一方 | FastAPI / SQLite / streaming upload | Admin 原生 OIDC；upload capability 分離 | 本機整合與 11 tests 完成；待 VPS Preview |
| `webmail.pg72.tw` | 上游 Roundcube | Cloudflare Access + Webmail/IMAP login | 打包上游 stable release，設定原生 Generic OIDC | 上游 1.8-git 原始碼已檢視 |
| `file.pg72.tw` | 上游 File Browser | 內建帳密，可使用 proxy auth | 打包上游 stable release，使用可信 proxy auth | 上游原始碼已檢視 |

`file.pg72.tw` 現有的 `proxy` auth 會直接信任指定 HTTP header，並在本機找出或建立使用者。若採此方式，gateway 必須移除用戶端傳入的同名 header、重新寫入驗證後的值，且 File Browser origin 絕對不能被使用者繞過直接存取。

File Browser 與 Roundcube 的目錄是整合研究用上游原始碼，不視為 PG72 要長期維護的 fork。正式部署應從鎖定版本與 checksum 的上游 release 自行打包，PG72 的變更優先放在設定、plugin、adapter 或獨立 gateway；只有上游無法提供必要安全能力時才維護最小 patch。

## 5. 技術決策

| 類別 | 決策 |
| --- | --- |
| Runtime | Cloudflare Workers，TypeScript |
| HTTP routing | Hono |
| Frontend | React，與 Worker 靜態資產整合 |
| Auth engine | Better Auth；目前評估版本 `1.6.23`，core 與所有 plugin exact pin 且版本一致 |
| Identity protocols | OAuth 2.1、OpenID Connect、WebAuthn |
| Social login | Google 為主力；Discord、GitHub、Facebook、Apple、Telegram 為設定後才啟用的可選 provider |
| Database | Cloudflare D1 |
| Schema/migrations | Better Auth CLI 產生基礎 SQL + PG72 版本化 custom migrations |
| Async delivery | Cloudflare Queues + Dead Letter Queue |
| Audit archive | D1 主資料、R2 加密封存、Cloudflare 外部備份 |
| Abuse protection | Workers Rate Limiting binding、Turnstile、應用層節流；不使用 KV 作精確安全計數器 |
| Secrets | Wrangler secrets 或 Secrets Store，不進 Git/D1 明文 |
| Deployment | Wrangler，preview 與 production 完全分離 |

Better Auth 僅作為協議與驗證引擎。PGID 自行實作產品介面、邀請政策、角色、稽核、client 管理、全域登出協調與 legacy gateway contract。

### 5.1 Workers production rules

- 新專案使用 `wrangler.jsonc`、當日 `compatibility_date` 與 `nodejs_compat`。
- 定期升級 compatibility date，升級前必須跑完整 authentication/OIDC regression suite。
- 使用 `wrangler types` 產生 binding types，不手寫 `Env` 或以 `any` 取代 binding 型別。
- Better Auth instance 透過 request-scoped factory 使用 `c.env` 建立，不把 D1 binding 或 request state 放入 module-level mutable singleton。
- 每個 Promise 都必須 `await`、`return` 或交給 `ctx.waitUntil()`；session/token/revocation 的 source-of-truth 寫入一律在回應前 `await`。
- Cloudflare 服務使用 D1、Queue、R2、Rate Limiting 與 Service Bindings，不從 Worker 呼叫 Cloudflare REST API。
- 前端使用 Workers Static Assets；大檔案與 proxy response 採 streaming，不先讀完整 body。
- Production 開啟 structured Workers Logs/Traces 與取樣，所有 auth log 先經過 redaction。
- 不使用 `passThroughOnException()`；錯誤以明確、不可洩密的 response 處理。

### 5.2 Better Auth GO/NO-GO gate

截至 2026-07-15，npm stable tag 為 Better Auth `1.6.23`，`1.7` 仍為 RC。Production 不使用 beta/RC，且 `better-auth`、`@better-auth/oauth-provider`、`@better-auth/passkey` 與其他 plugin 必須 exact pin 到相同 patch line。

在建立完整產品功能前，先以最小 Worker + D1 prototype 驗證：

- Google -> SSO -> test RP 的完整 Authorization Code + PKCE flow。
- 已存在 SSO session 時，以 Passkey 完成 RP authorize flow。
- Authorization code replay、redirect URI mismatch、refresh token rotation、revocation 與 introspection。
- 大量取消中的請求不能使單一 Worker isolate 的 Better Auth endpoints 永久 hang。
- D1 migration、key rotation、JWKS cache 與 Queue logout retry。

目前必須追蹤的上游問題：

- `#8081`：Passkey 在 OAuth Provider authorize flow 中無法正確恢復，issue 仍為 open。
- `#10315`：Cloudflare Workers 中，遭取消的初始化 request 可能污染 isolate 內的 lazy cached promise，issue 仍為 open。
- `#4203`：secondary storage TTL/session 行為曾造成非預期重新登入；v1 不啟用 KV secondary storage 或 cookie cache 組合。

GitHub issue 內的 workaround 不是正式安全保證。任何 workaround 必須以 package patch 固定、附 regression test，並在升級時重新驗證。若 Phase 0 prototype 無法可靠通過以上測試，不在故障基礎上繼續堆功能；改由 VPS 上成熟 IdP/protocol runtime 承擔 Issuer，仍保留 `https://sso.pg72.tw` 與相同 RP contract。

目前 `@better-auth/oauth-provider@1.6.23` 另以 tracked exact-version package patch `patches/@better-auth__oauth-provider@1.6.23.patch` 固定兩個窄行為。Mail Path A 保持 same-client introspection 預設，只提供 opt-in hook 讓 PGID 實作 §10.5 的單一 cross-client 例外；同時修正 `APIError.status` 的 RFC 7662 inactive 判斷、把 `token_type_hint` 維持為 hint 而非限制 lookup，以及分類 token-controlled JOSE/kid failure。RP-initiated logout 則在 provider 完成 ID token signature/issuer/audience/client/`sid` 驗證後提供 opt-in revoke hook，讓 PGID 在刪除 session 前原子 snapshot visit/outbox；未設定 hook 時保留 upstream 行為。這些都不是可泛用的授權或驗證 bypass。

升級 Better Auth 時不得把 patch 機械套到其他版本，也不得用 `allowUnusedPatches` 隱藏版本不符。只有 pinned stable provider 已提供經審核的等價 introspection 與 pre-delete logout hook、乾淨 frozen install 能在移除 patch 後通過，且完整 introspection/end-session/global-logout protocol regression suite 全數通過，才可移除或重作這個 patch；core 與所有 plugins 仍須維持 exact pin 並一起評估 migration/advisory。

## 6. 高階架構

```text
                    +----------------------+
                    | Google Identity      |
                    +----------+-----------+
                               |
                               v
+-------------+       +----------------------+       +------------------+
| User Agent  | <---> | sso.pg72.tw Worker   | <---> | D1               |
| Browser     |       | PGID / OIDC OP    |       | Identity DB      |
+------+------+       +----+------------+----+       +------------------+
       |                   |            |
       |                   |            +----------> Queue
       |                   |                          | logout/audit events
       |                   |                          v
       |                   |                     R2 / offsite archive
       |                   |
       |          OIDC Authorization Code + PKCE
       |                   |
       v                   v
+-------------------+     +--------------+     +------------------+
| Native OIDC       |     | Auth Gateway |     | Admin/API        |
| Copy/Link/Status/ |     | Legacy Apps  |     | Session Portal   |
| Roundcube         |     +------+-------+     +------------------+
+-------------------+            |
                                  v
                           File / Upload
```

## 7. 核心元件

### 7.1 PGID Worker

單一 Worker 初期同時承擔：

- 登入、登出、Google callback 與 Passkey ceremonies。
- OIDC/OAuth endpoints 與 discovery metadata。
- 帳號中心與管理後台 API。
- OIDC client、redirect URI、scope 與 consent 管理。
- Session introspection 與 revocation。
- 稽核事件寫入及 Queue 發送。
- 簽章 key rotation 與 JWKS 發布。

登入與協議路由應盡量保持標準且穩定：

```text
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/.well-known/jwks.json
/oauth2/authorize
/oauth2/token
/oauth2/userinfo
/oauth2/introspect
/oauth2/revoke
/oauth2/end-session
```

若 Better Auth 內部使用不同 base path，對外仍提供以上固定介面或正確 discovery metadata。應用程式不得硬編碼未公開的內部路徑。

### 7.2 D1

D1 是 identity、session、client、token、consent 與 audit metadata 的 primary store。

- 所有 schema 變更必須透過 migration。
- 不依賴 D1 不支援的 interactive transaction。
- 需要原子性的多筆操作使用 D1 batch 或重新設計成冪等步驟。
- Token、client secret 與 recovery code 只存 hash 或加密值。
- 重要寫入使用唯一 event ID / idempotency key。
- Production 資料庫不可供 preview deployment 共用。

### 7.3 Queues

Queue 用於：

- Back-channel logout delivery。
- Security event fan-out。
- Audit archive delivery。
- 通知與之後可能加入的 Email 工作。

Queue 是 at-least-once delivery。所有 consumer 必須以 `event_id` 或 logout token 的 `jti` 去重，並支援重試。無法成功送達的 Queue message 進入對應 Dead Letter Queue；外部告警只有在真的配置、測試並由 operator acknowledgement 後才能宣稱存在。

Queue 不作為撤銷或 audit 真實來源；D1 中的 session/token 狀態與 `audit_event` 才是 source of truth。Global logout 另以 `logout_delivery` 作 durable delivery source：中央撤銷、audit 與每個 visited RP 的 endpoint snapshot 同一 D1 batch commit，專用 `LOGOUT_DELIVERIES` Queue 只攜帶 opaque `deliveryKey` 並作 accelerator，每分鐘 Cron 會重送 due/expired-lease row。每次 claim 先原子寫入 `in_flight` attempt evidence；HTTP 結果同批 terminalize attempt 與 delivery，過期 lease 也先留下 `lease_expired` terminal evidence 才能 reclaim。因此 Queue send failure 或 result write failure 不會遺失 logout work，也不會讓已提交的中央撤銷看似回滾。

一般 security-event fan-out 仍是不同保證：client mutation 先將狀態與 audit 同批 commit，`SECURITY_EVENTS` Queue 只在 commit 後 best effort 發送。Queue 在接受事件前失敗目前可能漏掉該 fan-out，只有 redacted log，尚無通用 durable outbox/replayer 或告警補送；補齊這項是 full Production GO 前必須決定的債務。不得用 global logout outbox 的可靠性宣稱所有 Queue workload 都已 durable。

### 7.4 Auth Gateway

Auth Gateway 僅用於無法原生支援 OIDC 的 HTTP 應用程式。

- 未登入請求導向 `sso.pg72.tw`。
- Callback 完成後在應用程式網域建立 host-only gateway session。
- 每次請求驗證中央 session 或短期簽章 assertion。
- 移除外部請求的 identity headers，再注入由 gateway 產生的可信值。
- Origin 僅接受 gateway 或私人網路流量。
- 高敏感管理服務在中央 session 無法確認時 fail closed。
- 大型上傳與下載服務需驗證 Worker proxy 對串流與大小的影響；必要時在 origin reverse proxy 實作相同 contract。

## 8. Identity Model

### 8.1 使用者識別

- `user.id` 使用不可變 UUID，作為第一方服務共同的 OIDC `sub`。
- Email 可修改，不作 foreign key 或檔案目錄唯一識別。
- Google provider account 以 Google subject ID 綁定，不只比對 Email。
- `account(providerId, accountId)` 在 D1 全域唯一；任何 provider identity 只能連結一個 `user.id`。併發連結必須以資料庫 constraint 決定 winner，再重讀既有 owner 回應 conflict，不得使用 `SELECT` 後 `INSERT` 的競態流程或解析 constraint error 字串。
- 同 Email 帳號不得靜默合併；必須由已登入使用者明確連結。
- File Browser 等需要 username 的服務使用從 `sub` 派生的穩定別名，不直接使用可修改 Email。
- 唯一的日常 Email identity 例外是 §10.5 的 Dovecot legacy mailbox lookup：固定 mail introspector 可從符合窄條件的 `pg72-webmail` access token 取得 verified email，以對應既有 mailbox。這不改變 PGID/RP 的 `sub` 主鍵規則，不可擴張成帳號合併、一般服務授權或其他 client 的 identity binding。

### 8.2 使用者狀態

```text
registration: invited -> user row created
lifecycle:                 active <-> suspended -> deleted
access:                  standard <-> restricted
```

- `invited`：已有邀請但尚未完成初次登入。
- `active`：可正常登入與授權。
- `suspended`：所有 session/token 撤銷，不可重新登入。
- `deleted`：完成保留期後移除或匿名化個資，稽核事件保留必要識別摘要。
- `user.status` 只表示 lifecycle；`user.accessLevel` 是正交的敏感功能邊界，不得以 `restricted` 代替停權。
- `standard`：可依平台角色使用 PGID developer/admin/client-management 功能，仍受角色、fresh session、Passkey step-up 與 rate limit 約束。
- `restricted`：仍可登入、查看/維護一般帳號資料、使用 Passkey、完成 consent 與 ordinary OIDC；effective 平台角色固定為 `user`，不可新增 provider link、持有 elevated role、新建/接管 OAuth client，或進入任何 PGID developer/admin/system-client 管理面。Restrict 不會隱含停用既有 owned RP；事故需要時由 operator 另行處理 client containment。
- 未受邀的 public-created user 初始為 `restricted`；invited/bootstrap user 與 migration `0017` 前既有 row 為 `standard`。Admin 可在 hierarchy 內顯式 restrict/promote；restrict 會降為 `user` 並撤銷中央 sessions/tokens，promote 不會復權 suspended 帳號或恢復舊角色。

### 8.3 角色與權限

平台角色固定為 `bootadmin`、`admin`、`developer`、`user` 四級；完整權限與保護規則以 §12.3 及 `apps/sso/worker/roles.ts` 為準。`bootadmin` 由 `BOOTSTRAP_ADMIN_EMAIL` 推導，不能由一般角色指派。

應用程式角色另存為 client-specific grants，例如 `link:admin`、`status:operator`。平台角色不能自動等同所有服務的 admin，避免單一 claim 過度授權。

## 9. 註冊與登入政策

> 現行 production 設定：`REGISTRATION_MODE=invite`。
> `public` 程式路徑與測試已備妥，但下列 gate 尚未完成；只有 owner 明確核准並部署設定變更後才算開放。
> 本節分開記錄「目前已部署行為」與「尚未啟用的 public path」，不得把可用程式碼寫成遠端現況。

### 9.1 邀請註冊（現行）

- 未受邀 Email 拒絕建立帳號，回傳 `INVITATION_REQUIRED`，並寫入 `registration.denied` audit；bootstrap administrator 依既定保護規則例外處理。
- 管理員以 Email 建立有時效且單次使用的邀請。
- 有未消耗邀請的 Email 完成首次登入時，帳號以 `standard` access 取得邀請指定的角色（例如 `admin`），邀請立即標記為已消耗。
- 邀請功能在未來 public 模式仍保留，與公開註冊不衝突。

### 9.2 公開註冊路徑與啟用 gate（未部署）

已實作且有 regression coverage 的 `REGISTRATION_MODE=public` 行為：

- 公開新帳號只能由第一次 Google 登入建立；Google 必須回傳已驗證 Email（`email_verified`），否則拒絕（`EMAIL_NOT_VERIFIED`），兩種模式皆強制。Discord、GitHub、Facebook、Apple 等可選 provider 的既有 linked identity 可繼續 ordinary login；只有 standard account 可在 authenticated session 中新增明確連結，且它們不得成為 public 建帳入口。
- Telegram Login Widget 不提供 Email，因此未綁定的 Telegram identity 在 invite/public 兩種模式都先消耗 registration limiter、寫入不含 Telegram ID 或其他 PII 的 `registration.denied`，再以相同泛化錯誤拒絕；不得建立 placeholder-email user 或 session。Telegram identity 只能在 standard authenticated PGID session 中明確連結；帳號之後被 restrict 不會移除既有 link，仍可作 ordinary login method。
- Passkey 註冊仍需先有帳號與已登入 session；公開註冊不開放無帳號的 Passkey 註冊。
- 前端把登入既有帳號與建立新帳號分開；只有新帳號路徑顯示目前 Terms/Privacy 的明確勾選與 Turnstile。Google 是唯一 public 建帳入口；Passkey、Telegram 與其他可選社群 provider 均不顯示為建帳選項。
- `POST /api/registration/intent` 只接受 exact same-origin JSON，要求 client 回傳 Worker 公布的目前 Terms/Privacy version 並皆明確同意，再以 Turnstile Siteverify 驗證 `success`、exact issuer hostname 與固定 action `pgid_public_registration`；challenge 服務不可用時 fail closed。
- 驗證成功後只核發 10 分鐘、Web Crypto 產生、D1 一次性消耗的 opaque intent ID；D1 只保存其 SHA-256 digest。第一方註冊起始 endpoint 將 raw intent 換成獨立 secondary reference，Better Auth 保護的 OAuth state 只帶該 reference，server 再把其 digest 綁定實際 Better Auth OAuth state digest；raw intent 不寫入 D1 或 Better Auth verification value。Callback 建立 user 前必須以兩者原子消耗 intent，過期、重放、版本不符、provider 不符或缺少皆回泛化拒絕；browser 不保存或傳送 Turnstile secret。
- `0016` 將 server-side intent issuance time、Terms version 與 Privacy version 隨 user 建立寫入；D1 trigger 強制三欄全有或全無、禁止變更初次同意，並在同一 transaction 建立 `legal_acceptance` history。帳號存在期間直接 UPDATE/DELETE history 會被拒絕；依 Privacy Policy 刪除 parent account 時則由 FK cascade 一併移除其 account-scoped history。Invite-mode user 的三欄保持 `NULL`。
- 新帳號建立有獨立、比登入更嚴的 per-IP rate limit（Workers Rate Limiting binding `REGISTRATION_RATE_LIMITER`，5 次/60 秒；登入面為 `AUTH_RATE_LIMITER` 30 次/60 秒）。限流檢查在任何 denial audit 寫入與邀請查詢之前消耗額度，避免被濫刷。
- 觸發限流寫入 `registration.rate_limited` audit；所有 registration 拒絕訊息不洩漏帳號是否存在。
- `suspended` 使用者不因公開模式繞過管制：session 建立前一律檢查中央 `user.status`，非 `active`（含已刪除、user row 不存在）一律拒絕。
- 已刪除帳號重新註冊會取得全新的 `sub`；RP 視其為新使用者，不會繼承舊資料。
- 未受邀、非 bootstrap 的 public-created user 持久化為 `accessLevel=restricted`；邀請與 bootstrap 建帳為 `standard`，`0017` 套用前既有 rows 由 default/backfill 保持 `standard`。Restricted user 保留 basic login、account view/mutation、Passkey 與 ordinary OIDC；ID token/UserInfo 平台 role claim 固定為 `user`。
- Restricted user 不可新增 Google/Telegram/其他 optional provider link，不可取得 elevated platform role，不可新建或接管 OAuth client，也不可使用 developer/admin/system-client management。Initial public Google account 是 migration trigger 的唯一窄例外；request guard 每次重讀 D1，所有 management/developer mutation 的 D1 batch 另以同一 actor session + email/stored-role snapshot 重驗 live + active + standard，D1 trigger 則守住 provider/client-owner/role constraint。既有 owned client 不因 restrict 自動停用，若 incident 涉及該 RP 必須由 operator 另作 client containment 決策。
- 管理後台可依 `standard`/`restricted` filter，並在 role hierarchy 內執行 restrict/promote/suspend/reactivate。Restrict 同批 demote 至 `user`、撤銷 sessions/access tokens/refresh tokens 並插入 success audit；promote 不 re-activate、不還原舊 role。Actor 或 target guarded snapshot 不符時回 state-conflict，且 mutation 與 success audit 都不落寫；重複的 no-op transition 不新增 success audit。
- Restricted sensitive denial 寫入 `account.restricted_action_denied`，metadata 只有固定 `surface`；`user.created` 另記 `accessLevel` enum，讓 promotion/deletion 不會改寫歷史 volume。Registration limiter/denial 與管理狀態轉換事件同樣避免 email/IP/token。初始人工 review threshold、triage、containment、false-positive 與 invite-mode rollback 見 [`docs/runbooks/public-registration-abuse.md`](./docs/runbooks/public-registration-abuse.md)。Repository 尚無外部 dashboard/paging/自動 suspension，runbook 不等同 operational monitoring。

切換 production 至 public 前尚未完成的安全 gate：

- [ ] 將 local source 已實作的 Turnstile registration challenge 部署至隔離 Preview，配置 hostname-scoped site/secret key，完成獨立 review、bypass/失效/服務中斷測試與 production smoke；production secret 僅可存 Wrangler secrets / Secrets Store。
- [ ] 由 owner 核准實際 Terms/Privacy 內容與 version identifiers，於隔離 Preview 驗證 `0016` 同意紀錄、rollback 與資料匯出，再部署並 smoke-test；local schema/UI/regression 通過不等同法務核准或 production 啟用。
- [x] Repository abuse response runbook：以現有 redacted D1 events 提供人工查詢、具體 threshold、triage、restrict/promote/suspend、false-positive 與 rollback；不宣稱外部監控已存在。
- [ ] 在隔離 Preview 以核准負載驗證/調整 runbook threshold，指定 operator/response channel，並實作及測試外部 aggregation 與 alert delivery。
- [ ] 獨立安全審查與 OIDC conformance/security testing。
- [ ] 在隔離 Preview 完成 authenticated DAST，覆蓋 auth、OIDC、admin、gateway 與 logout endpoints；repository 現有 `pnpm dast:local` 只跑 ephemeral loopback Worker/test RP 的無憑證 public/error/header/CSRF baseline，受保護的 manual Preview workflow 尚未執行，不能取代完整 gate。
- [x] Repository source 已有 `pnpm security:check` 自動化 gate：type-aware Worker Promise SAST、checksum-pinned Gitleaks 完整 history、明確枚舉 tracked/untracked/ignored sensitive path，並以 TypeScript compiler AST bounded static evaluator、line/dotenv parser、UTF-8/UTF-16/NUL decode、exact fixture/fallback digest+context contract 與 unsafe-path hash diagnostics 實作 redacted scan。兩個 workflow 在 checkout 後、任何 repository script／Preview authorization／`pnpm install` 前先執行只用 Node standard library 的 identity checker，固定 workflow raw LF bytes/file set、四個 manifest/完整 scripts map、`pnpm-workspace.yaml` lifecycle/build policy、`pnpm-lock.yaml` raw digest 與 `patches/` exact file set/digests，並要求 workspace `.pnpmfile.mjs`／legacy `.pnpmfile.cjs`、各 code-owned package root `.npmrc`／`binding.gyp`／pre-existing `node_modules` 不存在；後段再固定完整 scripts objects、reachable graph，並展開每個 pnpm script 的 `pre*`/`post*` 及全 workspace `preinstall`/`install`/`postinstall`/`prepare`。另以 code-owned SHA-256 固定 deterministic production Wrangler entry whole-file identity，再保留 GitHub Action SHA、workflow/job/step structural validation、artifact upload、environment scope、Wrangler source/generated typed binding/resource contract、exact advisory reconciliation、production artifact source-map/private-path/secret/size scan，以及 dependency/license inventory。任何 runtime/dependency/bundler/build-chain 變更都必須經人工 review 與兩次 byte-identical clean build/dry-run 後才可明確更新 entry digest，不可從 policy 或目前產物自動學習；目前 Linux entry digest equality 尚未實測，不能宣稱跨平台一致。每個 release candidate 仍必須先安裝 pinned tools、實際跑完並保存結果。
- [ ] 負載測試、備份還原演練、key rotation 與 Queue retry/DLQ 演練。
- [x] Source-local fail-closed continuity/load tooling：固定 literal-loopback target、clean Git commit attribution、fresh D1 migration/export/restore、完整 ordered migration ledger、synthetic Passkey/session/consent/JWK overlap-retirement、固定六 scenario／每項 16 request 的 bounded profile、mode-`0600` redacted schema-v2 report 與 cleanup regression；命令與報告格式見 [`docs/runbooks/continuity.md`](./docs/runbooks/continuity.md) 與 [`docs/runbooks/load-failure-drills.md`](./docs/runbooks/load-failure-drills.md)。這只代表工具已進 source，不代表 dependency 或演練已通過。
- [x] Recovery `0019` 與 release automation 已整合進 local candidate；兩個 local command 會在同一 process 內分別要求 exact recovery 4-suite/20-test proof 與 exact release 9-file/89-test proof，才可把其 dependency 從 `source_present_unverified` 升為 `verified`。這只記錄 candidate source 與可重跑 proof，尚不代表 final independent integration review、final Worker artifact identity 或 Preview gate 已完成。
- [x] Observability `0020` schema、pure rule/evaluator/parser、尚未接入 Worker entry point/scheduler 的 evaluator runtime-status/lease/bootstrap 與 alert state/incident/outbox CAS repositories、bounded 十規則 `audit_event` source repository、bounded OAuth-report source repository、bounded global fan-out-gap source repository、bounded logout-delivery source repository、archive record/envelope crypto contract 與 schema-only `0021` ledger 已加入 local source 並具負面/競態測試；六個 repository 都尚未接入 Worker/scheduler，fan-out source 不提供 durable delivery/replay，logout source 也不改動 delivery/replay；其餘 Queue source、Cron、alert/archive Queue/DLQ、Email/admin delivery、R2 writer/restore/external backup 與同輪 execution proof 仍不存在，所以 observability 必須維持 `source_present_unverified`，archive source 也不能把 `encrypted_r2_archive` 從 `dependency_missing` 升級。
- [ ] 完成並獨立 review observability repository/Cron/delivery proof 與 encrypted R2 archive `0021` writer/checkpoint/restore/external-backup contract；兩個 local report 對任何非 `verified` dependency 都必須維持 blocked + nonzero，全部五項到位後才可記錄 synthetic local pass。
- [ ] 在隔離 Preview 另行執行核准 budget 的 D1 restore、signing-key rotation、recovery、Queue retry/DLQ、R2 archive/restore、外部 alert delivery、failure rollback 與 RP smoke；local synthetic report 不可勾除此項。
- [x] Local source 的 persistent restricted-account state、request guards、D1 race guards、admin controls 與 workerd regression。
- [ ] 套用 `0017`、部署 restricted-account Worker 至隔離 Preview，完成獨立 review、race/rollback/ordinary-OIDC smoke，再納入 production rollout；不得因 local gate 通過而宣稱已部署。
- [x] Local source 的 visited-client ledger、durable logout outbox、opaque delivery key、原子 `in_flight`/terminal attempt evidence、self-delete 全批 rollback、專用 Queue consumer、Cron replayer、bounded retry、redacted operator replay、bounded JWKS reader 與 test-RP receiver/regression。
- [ ] 套用 `0018`、provision 隔離 logout Queue/DLQ、完成 Preview multi-RP/failure/rollback exercise、部署各 production RP receiver，並實作及測試外部 DLQ/dead-delivery 告警；local source 完成不等於全面上線。
- [ ] 將 local source 已實作的 Passkey step-up 與 migration `0014` 部署至 production，完成獨立 review 與實機 smoke；10 分鐘 session-age freshness 仍是額外條件，不能替代重新驗證。
- [x] Local source 的 `0019` recovery schema、hash-only code management、獨立 recovery principal、required-UV Passkey replacement、atomic session/token/logout revocation、one-view replacement codes、UI 與 workerd regression。
- [ ] 在隔離 Preview 套用 `0019`、綁定專用 recovery limiter、以 Preview-only 帳號完成 lost-device/concurrency/rollback/multi-RP logout exercise、獨立 source/security review 與 operator runbook 驗收；production 維持 `RECOVERY_MODE=disabled`，直到 owner 另行核准部署與實機 smoke。

### 9.3 Google

- 僅要求 `openid email profile`。
- 不要求 Gmail、Drive 或其他產品 scope。
- 不因登入用途要求 Google offline access。
- 不需要的 provider access/refresh token 不應長期保存。
- 若必須保存 provider token，需使用應用層加密，金鑰不得放入 D1。
- 關閉 implicit account linking；同 Email 的既有帳號只能在已驗證 session 中明確連結。

### 9.4 Passkey

- RP ID 固定為 `sso.pg72.tw`，expected origin 固定為 `https://sso.pg72.tw`。
- 不把 RP ID 放寬成 `pg72.tw`；認證主機是長期穩定邊界，縮小 RP scope 可降低其他子網域被入侵時的風險。
- 支援同步 Passkey、平台驗證器與硬體安全金鑰。
- 使用者可查看、命名與移除每一組 Passkey。
- 管理員至少登錄兩組不同復原路徑的 Passkey。
- 移除最後一組 Passkey、變更 Email、管理 client，以及建立、輪替或撤銷 recovery codes 必須 fresh authentication；recovery-code mutation 另要求同一 session 最近完成 Passkey step-up。
- 所有 client mutation 同時要求 session 建立時間在 10 分鐘內，並要求該 D1 session 的 Passkey step-up 時戳仍在 `PASSKEY_STEP_UP_MAX_AGE_SECONDS`（60-600 秒，現行 600）內；兩者缺一不可。
- Step-up 使用 `POST /api/account/passkey-step-up/challenge` 與 `/verify`。Challenge 由 Web Crypto/SimpleWebAuthn 產生、兩分鐘內有效、一次性且綁定 user + session；assertion 強制 exact origin、RP ID、credential ownership 與 user verification。成功後先以 guarded CAS 更新 credential counter，再以 D1 batch 先寫 success audit、最後寫入依賴該 exact audit event 的 session timestamp；任何 guard 失敗都不會產生有效 step-up。
- 沒有 Passkey 的帳號一律回 `PASSKEY_ENROLLMENT_REQUIRED`，包含 `bootadmin`，沒有 runtime bypass。首次 bootstrap 以既有 Google fresh session 註冊 Passkey 後再 step-up。Local recovery source 只能在使用者事先建立且仍持有未使用 recovery code 時替換 Passkey；它不是 client-management bypass，production 尚未啟用。
- 以上行為已在 local source 以真實 P-256 assertion、replay、cross-session、expiry、missing-Passkey 與 UV regression 驗證；production 尚未套用 `0014` 或部署，不能宣稱遠端 blocker 已關閉。

### 9.5 Recovery codes（local source，production disabled）

- `RECOVERY_MODE` 是獨立 runtime switch；`disabled` 時管理與 recovery endpoints 都回 404。Migration `0019` 本身不啟用功能，production 必須維持 disabled，直到隔離 Preview、獨立 review、runbook drill 與 owner 核准完成。
- 帳號中心的 `GET /api/account/recovery-codes` 只回 configured、generation、remaining、count、format 與 nullable expiry 狀態，不回 raw code。`POST /api/account/recovery-codes/rotate` 與 `DELETE /api/account/recovery-codes` 都要求 active normal session、session 建立未滿 10 分鐘、至少一組 Passkey，以及同一 D1 session 最近完成 Passkey step-up；沒有 `bootadmin`/admin bypass，restricted 但 active 的使用者仍可管理自己的 codes。所有 eligibility 與 generation/active-set snapshot 在 committing D1 batch 再驗一次。
- 每個 generation 固定產生十組 `PGID-R1` code；每組由 Web Crypto 產生 20 random bytes（160 bits），以不含易混淆字元的 32-character payload 顯示。Parser 只接受 ASCII 大小寫、空白與連字號的等價輸入；D1 全域只保存 canonical code 的 SHA-256 unpadded base64url digest。Raw codes 只在建立、輪替或成功復原時的 `no-store` response 顯示一次，不進 log/audit/Queue。現行 set 不自動到期，`expires_at` 保留為 nullable future-policy field。
- `POST /api/recovery/start` 先使用專用 per-IP `RECOVERY_RATE_LIMITER`，再執行 constant-shape hash lookup；malformed、unknown、used、revoked、expired、suspended 與並行輸家回相同泛化拒絕。Code 一旦成功開始 recovery 就永久 consumed；取消或後續失敗不會恢復它。
- 成功 start 只建立十分鐘的獨立 recovery principal。Browser 取得 host-only `__Secure-pg72_recovery` cookie，固定 `Path=/api/recovery`、`Secure`、`HttpOnly`、`SameSite=Strict`；D1 只存 token hash。它不能授權 Better Auth、account、admin、OIDC 或任何一般 endpoint，也不建立 normal session。
- Recovery Passkey challenge 兩分鐘內有效且一次性，registration 強制 exact origin/RP ID、required user verification、resident-key preferred、attestation none，並排除使用者既有 credentials。Challenge、response 與欄位長度有明確上限；credential ID 在 D1 全域唯一。
- 成功 completion 在單一 D1 batch 建立新 Passkey與 success audit、撤銷舊 recovery set、建立下一 generation 十組 hashes、撤銷所有 central sessions/access tokens/refresh tokens、清除相關 verification state，並為已造訪 RP 建立 durable logout delivery。任何核心 statement 失敗整批 rollback；Queue fan-out 只在 commit 後進行。Raw replacement codes 只回一次，recovery principal 隨舊 set cascade 移除，使用者必須用新 Passkey 走一般登入。
- 移除最後一個 social provider 除了必須保留至少一組 Passkey外，也必須在 enabled mode 下存在 active、未到期且至少一組 unused recovery code；request check 與 committing DELETE 都重驗，避免 code-consumption race。多於一個 social provider 時不增加這個額外限制。
- Local test 覆蓋 code entropy/格式/hash-only storage、rotation/revoke、fresh+step-up race、restricted/suspended state、並行 single winner、cookie scope、取消不復原、limiter failure、exact origin、required UV、challenge replay、atomic completion/rollback、Queue failure、normal Passkey re-login 與既有 RP logout outbox。完整 Preview/production acceptance 見 [`docs/runbooks/account-recovery.md`](./docs/runbooks/account-recovery.md)。

### 9.6 Telegram

- Telegram Login Widget payload 必須以 bot token 衍生的 HMAC 驗證，並拒絕過期或未來時間超出容許範圍的 payload。
- Telegram numeric user ID 只作 provider account identifier，不作 email、OIDC `sub` 或一般服務主鍵。
- Telegram 不提供 verified email，因此不論 `REGISTRATION_MODE` 是 `invite` 或 `public`，未綁定 identity 都不能建立 PGID user、account 或 session。
- Telegram 只能在 active authenticated PGID session 中明確連結；已連結且 user 仍為 active 時才可用 Telegram 登入。不得以 placeholder email、implicit linking 或 public mode 繞過 verified-email enrollment gate。
- Telegram link 使用 `INSERT OR IGNORE` 與 `(providerId, accountId)` 唯一索引原子決定 owner；insert 未改變資料時必須重讀 owner，對同一 user 回 `already_linked`，對其他 user 回 `telegram_already_linked`，且只有成功 insert 才寫入 `account.linked` success audit。

## 10. OIDC Client Contract

### 10.1 Client 類型

- Server-side Web Apps：confidential client，Authorization Code + PKCE S256。
- Browser-only / Native Apps：public client，Authorization Code + PKCE S256，無 client secret。
- Machine-to-machine：獨立 client credentials，與人類使用者 session 分離。

第一階段所有 clients 由管理員手動建立，dynamic client registration 關閉。

現行第一方 confidential RP 在 token endpoint 使用 `client_secret_post`。Better Auth `1.6.23` 對 HTTP Basic credentials 的解析與 `oauth4webapi` RFC 6749 percent-encoding 不互通；在 provider 有可追蹤 patch、protocol regression test 且 RP 完成 migration 前，不把 `client_secret_basic` 寫成現行 contract。

### 10.2 Redirect URI

- 只允許完整、精確比對的 HTTPS URI。
- Production 不允許 wildcard、HTTP 或任意 query-based callback。
- Local development callback 必須列為獨立 development client。
- Client secret 僅顯示一次，資料庫只保存 hash。
- Owner 可透過 guarded admin PATCH 更新 `name`、nullable `uri`、redirect/post-logout redirect URI、scopes、grant types、end-session 與 trust/logout metadata。Request 必須原樣帶回 GET list 的 `expectedUpdatedAt`，並將它視為 required、bounded opaque exact-version precondition，而非自行解析或重組的 timestamp；same-row 版本失配時回 409，不能 stale write-back。Client ID、public/confidential 類型、token auth method、secret、owner、PKCE/consent、response/subject type 與 disabled 狀態不可由 generic update 修改；`pgid-mail-introspect` 的 protocol/authorization 欄位另行鎖定。
- Redirect membership 變更必須在 client update 的同一 D1 batch 清除 pending authorization code 與 consent；scope/grant membership 變更還必須刪除 access token、撤銷 live refresh token。Success audit 是 batch 內唯一的 actor/session authorization snapshot，並重驗 exact row、owner 與舊版本；cleanup/update 必須依賴該 exact audit event 並再次重驗 row/owner/version，不能在各 statement 重算會變動的 session clock。並行更新、刪除或 replacement row 不得被 stale request 修改或清理。Metadata-only update 不撤銷 token。

### 10.3 Claims

標準 claims：

```text
iss sub aud exp iat auth_time nonce sid
email email_verified name picture
```

自訂 claims 必須有 namespace，且只提供必要資料。角色與群組資訊依 client 與 scope 過濾，避免把完整管理權限暴露給不需要的服務。

### 10.4 Token 與 Session 建議值

以下為初始 baseline，實作前仍需以 threat model 與 library 能力確認：

| 項目 | 建議值 |
| --- | --- |
| Authorization code | 60 秒、單次使用 |
| ID token | 5 分鐘 |
| Access token | 5 分鐘 |
| Refresh token | 預設不發；核准 `offline_access` 後 7 天並 rotation |
| SSO idle session | 7 天 |
| SSO absolute session | 30 天 |
| Fresh authentication | 5 分鐘 |
| 公開服務撤銷快取 | 最多 30 秒 |
| 管理服務撤銷快取 | 不快取或使用同請求即時檢查 |

第一方 Web App 完成 OIDC callback 後建立自己的 server-side session。Token 不得存入 `localStorage` 或可被 JavaScript 讀取的 cookie。

### 10.5 Mail introspection system client（本地已實作，未部署）

Mail Path A 對 RFC 7662 的唯一 cross-client 例外固定為：

```text
introspection client: pgid-mail-introspect
token client:         pg72-webmail
token type:           opaque access token only
required state:       live central session + email scope + active user + verified email
```

- `pgid-mail-introspect` 與 `pg72-webmail` 是 system-reserved client ID；developer 不能 claim。一般 client 仍只能 introspect 自己的 token。
- JWT、refresh token、其他 introspection-client/token-client 配對，以及缺少 live session、`email` scope、active user 或 verified email 的 token，一律回 RFC 7662 inactive；不能因來自第一方 client 而放寬。
- 未知、過期、撤銷、停用 target client、JWT 無 `kid` 或 token-controlled JOSE 驗證失敗都回 HTTP 200 `{"active":false}`。`token_type_hint` 只是優先查詢提示，hint miss 必須再查另一種 token type。JWKS corruption、重複 matching `kid`、fetch timeout 等 server/infrastructure fault 仍是 internal error，不得偽裝成一般 inactive token。
- 成功的 mail response 只允許 `active`、`client_id`、`scope`、`iss`、`exp`、`iat`、`email`、`email_verified`；不得回 `sub`、`sid` 或其他不必要 claim。Email 只供 Dovecot legacy mailbox lookup，不成為 PGID 或 Roundcube 的主鍵。
- Introspection client 使用 `client_secret_post`；Worker preflight 拒絕 Authorization header、重複 single-value credentials/token 欄位、錯誤 media type、非 POST 與超過 4 KiB 的 body。Client authentication 失敗回 HTTP 401；token 狀態不得藉由 error response 洩漏。
- `POST /api/admin/clients/provision-mail-introspector` 只允許 `clients.manage_all` actor，建立無 owner、無 redirect URI/scope，且只有 introspection-only sentinel grant（不能簽發 token）的 confidential service client；secret 只顯示一次，D1 只存 hash。Provision、rotate、disable/delete 同時要求 10 分鐘內建立的 fresh session 與該 session 最近完成的 Passkey step-up；local source 已實作，production 仍待 `0014`、部署、獨立 review 與 smoke。
- 若 service secret 疑似外洩，先停用 `pgid-mail-introspect` 使 introspection fail closed，再 rotate secret、更新受管 secret store／Dovecot 設定；停用中的 client 無法通過真正的 introspection smoke，須在維護窗口重新啟用後立即 smoke，失敗即 re-disable/rollback。不得在事故處理中把 secret 寫入 D1 明文、log、文件或聊天。

Introspection 不共用一般 auth 端點的 30/min limiter。`INTROSPECTION_IP_RATE_LIMITER` 使用 namespace `1004`、每 60 秒 1200 次的 IP bucket；`INTROSPECTION_CLIENT_RATE_LIMITER` 使用 namespace `1005`、每 60 秒 600 次的 client-class/IP bucket（`mail` 與 `other` 分開）。Binding failure 回 503、拒絕回 429。Cloudflare Workers Rate Limiting binding 的判斷是 per-location 且 permissive／eventually consistent，這些數字是濫用緩解而不是精確全域上限；不能用它取代 client authentication、token validation、D1 revocation source of truth 或上游邊界防護。

以上程式與 regression coverage 已收入 repository，但 production 尚未 deploy、system client 尚未 provision，也沒有 mail VPS cutover 的 production 驗收紀錄。

## 11. Session 與全域登出

### 11.1 Session 分層

SSO session 與應用程式 session 是兩個不同層級：

- SSO session：由 `sso.pg72.tw` 管理登入狀態、裝置與重新驗證。
- RP session：由 Copy、Link、File 等服務管理應用內狀態。
- Recovery session：migration `0019` 的十分鐘、hash-token、`/api/recovery` cookie-scoped principal，只能註冊 replacement Passkey；它不是 SSO/RP session，不能取得 consent、OIDC token 或一般 API 權限。

SSO 無法只靠刪除自己的 cookie 清除所有 RP cookie。因此所有第一方服務必須支援下列 contract。

### 11.2 RP Session Contract

現行 local source 已完成所有 user ID token 的 nonempty central `sid`、refresh
grant live-session binding、`(sid, client_id)` visit ledger、D1 durable delivery
outbox/attempt evidence、opaque delivery key、專用 Queue/DLQ consumer、Cron replayer、operator replay
API，以及 test RP 的 idempotent receiver。Production 尚未套用 `0018`、provision
專用 Queue/DLQ 或部署任何經驗收的 RP receiver，外部告警也尚未實作；因此仍
不能宣稱全域登出已在 production 完成。

- ID token 包含 `sid`。
- RP 建立本機 session 時保存 `sid` 與 `sub`。
- SSO 在授權完成時記錄 `(sid, client_id)`，用來識別該 session 存取過的服務。
- RP 提供管理員明確註冊的精確 `backchannelLogoutUri`；production 必須 HTTPS，不允許 wildcard、fragment 或任何 `@`。Development 的 HTTP loopback 必須含明確 port。
- RP 收到 logout token 後，以 `iss`、`aud`、signature/`kid`、`exp`、`iat`、`events`、`sid`、`jti` 與 no-`nonce` 驗證；token lifetime 不超過五分鐘。
- RP 依 `sid` 移除所有對應本機 sessions。
- Logout endpoint 必須把 `jti` receipt 與 session deletion 同一 transaction commit；相同 `jti` 重複送達回 `200`/`204`，不同 `sid` 的 conflicting reuse 必須拒絕。

### 11.3 撤銷流程

```text
User/Admin requests revoke
        |
        v
D1 batch commits central revocation
        |
        +--> delete central session + access/refresh tokens
        |
        +--> append success audit event
        |
        +--> snapshot one durable delivery per visited client
                          |
                          +--> dedicated Queue after commit
                          |          |
                          |          v
                          |   signed logout token
                          |          |
                          |          v
                          |   RP deletes by sid
                          |
                          +--> Cron re-enqueues due/expired leases
```

中央撤銷、audit 與 durable delivery rows 必須先原子完成，Queue 發送才可開始。即使 Queue 暫時失敗，introspection 或 gateway 檢查也必須看到 session 已失效；replayer 由 D1 row 復原送達，不得恢復中央 session/token 作補償。

### 11.4 撤銷 SLA 與故障政策

- 管理服務：要求立即撤銷，每次請求確認中央狀態，確認失敗時 fail closed。
- 公開服務：專用 Queue 主動推送，另允許最多 30 秒撤銷快取。
- Delivery 只有 HTTP `200`/`204` 成功；network/timeout、`408`、`425`、`429`、`5xx` retry，其他任何 HTTP status（包含 `201`、`3xx` 與其他 `4xx`）permanent，最多五次 bounded attempts。
- 過期 lease 由每分鐘 Cron 回收；reclaim 前先把原本的 `in_flight` attempt terminalize 為 `lease_expired`，attempt 5 則進 dead state。dead/retry row 可由具 `users.manage`、fresh session 與 Passkey step-up 的管理員人工 replay。`202` 代表 D1 reset/audit 已 commit、立即 Queue send 失敗而等待 Cron，不代表 rollback。
- Redacted 管理 API 只用 opaque `deliveryKey` 定位，不暴露內部 sequential primary key、endpoint snapshot、`sid`、`jti` 或 token。Repository 尚無外部 DLQ/dead-delivery paging；只有完成配置與演練後才能宣稱告警存在。
- SSO 暫時不可用：公開服務可依風險提供短期既有 session grace period；管理服務不得繞過驗證。

「立即撤銷」與「SSO 故障時所有服務仍完全可用」無法同時保證。以上政策優先保護管理與高敏感服務。

Preview acceptance、唯讀 migration check、triage、manual replay 與 rollback 詳見 [`docs/runbooks/global-logout.md`](./docs/runbooks/global-logout.md)。RP 實作契約另見 [`docs/api/PGID-integration.md`](./docs/api/PGID-integration.md) §5.5。

## 12. 帳號中心與管理後台

### 12.1 使用者帳號中心

- 個人資料與穩定帳號 ID。
- 已連結 Google 帳號。
- Passkey 列表、新增、命名與移除。
- 目前及其他裝置 sessions。
- 撤銷單一裝置、其他裝置或所有裝置。
- 已授權應用程式、scopes 與撤銷 consent。
- 個人登入、安全與帳號變更紀錄。
- Recovery codes 狀態、產生、重新產生與撤銷；raw codes 只在成功 response 顯示一次。此區只在 `RECOVERY_MODE=enabled` 顯示。
- 帳號刪除申請。

### 12.2 管理後台

- 使用者搜尋、`standard`/`restricted` filter、邀請、restrict/promote、停權、解除停權與刪除。
- 平台角色與 client-specific roles。
- OIDC clients、redirect URIs、scopes、backchannel logout URI。
- Session 與 token 強制撤銷。
- Signing keys 與 rotation 狀態。
- Security/audit event 查詢與匯出。
- Redacted logout delivery、retry/dead 與 manual replay evidence；外部 Queue/DLQ dashboard/paging 仍須另行配置。
- 註冊模式與 abuse controls。

### 12.3 平台角色階層

平台角色固定四級，權限對照表集中在 `worker/roles.ts`，路由只檢查 permission、不比對角色字串：

| 角色 | 說明 |
| --- | --- |
| `bootadmin` | 綁定 `BOOTSTRAP_ADMIN_EMAIL` 的 bootstrap administrator。不可被刪除、降級或停權（app 層與 D1 trigger 雙重保護），且是唯一可指派/收回 `admin` 的角色。effective role 一律以設定的 email 推導；stored role 只是持久化快照。 |
| `admin` | 管理使用者（邀請、停權、撤銷 sessions、刪除、指派 `developer`/`user`）與全部 OAuth clients。不可動 `bootadmin`、其他 `admin` 的角色與自己。 |
| `developer` | 建立並管理「自己擁有的」OAuth clients（`oauthClient.ownerUserId`）。無使用者管理權限。 |
| `user` | 一般使用者，無管理權限。 |

補充規則：

- `bootadmin` 不可被指派；它由設定推導，非授予。
- 邀請可帶角色（`user`/`developer`/`admin`），可指派範圍與直接角色變更相同。邀請既有帳號時立即套用角色（不留待日後生效的 pending grant），audit 記錄來源為 invitation。
- Restricted account 不可取得 `developer`/`admin`/`bootadmin`；admin 不能 restrict peer admin，只有 bootadmin 可依 hierarchy 將另一位 admin restrict 並 demote 至 `user`。Restrict/promote 與 suspend/reactivate 是分離的原子 audited transitions，role assignment 仍是第三個分離操作。
- OAuth client 擁有者被刪除時，client 保留但立即停用、tokens 撤銷、轉為無主（admin 管理）；`ownerUserId` 為 NULL 的既有 client 一律視為 admin 管理。
- 所有管理操作寫入 audit（actor、target、redacted metadata，不含 PII 全文）。

## 13. 資料模型

### 13.1 Auth engine tables

實際名稱以 Better Auth stable schema 為準，預期包含：

- `users`
- `accounts`
- `sessions`
- `verifications`
- `passkeys`
- `jwks`
- `oauth_clients`
- `oauth_access_tokens`
- `oauth_refresh_tokens`
- `oauth_consents`

本 repository 的實際 Better Auth `user` table 另有 PGID additional fields：`role`、`status`、`accessLevel`、初次 Terms/Privacy version 與 `legalAcceptedAt`。`accessLevel` 只接受 `standard`/`restricted`，migration `0017` 對既有 rows default/backfill `standard`。Migration `0018` 另在 `oauthClient` 加入 nullable `backchannelLogoutUri`，並把相容的 legacy metadata 值一次性 backfill 到 dedicated column。

### 13.2 PG72 application tables

- `invitations`
- `platform_roles`
- `user_platform_roles`
- `client_roles`
- `user_client_roles`
- `rp_session_client`（實際 central `sid`/client visit ledger）
- `logout_delivery`（D1 durable delivery source of truth）
- `logout_delivery_attempt`（每個 replay generation/attempt evidence）
- `logout_delivery_legacy_0018`（只保留 pre-`0018` evidence，不送達）
- `recovery_code_set`（每個 user 的 generation、nullable expiry 與 revoke state；同時最多一組 active set）
- `recovery_code`（十組全域唯一 SHA-256 hashes、ordinal 與一次性 consumption）
- `recovery_session`（獨立十分鐘 recovery principal，只存 token hash並綁定 exact consumed code/set/user）
- `recovery_passkey_challenge`（每個 recovery session 至多一組、兩分鐘的一次性 Passkey registration challenge）
- `audit_events`
- `security_events`
- `event_deliveries`
- `system_settings`

### 13.3 Audit event 最低欄位

```text
event_id
occurred_at
event_type
result
actor_user_id
actor_session_id
target_type
target_id
client_id
auth_method
ip_prefix_or_hash
country
user_agent
request_id
metadata_json
```

Audit metadata 不得包含 access token、refresh token、session token、authorization code、Passkey challenge、client secret、Google token 或 recovery code。

## 14. 必須稽核的事件

- 邀請建立、撤銷、使用與過期。
- 註冊成功、失敗與拒絕原因。
- Google 與 Passkey 登入成功/失敗。
- Passkey 新增、改名與移除。
- Session 建立、更新、撤銷與全部撤銷。
- Consent 建立與撤銷。
- OAuth client、redirect URI、scope 與 secret 變更。
- Token refresh、revocation 與異常重複使用。
- 使用者 restrict/promote、停權/復權、角色變更與刪除。
- Restricted account 嘗試 provider linking 或 developer/admin/client-management sensitive surface 的 denied event（固定 surface enum，不含 PII）。
- Recovery codes 建立、輪替、撤銷、開始使用、Passkey failure 與完成；metadata 只能包含 bounded enum/count/generation，不得包含 raw code、token、challenge、credential ID、Email 或 IP。
- Signing key 建立、啟用、停用與移除。
- Back-channel logout 發送、成功、重試與永久失敗。
- 管理員資料查詢與匯出。

## 15. 安全基線

- 所有 production 流量只允許 HTTPS。
- Cookie 使用 `Secure`、`HttpOnly`、合適的 `SameSite` 與 host-only scope。
- 不建立 `Domain=.pg72.tw` 共用 session cookie。
- OAuth Authorization Code Flow 強制 PKCE S256、`state`、`nonce` 與 issuer/audience 驗證。
- Redirect URI 完整比對，不允許 wildcard。
- ID token 與 back-channel logout JWT 使用非對稱簽章並透過 JWKS 驗證。現行
  `pg72_at_` access token 是 opaque；一般 RP 使用 UserInfo，Mail Path A 使用
  §10.5 的 scoped introspection，不得解析 access token 或用 JWKS 本地驗證。
- 支援 signing key overlap rotation，舊 key 在既有短效 token 到期後才移除。
- 所有 secret 經 Wrangler secrets/Secrets Store 管理，不寫入 repo、log 或 D1 明文。
- Recovery code、recovery-session token、refresh token、client secret 與 invitation token 只保存不可逆 hash，除非協議明確要求可還原資料。
- 管理員操作要求 fresh authentication；高風險 client mutation 另要求同一 D1 session 的 Passkey step-up。Local source 已實作 required UV、exact origin/RP ID、一次性 session/user-bound challenge、counter guard 與 timestamp/audit 寫入；production 尚未套用 `0014` 或部署，仍須獨立 review 與實機驗證。
- 管理員至少具有兩種獨立復原方式；local recovery-code source 不能取代第二組 Passkey、獨立 review、isolated Preview drill 或 owner-controlled break-glass planning。Production 尚未套 `0019` 或啟用 recovery，仍是 full Production GO gate。
- CORS 採 allowlist，不對 credentialed endpoints 使用 `*`。
- 所有 state-changing endpoints 使用 CSRF 保護或不依賴 cookie 的等效防護。
- 登入、callback、token、Passkey、邀請與管理 endpoints 具獨立 rate limits；新帳號建立另有更嚴的 per-IP `REGISTRATION_RATE_LIMITER`。
- Turnstile、版本化法律同意與 restricted account 已在 local source 實作。受限帳號的 sensitive request guard 必須重讀 D1；所有 management/developer writes 必須在 committing D1 batch 重新確認 actor session 仍 live、帳號仍為 active + standard 且 permission-relevant snapshot 未變，成功 mutation 與 audit 必須同批 commit；D1 trigger 另覆蓋 role、provider insert 與 client owner constraint。
- Abuse runbook 已以現有 redacted D1 evidence 定義 manual threshold/triage/containment/rollback；Preview/production 配置、獨立 review、實機驗證、threshold baseline、operator assignment 與外部 aggregation/alert delivery 仍未完成，皆屬 §9.2 的 public 啟用 gate。
- Error response 不洩漏帳號是否存在、token 狀態、secret 或內部 exception。
- 日誌與 telemetry 預設遮蔽 PII 與憑證。

Better Auth 曾出現 OAuth/OIDC 與 account linking 相關安全公告。因此：

- 只使用當下已修補的 stable 版本，不使用 beta/RC 作 production auth core。
- `better-auth` 與所有 `@better-auth/*` 套件必須同步更新及分別檢查 advisory。
- Lockfile 納入版本控制，CI 執行 dependency audit。
- 公開註冊前執行獨立安全審查與 OIDC conformance/security testing。
- 不假設 library default 永遠符合本專案 threat model；所有敏感 default 必須顯式設定並測試。

## 16. 備份與復原

- 使用 D1 Time Travel 作短期操作錯誤復原，但不可把它視為唯一備份。
- 每日將 identity metadata 與 audit events 加密封存至 R2。
- 定期建立 Cloudflare 帳號外的加密備份，防止單一供應商或帳號層級事故。
- 私鑰備份必須獨立加密，存取權與資料備份分離。
- 每季執行一次完整還原演練，記錄 Recovery Time 與 Recovery Point。
- 還原後需能保留原 issuer、使用者 `sub`、Passkey credential、client ID 與未過期 signing key。
- 備份檔與匯出工具不得包含明文 token 或 secret。
- Recovery backup 只能保存 hashes 與狀態，不可能還原 raw recovery codes；使用者遺失全部 codes 時不得從 D1 backup、log 或 operator tooling 取回明文。

## 17. Observability 與告警

最低監控項目：

- 登入成功率與依 provider 分類的失敗率。
- OAuth authorize/token endpoint latency 與 error rate。
- Passkey ceremony failure rate。
- D1 error、timeout 與 migration 狀態。
- Queue backlog、retry 與 Dead Letter Queue 數量。
- Back-channel logout delivery latency。
- Token refresh 重用或異常撤銷。
- 管理員登入、角色變更與大量匯出。
- Signing key 即將過期或 JWKS 不一致。
- Public registration rate-limit/denial、新 restricted-account volume、restricted sensitive denial 與管理員 restrict/promote/suspend transitions。
- Recovery rate-limit/denial、code issue/revoke、started、Passkey failure 與 completed 的 redacted volume；不得把 raw code、recovery cookie、challenge、credential ID 或 user identity送入外部告警。

告警不得直接包含完整 Email、IP、token、authorization code 或 credential ID。

本清單是目標，不代表 repository 已配置外部 dashboard、paging 或自動封鎖。Public-registration 的持久 evidence 與人工初始門檻見 [`docs/runbooks/public-registration-abuse.md`](./docs/runbooks/public-registration-abuse.md)；global logout 的 D1 evidence、Preview acceptance、manual replay 與 rollback 見 [`docs/runbooks/global-logout.md`](./docs/runbooks/global-logout.md)；recovery migration、lost-device acceptance 與 rollback 見 [`docs/runbooks/account-recovery.md`](./docs/runbooks/account-recovery.md)。在隔離 Preview 驗證門檻、指派 operator 並測試 alert delivery 前，不得把任一 runbook 寫成 operational monitoring 已完成。

Local migration `0020` 提供 fail-closed schema 與查詢索引；repository 另有 pure rule/evaluator/parser、尚未接入 Worker entry point/scheduler 的 evaluator runtime-status/lease/bootstrap 與 alert state/incident/outbox CAS repositories、只涵蓋十項 `audit_event` 規則的 bounded source repository、bounded OAuth-report source repository、bounded global fan-out-gap source repository、bounded logout-delivery source repository、audit-archive crypto contract 與 schema-only `0021` ledger。Fan-out source 只讀 audit/marker gap，不提供 durable general delivery；logout source 只讀 durable D1 delivery/attempt evidence，不改變 delivery runtime。其餘 Queue source、observability Cron、dedicated alert/archive Queue/DLQ、Email/admin delivery、same-run proof，以及 R2 archive writer/restore/external backup 仍未實作，因此 observability 狀態仍是 `source_present_unverified`，`encrypted_r2_archive` 仍是 `dependency_missing`。詳細邊界見 [`docs/runbooks/alert-observability.md`](./docs/runbooks/alert-observability.md) 與 [`docs/runbooks/audit-archive.md`](./docs/runbooks/audit-archive.md)。

## 18. Service Integration Patterns

### 18.1 原生 OIDC

適用於可修改的 Copy、Link 及其他第一方服務。

- App 導向 PGID authorize endpoint。
- Backend 交換 authorization code。
- 驗證 ID token signature、`iss`、`aud`、`exp`、`nonce`。
- 以 `sub` 對應本機帳號。
- 建立 server-side session，保存中央 `sid`。
- 實作 back-channel logout endpoint。
- App logout 頁面要清楚區分「只登出此服務」與「登出所有服務」。

### 18.2 Gateway / Proxy Auth

適用於不能原生支援 OIDC 的服務。

- Gateway 本身是 OIDC client。
- Gateway session 綁定 `sub`、`sid`、client 與 expiry。
- Gateway 只注入最小 identity headers。
- Upstream 必須只信任 gateway 網段/連線，並拒絕外部同名 headers。
- 使用者停權或 session 撤銷後，下一個請求不得繼續通過。

### 18.3 第一方服務 migration blockers

#### Copy

- Production 已切換：NextAuth 改為 PGID OIDC confidential client + PKCE + consent，Copy 不再直接使用 Google client secret；目前 client auth 為 `client_secret_post`。
- 六位數 code 依需求保留為獨立訪客帳號，不與 PGID 用戶、Email 或 `sub` 合併；代碼使用 Web Crypto 產生並有 D1 rate limit 與 `auth_version` session 失效機制。
- `users.id` 已成為內部 ownership key，SSO 帳號以 issuer `sub` 綁定，Email 不參與授權。
- Auth.js JWT 只保存 opaque vault session ID；access/refresh token 以獨立 key 做 AES-GCM 加密後存 D1。
- Refresh 使用 `active -> refreshing -> active` 與 lease/generation CAS；timeout、5xx、write-back unknown 或 abandoned refresh 不重用舊 token，只允許 terminal reauthentication。
- 主動登出先撤銷 server-side vault row，成功後才清瀏覽器 cookie。
- 既有部署紀錄顯示本機登出修復已上線，仍待 owner 實機確認；PGID local source 已有 central `sid`/delivery，但 Copy receiver、`0018`/Queue rollout 與 multi-RP 實機驗收尚未完成，因此不代表完整 Production GO。

#### Link

- Production 已切換至 PGID；已移除 Worker 內手寫 Google OAuth，改用 `oauth4webapi` confidential client、`client_secret_post`、Authorization Code、PKCE S256、state、nonce、ID token 與 UserInfo 驗證。
- D1 session 以穩定 `sso_subject` 解析使用者；verified email 只供既有 local user 一次性綁定。舊 `owner_email` 暫保留為綁定後不再隨 UserInfo 改變的 local ownership key。
- Admin bootstrap 以 singleton D1 record 關閉 email bootstrap，production error 不回傳原始 exception。
- 所有 cookie-authenticated mutation 強制 exact Origin，短網址 target 僅接受 HTTP(S)。
- Callback：`/api/auth/callback`；migration：`migration-003-pg72-oidc.sql`。PGID local source 已有 central `sid`/delivery，但 Link receiver、`0018`/Queue rollout 與實機驗收尚未完成，因此不代表完整 Production GO。

#### Status / XUGOU

- 已移除瀏覽器 `localStorage` Bearer JWT，改用 D1 hashed opaque session + `HttpOnly` host-only cookie。
- 已加入 `oauth4webapi` PKCE/state/nonce/replay 驗證、verified-email legacy binding 與本機 role gate；帳密登入、註冊及 password update surface 回傳 retired response。
- Agent register/report 保持獨立；registration token 改用 `AGENT_TOKEN_SIGNING_KEY` HMAC-SHA-256，並修正 Agent GET/PUT/DELETE owner/admin IDOR。
- CORS 與 unsafe mutation 只允許精確 `APP_BASE_URL`；runtime 與 dev dependency audit 目前為 0 known vulnerabilities。
- Callback：`/api/auth/oidc/callback`；migration：`backend/drizzle/0005_lovely_vargas.sql`。現有本機 session 最長 12 小時；PGID delivery local source 已完成，但 Status receiver 與 Preview rollout 尚未完成，中央 consent revoke 仍不會即時清除本機 session。

#### Upload

- 已移除 `Cf-Access-Jwt-Assertion` 與 `DEV_MODE` auth bypass；Admin 改為 Authlib confidential OIDC client。
- Admin 使用 immutable `sub` allowlist、角色 claim、SQLite hashed opaque session、Fernet token encryption、Origin + synchronizer CSRF；logout 先刪本機 session，再 best-effort revocation 與 state-correlated RP logout。
- 公開 16 字 upload code、`X-Session-Token` 與 chunk streaming 保持獨立，既有四張 upload tables 未修改。
- Callback：`/admin/auth/callback`；post logout：`/admin/logged-out`；migration：`migrations/0001_admin_oidc.sql`。
- 本機 11 tests、compile、JS syntax、dependency compatibility 與 pip audit 通過；尚待 VPS Preview 與實際反向代理驗證。

### 18.4 File Browser

目前原始碼已確認有 proxy auth：

- `auth/proxy.go` 讀取設定的 username header。
- 使用者不存在時會建立本機 File Browser user。
- 新使用者預設不具 admin 或 command execution 權限。
- 官方文件明確指出 proxy header 會被盲目信任。

初步建議：使用自行打包的上游 stable release，外接 gateway + proxy auth，不直接修改上游 auth core。Gateway 注入的 username 使用由 `sub` 派生的穩定值。File Browser origin 必須封閉，且 gateway 必須覆寫而不是保留用戶端 header。

### 18.5 Webmail / Roundcube

目前提供的是 Roundcube `1.8-git` snapshot，上游 README 明確表示不是 stable release，不可直接作 production package。正式環境必須選定上游 stable release、鎖定 Composer dependencies 與 image digest 後自行打包。

此版本原始碼已具備 Generic OAuth/OIDC discovery、PKCE S256、JWKS 驗證、OIDC logout 與 back-channel logout endpoint，因此 Web UI 優先走 Roundcube 原生 OIDC 設定，不需要 Cloudflare Access，也不優先 fork PHP auth core。

Webmail 仍須分成兩個問題：

- Web UI 以 PGID OIDC 登入。
- IMAP/SMTP server 是否支援 OAuth2/OIDC，或仍需 app password。

在取得實際 IMAP/SMTP server 類型與設定前，不承諾瀏覽器 SSO 能完全取代郵件帳密。若 mail backend 不支援 `XOAUTH2`/`OAUTHBEARER`，需明確設計短效 mail credential bridge 或保留獨立 app password，不能把 SSO access token 當一般密碼轉送。

目前選定的 Mail Path A 使用 Dovecot introspection + XOAUTH2。§10.5 的固定 service-client／target-client 例外已在 repository source 實作及測試；只有具 live session、`email` scope 與 active verified user 的 `pg72-webmail` opaque access token 才會回 verified email，且該 email 只供 Dovecot 對應既有 mailbox。它尚未部署、provision 或經 production 驗證；mail VPS 設定、service-secret 注入、disable/rotate 演練與完整 rollback/驗收仍待 owner 維護窗口。

## 19. 測試與驗收

### 19.1 Protocol tests

- OIDC discovery 與 JWKS 正確且可快取。
- Authorization Code + PKCE 正常，plain/no-PKCE 被拒絕。
- 錯誤 issuer、audience、nonce、state、redirect URI 被拒絕。
- Authorization code 無法重複兌換。
- Refresh token rotation 與重用偵測正確。
- Token revocation 與 introspection 狀態一致。
- Mail delegated introspection 覆蓋 fixed client pair、live-session/email/verified-user gate、JWT/refresh/其他 pair 拒絕、`token_type_hint` fallback、JOSE/kid failure、secret disable/rotate、rate-limit failure 與最小 response allowlist。
- Signing key rotation 期間新舊有效 token 均符合預期。

### 19.2 Authentication tests

- Google 首次登入、既有登入、取消與錯誤 callback。
- Passkey 註冊、登入、移除、重複 credential 與錯誤 challenge。
- 邀請不存在、已用、過期、Email 不符與競態條件。
- 使用者停權後無法登入，既有 session 全部失效。
- Public user persistent restricted default；invited/bootstrap/existing user standard default/backfill。
- Restricted user basic account/OIDC success，provider linking、role elevation與 developer/admin/client management fail closed；restrict/promote/suspend hierarchy、session/token revoke、D1 audit atomicity 與 stale-snapshot race/replay。
- Recovery management 與 lost-device flow：hash-only storage、fresh/step-up guards、single-consume race、generic denial、scoped recovery principal、exact origin/RP ID/UV、challenge replay、full-batch rollback、session/token/logout revocation、replacement-code one-view response 與 recovered Passkey normal sign-in。

### 19.3 Global logout tests

- 撤銷單一裝置只影響對應 `sid`。
- 撤銷所有裝置使所有中央 sessions 與 refresh tokens 失效。
- Access-token trigger 只為 live user session 記錄實際 client visit；Client Credentials 不可寫入 ledger。
- 中央撤銷、token/session deletion、audit 與所有 visited-client durable rows 原子 commit；self-delete 另把 actor/session snapshot、owned-client shutdown 與 account/user deletion 放在同一批，強制 outbox failure 必須整批 rollback，且不能清 cookie 或送 Queue。
- 所有已存取 clients 都收到 logout event；partial Queue send failure 不遺失其他 D1 work。
- Queue 重複投遞與相同 `jti` receiver replay 不造成錯誤；相同 `jti`/不同 `sid` fail closed。
- Claim 必須在 HTTP 前 commit `in_flight` evidence；HTTP/result persist crash 保留同一 `jti`，expired lease terminalize 前一次 evidence 後才 reclaim，attempt 5 crash 進 dead state，並行 Queue duplicate 只能有一個 claim。
- `200`/`204` 成功；timeout/`408`/`425`/`429`/`5xx` bounded retry；其他 status 或 exhausted attempts 進 dead state。
- Manual replay 要求 permission/fresh/Passkey step-up、使用 opaque `deliveryKey`，且 list response 不暴露 sequential ID、endpoint、`sid`、`jti` 或 token。
- 管理服務在 SSO/D1 無法確認時 fail closed。

### 19.4 Security tests

- Cookie、CSRF、CORS、open redirect、header spoofing 與 session fixation。
- OAuth mix-up、authorization code interception、redirect URI manipulation。
- Account linking 與相同 Email takeover scenarios。
- Rate limit、Turnstile bypass 與帳號列舉。
- 管理權限 escalation 與 audit tampering。
- `security/accepted-advisories.json` 與即時 dependency audit 精確比對 package/version/severity/range；stale、changed、expired、unrecorded advisory 皆 fail，High/Critical 不可 waiver。
- Required checksum-pinned Gitleaks history、captured Secretlint，加上不受 gitignore 影響的 tracked/untracked/ignored-sensitive-path bounded scanner；JavaScript/TypeScript 使用 pinned compiler AST 與 depth/segment/length-bounded evaluator 處理 literal、static template、binary `+`、parentheses/assertion wrapper，再 normalize declaration/property key；line/dotenv parser 另支援 `export`/`const`/`let`/`var`。UTF-8、UTF-16LE/BE、NUL-interleaved printable strings 共用 known token/private-key/assignment/high-entropy family。Source fixture/generated metadata 只接受 exact path/key/value 或 digest；generated required-config fallback 必須保留三個 exact digest、literal form、occurrence count 與 AST context。deterministic production Wrangler entry 先比對 code-owned whole-file SHA-256，故任一 replace/remove/decoy/duplicate/concat/template 或其他 byte 變更都在既有 AST/secret scan 前 fail；runtime/dependency/bundler/build-chain integration 後只能在人工 review 且兩次 clean build/dry-run bytes 一致後明確更新 digest，policy 與產物不可自動放寬。production artifact 另檢查 private-path/source-map/unexpected-file/symlink/size；diagnostic path 先 normalize，sensitive/secret-bearing/absolute-outside/control-character path 只輸出短 SHA-256 identifier。
- `ci.yml`、`dast-preview.yml` checkout 後第一個 run step 是 dependency-free early identity checker；它在 authorization/install/其他 repository script 前固定 exact workflow file set/raw LF bytes、四個 manifests/完整 scripts maps、pnpm workspace lifecycle/build policy、frozen lockfile 與 exact patch directory/file raw identity，並拒絕 workspace pnpmfile 與各 package root `.npmrc`、`binding.gyp`、pre-existing `node_modules`。CRLF 或任何 action `uses/with`、checkout input、job/step control、run/env、upload path/retention/hidden/comment 變更都 fail；GitHub Actions immutable SHA/least permissions/concurrency/retention、code-owned workflow/job/step exact run string map、完整 scripts-object digest、reachable package-script graph（含 implicit pre/post 與 install lifecycle），以及 exact environment key/value/expression scope仍作第二層。policy 不可新增 command/local-script/leaf allowance；release artifact upload 固定為 `.artifacts/release`、missing=error、hidden=false、retention=7。`CLOUDFLARE_*`、legacy `CF_*`、`WRANGLER_*` 不可由 policy 放行。另含 Preview actor/ref guard，以及 Wrangler JSON Schema 與 source/generated D1/Queue/DLQ/Rate Limit/route/assets typed target exact contract。
- Pinned pnpm 11.5.0 會在一般 dependency 前處理 `configDependencies` 並自動載入 plugin pnpmfile；目前 exact `pnpm-workspace.yaml` 未配置此欄位。它也支援 `package.json5`／`package.yaml` fallback，但各 package 的 exact regular `package.json` 會先被選取；default pnpmfile 僅 `.pnpmfile.mjs` 與 legacy `.pnpmfile.cjs`，不含 `.pnpmfile.js`。Lifecycle runner 在 package root 有 `binding.gyp` 且無 explicit `preinstall`／`install` 時會合成 `node-gyp rebuild`，並會探測 `<project node_modules>/.hooks/<stage>`；兩者分別由 `binding.gyp` 與 pre-existing `node_modules` absence contract 阻擋。相鄰 `server.js` default 只適用 explicit `start`，release workflow 不會呼叫。Early checker 執行後才產生的 `node_modules` state、user/global config/global pnpmfile、CLI/runner env、store、registry bytes 與 Node/pnpm binary 仍屬 trusted clean-runner/network boundary，不能以 local pass 宣稱外部供應鏈未被破壞。
- Worker request abort、isolate reuse、併發初始化與 hanging promise regression。
- 使用 `@cloudflare/vitest-pool-workers` 在 workerd 環境測 D1、Queue、cookies 與 bindings，不只在 Node.js mock 測試。
- Local credential-free DAST 僅接受 canonical literal `http://127.0.0.1:5173`/`:5174`，manual redirect、禁止 Host override，並覆蓋 health/readiness/discovery/JWKS、authorize/token/userinfo/introspection/revocation/logout/admin errors、resource rejection、headers/CSRF 與 test RP；repository Preview origin 尚未核定而 fail closed，isolated Preview 的 authenticated login/consent/admin/gateway/logout 完整 DAST 仍是未完成 gate。
- SAST/secret scan/dependency scan 無未處理的 Critical 或 High finding；Medium 必須有書面接受期限與補救措施。

### 19.5 Local continuity and bounded drills

- `pnpm public-readiness:continuity:local` 只從 exact clean Git commit、只在
  policy-owned `http://127.0.0.1:5183` 建立 fresh source/restore D1，驗證完整
  ordered migration ledger（逐筆 source/D1 比對及 count/head/digest）、
  schema/row-count/D1 `quick_check`/FK 等價、synthetic consent/session/Passkey、
  discovery issuer、JWK decrypt/overlap/retirement，並刪除所有 ephemeral
  SQL、secret 與 state。
- `pnpm public-readiness:drills:local` 只在 policy-owned
  `http://127.0.0.1:5185` 以固定 96 requests、concurrency 4、12 rps、10 秒
  hard deadline 跑 workerd/global-logout regression；live profile 固定為六個
  ordered scenario、每項 16 requests，report 必須精確符合 ID、count、status、
  latency ordering 與 throughput contract；不可接受 caller target/budget。
- 兩者都必須拒絕 Cloudflare credentials、remote/Preview/production target，
  也必須拒絕 dirty/untracked/unavailable Git source，只寫 mode-`0600`
  allowlisted schema-v2 aggregate report。Dependency 的 exact source content
  與同輪 execution proof 必須同時成立才是 `verified`；Global Logout 與
  Recovery proof 另在執行前、執行後及 promotion 時重算完整 tracked
  `apps/sso` path/bytes 加 root manifest/lock/workspace/patch inputs，任何
  runtime、test、config 或 dependency input 漂移都使 opaque proof 失效；cleanup failure、local
  invariant failure或 recovery `0019`／observability `0020`／encrypted R2／
  release automation 未 verified 皆 nonzero。
- Synthetic local pass 只證明 source-local contract；不取代 Preview D1
  restore、live Queue/DLQ/R2、external alert、production smoke、獨立 review
  或 owner GO。

## 20. 導入階段

### Phase 0：GO/NO-GO prototype 與 threat model

- 確認本文件與安全預設，建立 repo、CI 與隔離的 preview environment。
- Exact pin Better Auth stable core/plugins，建立最小 Worker + D1 + test RP。
- 驗證 Google、Passkey-in-authorize、PKCE、JWKS、replay、revocation 與 request-abort regression。
- 建立 D1 migrations、secrets、Queue、DLQ 與 backup prototype。
- 建立 threat model、資料保留政策與 VPS fallback decision record。
- Phase 0 未通過不得進入完整 UI、admin 或 production app migration。

### Phase 1：Friends Beta SSO Core

- Google、Passkey、邀請制 SSO core 已部署；可選社群 providers 未設定時保持關閉。
- OIDC Provider、JWKS、client 管理、帳號中心、sessions 與基礎 audit 已部署。
- Recovery codes 已在 local source 完成且預設關閉；`0019` Preview/production rollout、獨立 review、lost-device/rollback drill、完整 audit 與 key rotation/restore drill 仍未完成。

### Phase 2：第一方應用整合

- Copy 與 Link 已切換 production traffic 至 PGID；Copy 六位數訪客碼保持獨立。
- Email 只用於一次性 legacy binding，日常 authentication 已改用 SSO `sub`。
- 這是已部署的 invite beta，不是完整 Production GO；ID-token `sid`、visited-client ledger、durable back-channel delivery 與 test receiver 已在 local source 完成，仍待 `0018`/Queue/DLQ Preview rollout、各 production RP receiver、外部告警、rollback drill 及單一/全域登出實機驗收。

### Phase 3：Legacy 與管理服務

- Status 與 Upload 的程式整合及本機安全測試完成；browser、agent、upload capability 已分離，待各自 Preview 實機 flow。
- 從上游 stable release 自行打包 File Browser 與 Roundcube，不直接部署 development snapshot。
- 設定 File Browser proxy auth 與 Roundcube Generic OIDC。
- Mail Path A 的窄 scope introspection prerequisite 已在 repository source 完成；仍待 owner 執行 deploy、system-client provisioning、Dovecot/VPS 設定、事故 rollback 與實機驗收。
- 建立 auth gateway、origin lockdown 與管理服務 fail-closed policy。

### Phase 4：公開註冊 gate

`REGISTRATION_MODE = public` 的程式路徑已具備 verified-email 強制（含未綁定 Telegram 不可建帳）、per-IP 註冊限流、suspended/deleted 管制、audit、Turnstile-backed 一次性 intent、版本化法律同意紀錄、persistent restricted access 與 manual abuse-response runbook，但 production 仍維持 `invite`。切換前必須完成 §9.2 gate：

- 核准實際 Terms/Privacy versions，部署、配置、獨立 review 並 smoke-test local Turnstile/legal/restricted slice；在隔離 Preview 驗證 threshold，指定 operator 並測試外部 alert delivery。
- 獨立安全審查、DAST、負載測試、備份還原與事故演練。
- 所有 high/critical findings 修正後，經 owner 明確核准與部署，才可宣稱公開註冊已啟用。

## 21. Repository 目錄結構

```text
.
├── README.md
├── SECURITY.md
├── codex.md
├── apps/
│   ├── sso/                  # PGID Worker, frontend, tests, D1 migrations
│   └── test-rp/              # Independent OIDC protocol RP
├── docs/                     # Public references and local operator runbooks
├── wiki/                     # GitBook-compatible user/developer guides
└── patches/                  # Audited exact-version dependency patches
```

## 22. 待確認項目與目前建議

| 項目 | 建議預設 | 狀態 |
| --- | --- | --- |
| 產品顯示名稱 | PGID | 已確認 |
| 公開服務撤銷 SLA | 30 秒內 | 待確認 |
| 管理服務撤銷 SLA | 立即，fail closed | 待確認 |
| Audit retention | 365 天 | 待確認 |
| 管理員復原 | 兩組 Passkey + recovery codes；local source complete，production disabled | Preview / drill 待完成 |
| Dynamic client registration | 關閉 | 建議固定 |
| Public registration | 現行 `invite`；§9.2 gate 通過並經 owner 核准部署後才開啟 | 已確認 |
| Better Auth runtime | 目前 `1.6.23` exact pin；安裝前重新查 stable/advisories，不使用 beta/RC | 建議固定 |
| Passkey RP ID | `sso.pg72.tw` | 建議固定 |
| Cloudflare Access | 不使用 | 已確認 |
| 日常登入方式 | Google + Passkey | 已確認 |

## 23. 參考資料

- Better Auth OAuth 2.1 Provider: <https://better-auth.com/docs/plugins/oauth-provider/>
- Better Auth Passkey: <https://better-auth.com/docs/plugins/passkey/>
- Better Auth Session Management: <https://better-auth.com/docs/concepts/session-management/>
- Better Auth Google Provider: <https://better-auth.com/docs/authentication/google/>
- Better Auth D1 Support: <https://better-auth.com/blog/1-5>
- Better Auth Security Update, June 2026: <https://better-auth.com/blog/security-update-june-2026>
- Better Auth issue #8081, Passkey in OAuth Provider flow: <https://github.com/better-auth/better-auth/issues/8081>
- Better Auth issue #10315, aborted request / Worker isolate hang: <https://github.com/better-auth/better-auth/issues/10315>
- Better Auth issue #4203, secondary storage session TTL: <https://github.com/better-auth/better-auth/issues/4203>
- Cloudflare Workers Best Practices: <https://developers.cloudflare.com/workers/best-practices/workers-best-practices/>
- Cloudflare Workers Rate Limiting binding: <https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/>
- Cloudflare Workers Vitest integration: <https://developers.cloudflare.com/workers/testing/vitest-integration/>
- Cloudflare Queues Delivery Guarantees: <https://developers.cloudflare.com/queues/reference/delivery-guarantees/>
- Cloudflare D1 Time Travel: <https://developers.cloudflare.com/d1/reference/time-travel/>
- OpenID Connect Back-Channel Logout 1.0: <https://openid.net/specs/openid-connect-backchannel-1_0.html>
