# PGID SSO 架構規格

> 狀態：Canonical Architecture Baseline
> 最後更新：2026-07-17
> 服務名稱：PGID
> Issuer：`https://sso.pg72.tw`

## 0. Phase 0 實作狀態

截至 2026-07-17，repository source 包含 SSO Worker、React 帳號中心、D1 migrations `0001`–`0016`、Google/Passkey、可選社群登入、OAuth 2.1 Provider、四級角色、邀請/停權/audit/client 管理、ID-token central `sid` contract、Mail Path A introspection prerequisite、Passkey client-mutation step-up、Telegram verified-email enrollment boundary、全域 provider-identity 唯一 ownership、Turnstile-backed public-registration intent 與版本化法律同意紀錄，以及使用 `oauth4webapi` 的獨立 test RP。每個 release candidate 都必須重跑本 repository 的 typecheck、workerd suite、production build 與 test RP protocol gate；本地通過不得寫成遠端已部署。

`0013_confidential_client_secret_post.sql` 將既有 confidential client metadata 正規化為 `client_secret_post`；它不旋轉 secret、不改 grant/token。`0014_passkey_step_up.sql` 新增 session step-up timestamp 與短效 challenge table。兩者都不代表 production 已套用；現有 deployment record 仍只確認 production D1 至 `0012`，必須由 owner 在維護窗口依序確認與執行。

`0015_account_provider_identity_unique.sql` 以 `(providerId, accountId)` 全域唯一索引保證每個外部 provider identity 只有一個 PGID owner。套用前必須執行下列唯讀 duplicate preflight；若有任何結果就停止，不得由 migration 自動挑選或刪除 owner。依賴此 invariant 的 Worker 不得早於 `0015` 部署。

`0016_public_registration_intent.sql` 新增短效、一次性 public-registration intent、user 初次法律同意欄位與不可變 history。新增欄位已納入 Better Auth user schema，因此任何含此變更的 Worker 都必須在部署前先套用 `0016`；migration 可在 `invite` 模式下先套用，且本身不會開啟公開註冊。

### 0.1 Provider Identity Migration Preflight

在 owner-controlled maintenance window 內、套用 `0015` 之前，對 production D1 執行：

```sql
SELECT providerId, accountId, COUNT(*) AS copies
FROM account
GROUP BY providerId, accountId
HAVING COUNT(*) > 1;
```

必須回傳零列。若有任何 duplicate，停止 rollout，獨立審查受影響的使用者與 audit evidence；不得自動刪除、重新指派或合併 identity owner。之後先建立 private backup / Time Travel checkpoint，於隔離 Preview 驗證後才依序套用 `0013`、`0014`、`0015`、`0016`。

既有公開部署紀錄顯示 `pg72-id` 已部署至 `https://sso.pg72.tw`，production D1 已套用至 `0012`，Copy 與 Link 也已切換 production traffic 至 PGID。這些紀錄建立了「已部署 invite beta」現況，但仍不是完整 Production GO：visited-client ledger、back-channel logout、DLQ 告警、完整復原演練與其他 §9.2 gate 尚未完成。任何 maintenance operation 前都必須由授權 operator 重新驗證實際遠端版本與 migration 狀態。

Preview 必須使用獨立 Cloudflare account、D1、queue、secret、domain、Google callback 與 Rate Limiting namespace，不得以 production D1 或 production secret 代替 Preview。

SSO 的 Cloudflare Vite build 包含 post-build cleanup，production/preview artifact 不保留 plugin 為 `vite preview` 複製的 `.dev.vars*`。

Production `REGISTRATION_MODE` 目前仍是 `invite`。`public` 程式路徑與 workerd regression tests 已備妥：所有新帳號都必須通過 verified-email enrollment gate，Google 首次登入要求 verified email，Telegram 因不提供 email 而只能登入已明確連結的既有帳號；邀請功能保留，新帳號建立使用獨立 per-IP `REGISTRATION_RATE_LIMITER`，suspended/deleted 使用者仍由 session 建立檢查擋下。Local source 另要求 exact-hostname/action Turnstile 驗證與版本化 Terms/Privacy 明確同意，並以一次性 intent 將接受紀錄帶入 OAuth 建帳。完整安全 gate 尚未完成，未完成項目列於 §9.2；只有 owner 明確核准並部署設定變更後才算開啟公開註冊。

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
| `copy.pg72.tw` | 第一方 | Next.js / NextAuth、6 位數訪客碼、D1 | PGID OIDC client；訪客碼保持獨立 | Production live；登出實機確認、中央 `sid`/back-channel logout 待完成 |
| `link.pg72.tw` | 第一方 | Cloudflare Pages / D1，具有 user/admin | BFF OIDC client，保留應用內角色 | Production live；中央 `sid`/back-channel logout 待完成 |
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

目前 `@better-auth/oauth-provider@1.6.23` 另以 tracked exact-version package patch `patches/@better-auth__oauth-provider@1.6.23.patch` 固定 Mail Path A introspection 行為。Patch 預設仍是 same-client introspection，只提供 opt-in hook 讓 PGID 實作 §10.5 的單一 cross-client 例外；同時修正 `APIError.status` 的 RFC 7662 inactive 判斷、把 `token_type_hint` 維持為 hint 而非限制 lookup，以及分類 token-controlled JOSE/kid failure。這不是可泛用的跨 client 授權開關。

升級 Better Auth 時不得把 patch 機械套到其他版本，也不得用 `allowUnusedPatches` 隱藏版本不符。只有 pinned stable provider 已提供經審核的等價行為、乾淨 frozen install 能在移除 patch 後通過，且完整 introspection/protocol regression suite 全數通過，才可移除或重作這個 patch；core 與所有 plugins 仍須維持 exact pin 並一起評估 migration/advisory。

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

Queue 是 at-least-once delivery。所有 consumer 必須以 `event_id` 或 logout token 的 `jti` 去重，並支援重試。無法成功送達的事件進入 Dead Letter Queue 並產生管理告警。

Queue 不作為撤銷或 audit 真實來源；D1 中的 session/token 狀態與 `audit_event` 才是 source of truth。需要 audit 的 client mutation 必須將狀態變更與 D1 audit insert 放在同一個 batch，成功後才回應；Queue 只在 D1 commit 後作 best-effort security-event fan-out。Queue 在接受事件前失敗可能漏掉 fan-out，目前只有 redacted log，尚無 durable outbox/replayer 或告警補送；補齊這項是 full Production GO 前必須決定的債務。Queue 失敗不得讓已提交的 D1 狀態看似回滾，也不得把未入 D1 的事件視為已稽核。

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
invited -> active -> suspended -> deleted
              |           |
              +-----------+
                admin action
```

- `invited`：已有邀請但尚未完成初次登入。
- `active`：可正常登入與授權。
- `suspended`：所有 session/token 撤銷，不可重新登入。
- `deleted`：完成保留期後移除或匿名化個資，稽核事件保留必要識別摘要。

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
- 有未消耗邀請的 Email 完成首次登入時，帳號取得邀請指定的角色（例如 `admin`），邀請立即標記為已消耗。
- 邀請功能在未來 public 模式仍保留，與公開註冊不衝突。

### 9.2 公開註冊路徑與啟用 gate（未部署）

已實作且有 regression coverage 的 `REGISTRATION_MODE=public` 行為：

- 第一次 Google 登入直接建立帳號；Google 必須回傳已驗證 Email（`email_verified`），否則拒絕（`EMAIL_NOT_VERIFIED`），兩種模式皆強制。
- Telegram Login Widget 不提供 Email，因此未綁定的 Telegram identity 在 invite/public 兩種模式都先消耗 registration limiter、寫入不含 Telegram ID 或其他 PII 的 `registration.denied`，再以相同泛化錯誤拒絕；不得建立 placeholder-email user 或 session。既有 Telegram identity 只能在 authenticated PGID session 中明確連結，連結後才可用 Telegram 登入。
- Passkey 註冊仍需先有帳號與已登入 session；公開註冊不開放無帳號的 Passkey 註冊。
- 前端把登入既有帳號與建立新帳號分開；只有新帳號路徑顯示目前 Terms/Privacy 的明確勾選與 Turnstile。Passkey 與 Telegram 不作 public 建帳入口。
- `POST /api/registration/intent` 只接受 exact same-origin JSON，要求 client 回傳 Worker 公布的目前 Terms/Privacy version 並皆明確同意，再以 Turnstile Siteverify 驗證 `success`、exact issuer hostname 與固定 action `pgid_public_registration`；challenge 服務不可用時 fail closed。
- 驗證成功後只核發 10 分鐘、Web Crypto 產生、D1 一次性消耗的 opaque intent ID。瀏覽器僅透過 Better Auth 保護的 OAuth state 帶入 ID，不保存或傳送 Turnstile secret；callback 建立 user 前必須原子消耗 intent，過期、重放、版本不符或缺少皆回泛化拒絕。
- `0016` 將 server-side intent issuance time、Terms version 與 Privacy version 隨 user 建立寫入；D1 trigger 強制三欄全有或全無、禁止變更初次同意，並在同一 transaction 建立 `legal_acceptance` history。帳號存在期間直接 UPDATE/DELETE history 會被拒絕；依 Privacy Policy 刪除 parent account 時則由 FK cascade 一併移除其 account-scoped history。Invite-mode user 的三欄保持 `NULL`。
- 新帳號建立有獨立、比登入更嚴的 per-IP rate limit（Workers Rate Limiting binding `REGISTRATION_RATE_LIMITER`，5 次/60 秒；登入面為 `AUTH_RATE_LIMITER` 30 次/60 秒）。限流檢查在任何 denial audit 寫入與邀請查詢之前消耗額度，避免被濫刷。
- 觸發限流寫入 `registration.rate_limited` audit；所有 registration 拒絕訊息不洩漏帳號是否存在。
- `suspended` 使用者不因公開模式繞過管制：session 建立前一律檢查中央 `user.status`，非 `active`（含已刪除、user row 不存在）一律拒絕。
- 已刪除帳號重新註冊會取得全新的 `sub`；RP 視其為新使用者，不會繼承舊資料。

切換 production 至 public 前尚未完成的安全 gate：

- [ ] 將 local source 已實作的 Turnstile registration challenge 部署至隔離 Preview，配置 hostname-scoped site/secret key，完成獨立 review、bypass/失效/服務中斷測試與 production smoke；production secret 僅可存 Wrangler secrets / Secrets Store。
- [ ] 由 owner 核准實際 Terms/Privacy 內容與 version identifiers，於隔離 Preview 驗證 `0016` 同意紀錄、rollback 與資料匯出，再部署並 smoke-test；local schema/UI/regression 通過不等同法務核准或 production 啟用。
- [ ] 濫用偵測與封鎖流程（abuse response runbook）。
- [ ] 獨立安全審查與 OIDC conformance/security testing。
- [ ] DAST 覆蓋 auth、OIDC、admin、gateway 與 logout endpoints。
- [ ] SAST、secret scan、IaC/config scan 自動化 gate。
- [ ] 負載測試、備份還原演練、key rotation 與 Queue retry/DLQ 演練。
- [ ] 新帳號限制狀態（限縮敏感功能）機制。
- [ ] Back-channel logout 全面上線與 DLQ 告警。
- [ ] 將 local source 已實作的 Passkey step-up 與 migration `0014` 部署至 production，完成獨立 review 與實機 smoke；10 分鐘 session-age freshness 仍是額外條件，不能替代重新驗證。

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
- 移除最後一組 Passkey、變更 Email 與管理 client 必須 fresh authentication；未來建立 recovery codes 時也必須套用同一要求。
- 所有 client mutation 同時要求 session 建立時間在 10 分鐘內，並要求該 D1 session 的 Passkey step-up 時戳仍在 `PASSKEY_STEP_UP_MAX_AGE_SECONDS`（60-600 秒，現行 600）內；兩者缺一不可。
- Step-up 使用 `POST /api/account/passkey-step-up/challenge` 與 `/verify`。Challenge 由 Web Crypto/SimpleWebAuthn 產生、兩分鐘內有效、一次性且綁定 user + session；assertion 強制 exact origin、RP ID、credential ownership 與 user verification。成功後先以 guarded CAS 更新 credential counter，再以 D1 batch 先寫 success audit、最後寫入依賴該 exact audit event 的 session timestamp；任何 guard 失敗都不會產生有效 step-up。
- 沒有 Passkey 的帳號一律回 `PASSKEY_ENROLLMENT_REQUIRED`，包含 `bootadmin`，沒有 runtime bypass。首次 bootstrap 以既有 Google fresh session 註冊 Passkey 後再 step-up。若 Google 與所有 Passkey 都遺失，目前沒有可用的自助 recovery/break-glass flow；其設計、審核與演練仍是 full Production GO gate，不能以 client API bypass 代替。
- 以上行為已在 local source 以真實 P-256 assertion、replay、cross-session、expiry、missing-Passkey 與 UV regression 驗證；production 尚未套用 `0014` 或部署，不能宣稱遠端 blocker 已關閉。
- Recovery code 尚未實作；未來只能供一次性帳號復原，不作為日常登入方式。

### 9.5 Telegram

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

SSO 無法只靠刪除自己的 cookie 清除所有 RP cookie。因此所有第一方服務必須支援下列 contract。

### 11.2 RP Session Contract

現行 local source 已完成第一步：所有 user ID token 都帶 nonempty central
`sid`，refresh grant 只接受屬於同一 user 的 live session，test RP 也會拒絕
缺少或為空的 `sid`。`(sid, client_id)` visit ledger、logout-token delivery 與
各 production RP receiver 仍是 Phase 2 工作，不能因此宣稱全域登出完成。

- ID token 包含 `sid`。
- RP 建立本機 session 時保存 `sid` 與 `sub`。
- SSO 在授權完成時記錄 `(sid, client_id)`，用來識別該 session 存取過的服務。
- RP 提供已註冊的 `backchannel_logout_uri`。
- RP 收到 logout token 後，以 `iss`、`aud`、signature、`exp`、`iat`、`events`、`sid/sub` 與 `jti` 驗證。
- RP 依 `sid` 移除所有對應本機 sessions。
- Logout endpoint 必須冪等；相同 `jti` 重複送達不得造成錯誤副作用。

### 11.3 撤銷流程

```text
User/Admin requests revoke
        |
        v
D1 marks central session inactive
        |
        +--> revoke OAuth access/refresh tokens
        |
        +--> append audit event
        |
        +--> enqueue one logout event per visited client
                          |
                          v
                 signed logout token
                          |
                          v
                 RP removes local session
```

中央撤銷狀態必須先完成，Queue 發送才可開始。即使 Queue 暫時失敗，introspection 或 gateway 檢查也必須看到 session 已失效。

### 11.4 撤銷 SLA 與故障政策

- 管理服務：要求立即撤銷，每次請求確認中央狀態，確認失敗時 fail closed。
- 公開服務：Queue 主動推送，另允許最多 30 秒撤銷快取。
- Queue 重試失敗：進 Dead Letter Queue、顯示於管理後台並告警。
- SSO 暫時不可用：公開服務可依風險提供短期既有 session grace period；管理服務不得繞過驗證。

「立即撤銷」與「SSO 故障時所有服務仍完全可用」無法同時保證。以上政策優先保護管理與高敏感服務。

## 12. 帳號中心與管理後台

### 12.1 使用者帳號中心

- 個人資料與穩定帳號 ID。
- 已連結 Google 帳號。
- Passkey 列表、新增、命名與移除。
- 目前及其他裝置 sessions。
- 撤銷單一裝置、其他裝置或所有裝置。
- 已授權應用程式、scopes 與撤銷 consent。
- 個人登入、安全與帳號變更紀錄。
- Recovery codes 產生與重新產生（planned，尚未實作）。
- 帳號刪除申請。

### 12.2 管理後台

- 使用者搜尋、邀請、停權、解除停權與刪除。
- 平台角色與 client-specific roles。
- OIDC clients、redirect URIs、scopes、backchannel logout URI。
- Session 與 token 強制撤銷。
- Signing keys 與 rotation 狀態。
- Security/audit event 查詢與匯出。
- Queue delivery、retry 與 Dead Letter Queue 狀態。
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

### 13.2 PG72 application tables

- `invitations`
- `platform_roles`
- `user_platform_roles`
- `client_roles`
- `user_client_roles`
- `rp_session_visits`
- `recovery_codes`（planned，尚未實作）
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
- 使用者停權、角色變更與刪除。
- Recovery codes 建立與使用。
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
- Recovery code（未來實作時）、refresh token、client secret 與 invitation token 只保存不可逆 hash，除非協議明確要求可還原資料。
- 管理員操作要求 fresh authentication；高風險 client mutation 另要求同一 D1 session 的 Passkey step-up。Local source 已實作 required UV、exact origin/RP ID、一次性 session/user-bound challenge、counter guard 與 timestamp/audit 寫入；production 尚未套用 `0014` 或部署，仍須獨立 review 與實機驗證。
- 管理員至少具有兩種獨立復原方式；受控 recovery/break-glass flow 尚未實作或演練，仍是 full Production GO gate。
- CORS 採 allowlist，不對 credentialed endpoints 使用 `*`。
- 所有 state-changing endpoints 使用 CSRF 保護或不依賴 cookie 的等效防護。
- 登入、callback、token、Passkey、邀請與管理 endpoints 具獨立 rate limits；新帳號建立另有更嚴的 per-IP `REGISTRATION_RATE_LIMITER`。
- Turnstile 與版本化法律同意已在 local source 實作；Preview/production 配置、獨立 review、實機驗證，以及濫用偵測與封鎖流程仍未完成，皆屬 §9.2 的 public 啟用 gate。
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

告警不得直接包含完整 Email、IP、token、authorization code 或 credential ID。

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
- 既有部署紀錄顯示登出修復已上線，仍待 owner 實機確認；中央 `sid` 與 back-channel logout 尚未完成，因此不代表完整 Production GO。

#### Link

- Production 已切換至 PGID；已移除 Worker 內手寫 Google OAuth，改用 `oauth4webapi` confidential client、`client_secret_post`、Authorization Code、PKCE S256、state、nonce、ID token 與 UserInfo 驗證。
- D1 session 以穩定 `sso_subject` 解析使用者；verified email 只供既有 local user 一次性綁定。舊 `owner_email` 暫保留為綁定後不再隨 UserInfo 改變的 local ownership key。
- Admin bootstrap 以 singleton D1 record 關閉 email bootstrap，production error 不回傳原始 exception。
- 所有 cookie-authenticated mutation 強制 exact Origin，短網址 target 僅接受 HTTP(S)。
- Callback：`/api/auth/callback`；migration：`migration-003-pg72-oidc.sql`。中央 `sid` 與 back-channel logout 尚未完成，因此不代表完整 Production GO。

#### Status / XUGOU

- 已移除瀏覽器 `localStorage` Bearer JWT，改用 D1 hashed opaque session + `HttpOnly` host-only cookie。
- 已加入 `oauth4webapi` PKCE/state/nonce/replay 驗證、verified-email legacy binding 與本機 role gate；帳密登入、註冊及 password update surface 回傳 retired response。
- Agent register/report 保持獨立；registration token 改用 `AGENT_TOKEN_SIGNING_KEY` HMAC-SHA-256，並修正 Agent GET/PUT/DELETE owner/admin IDOR。
- CORS 與 unsafe mutation 只允許精確 `APP_BASE_URL`；runtime 與 dev dependency audit 目前為 0 known vulnerabilities。
- Callback：`/api/auth/oidc/callback`；migration：`backend/drizzle/0005_lovely_vargas.sql`。現有本機 session 最長 12 小時，中央 consent revoke 不會即時清除，仍須 back-channel logout。

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
- 管理員 step-up 與 recovery flow。

### 19.3 Global logout tests

- 撤銷單一裝置只影響對應 `sid`。
- 撤銷所有裝置使所有中央 sessions 與 refresh tokens 失效。
- 所有已存取 clients 都收到 logout event。
- Queue 重複投遞不造成錯誤。
- RP 暫時離線後重試成功。
- 永久失敗事件進 DLQ 並顯示告警。
- 管理服務在 SSO/D1 無法確認時 fail closed。

### 19.4 Security tests

- Cookie、CSRF、CORS、open redirect、header spoofing 與 session fixation。
- OAuth mix-up、authorization code interception、redirect URI manipulation。
- Account linking 與相同 Email takeover scenarios。
- Rate limit、Turnstile bypass 與帳號列舉。
- 管理權限 escalation 與 audit tampering。
- Dependency audit、secret scanning 與 production source map 檢查。
- Worker request abort、isolate reuse、併發初始化與 hanging promise regression。
- 使用 `@cloudflare/vitest-pool-workers` 在 workerd 環境測 D1、Queue、cookies 與 bindings，不只在 Node.js mock 測試。
- DAST 對 login、authorize、token、userinfo、introspection、revocation、logout、admin 與 gateway endpoints 全部覆蓋。
- SAST/secret scan/dependency scan 無未處理的 Critical 或 High finding；Medium 必須有書面接受期限與補救措施。

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
- Recovery codes、完整 audit、key rotation/restore drill 仍未完成。

### Phase 2：第一方應用整合

- Copy 與 Link 已切換 production traffic 至 PGID；Copy 六位數訪客碼保持獨立。
- Email 只用於一次性 legacy binding，日常 authentication 已改用 SSO `sub`。
- 這是已部署的 invite beta，不是完整 Production GO；ID-token `sid` 已在 local source 完成，仍待 visited-client ledger、back-channel logout、rollback drill 及單一/全域登出驗收。

### Phase 3：Legacy 與管理服務

- Status 與 Upload 的程式整合及本機安全測試完成；browser、agent、upload capability 已分離，待各自 Preview 實機 flow。
- 從上游 stable release 自行打包 File Browser 與 Roundcube，不直接部署 development snapshot。
- 設定 File Browser proxy auth 與 Roundcube Generic OIDC。
- Mail Path A 的窄 scope introspection prerequisite 已在 repository source 完成；仍待 owner 執行 deploy、system-client provisioning、Dovecot/VPS 設定、事故 rollback 與實機驗收。
- 建立 auth gateway、origin lockdown 與管理服務 fail-closed policy。

### Phase 4：公開註冊 gate

`REGISTRATION_MODE = public` 的程式路徑已具備 verified-email 強制（含未綁定 Telegram 不可建帳）、per-IP 註冊限流、suspended/deleted 管制、audit、Turnstile-backed 一次性 intent 與版本化法律同意紀錄，但 production 仍維持 `invite`。切換前必須完成 §9.2 gate：

- 核准實際 Terms/Privacy versions，部署、配置、獨立 review 並 smoke-test local Turnstile/legal slice；另完成 abuse controls 與新帳號限制狀態。
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
├── docs/                     # Architecture-adjacent public documentation
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
| 管理員復原 | 兩組 Passkey + recovery codes | 待確認 |
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
