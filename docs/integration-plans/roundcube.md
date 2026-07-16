# Roundcube 接入 PGID 整合計畫

狀態：Owner 已選 Dovecot introspection + XOAUTH2 Path A；PGID prerequisite 已在 local source 完成，但尚未 production deploy/provision/VPS cutover
原始查證日期：2026-07-15
Current-source 對帳：2026-07-16
對應產品：PGID（issuer `https://sso.pg72.tw`，OAuth 2.1 / OIDC Authorization Code + PKCE S256）
方針：不維護 fork；production 從鎖定版本、checksum/digest 的 upstream stable 自行打包，優先用原生設定/plugin，不改上游 auth core。

> 本文的 Roundcube/upstream 與 mail-backend 資訊是 2026-07-15
> 唯讀查證紀錄。本輪只對齊 PGID repository truth，沒有重新讀取 production
> Cloudflare、D1、VPS、Dovecot 或 Roundcube 狀態，也沒有執行任何 remote
> 指令。Local commit `9efdece` 的完整 gate 為 166 個 SSO tests 與 4 個 RP
> protocol tests；這不是 production smoke record。

---

## 1. 快照版本查證

- 本機唯讀快照：`/Users/pgpenguin72/sso.pg72.tw/原專案代碼/webmail.pg72.tw`
- `program/include/iniset.php` 定義 `RCMAIL_VERSION = '1.8-git'`。
- 快照 git HEAD commit `752eebab...`（Aleksander Machniak，2026-07-05）為 master 開發線。
- 結論：**快照是 `1.8-git` 開發快照（未發行的 master），依 codex.md 判定「不可直接部署」**。它領先於目前 stable（1.7.x），屬 dev branch。

### 上游最新 stable（2026-07-15 時點）

- Roundcube 最新 stable：**`1.7.2`（2026-07-05，安全更新）**。
  - 1.7.x 為當前 stable 線；1.6.x 進入 LTS（僅重要安全更新），最新為 `1.6.17`（2026-07-05）。
  - 查證來源：<https://github.com/roundcube/roundcubemail/releases>（查證日 2026-07-15）
  - 查證來源：<https://roundcube.net/news/2026/05/10/roundcube-1.7.0-released>（查證日 2026-07-15）
- 建議 production 打包基準：**`1.7.2`**（原生 OIDC 能力最完整且為 stable）。實際打包時「重新」查最新 patch 與 advisories，勿沿用本文版本號。

---

## 2. 原生 OAuth / OIDC 支援

Roundcube 自 `1.5-beta` 起內建 OAuth2；`1.7` 大幅強化 OIDC。相關能力（依 stable `1.7.x`）：

- **Generic OIDC / discovery**：`oauth_config_uri`（since 1.7）可取代手填 `oauth_auth_uri` / `oauth_token_uri` / `oauth_identity_uri`。指向 PGID 的 `.well-known/openid-configuration`。
- **PKCE**：`oauth_pkce`（快照與 1.7 預設 `'S256'`；註解明言 `plain` 方法「voluntarily not implemented」）。符合 PGID 的 PKCE S256 要求。
- **JWKS**：`oauth_jwks_uri` 支援；搭配 `oauth_cache`（since 1.7，backchannel 時 **mandatory**）與 `oauth_cache_ttl`（預設 `8h`）。JWKS 只用於驗證 OIDC ID token 與 back-channel logout JWT；PGID 的 `pg72_at_` access token 是 opaque，不能用 JWKS 本地驗證。
- **Back-channel logout**：內建 endpoint `<roundcube>/index.php/login/backchannel`（action `rcmail_action_login_oauth_backchannel`）。實作依 OpenID Connect Back-Channel Logout 1.0：驗 `logout_token`（`jwt_decode`）、檢查 `typ`（允許 untyped，但若有須為 `logout+jwt`）、要求有 `sub`、拒絕帶 `nonce`，然後 `schedule_token_revocation($event['sub'])`。回 200/204。
  - 註記：其去重與撤銷以 `sub` 為鍵排程撤銷；PGID 要求「以 `jti` 去重」，需確認 Roundcube 當版對重放 `logout_token` 的處理，必要時在 gateway/前置層補 `jti` 去重（見 §7）。
  - 查證來源（設定鍵與 since 版本）：<https://github.com/roundcube/roundcubemail/wiki/Configuration:-OAuth2>（查證日 2026-07-15）
  - 查證來源（`1.7.2` 預設值）：<https://raw.githubusercontent.com/roundcube/roundcubemail/1.7.2/config/defaults.inc.php>（查證日 2026-07-15）
- **其他鍵**：`oauth_provider`、`oauth_provider_name`、`oauth_client_id`、`oauth_client_secret`、`oauth_issuer`、`oauth_logout_uri`、`oauth_scope`、`oauth_identity_fields`、`oauth_login_redirect`、`oauth_user_create_map`（claim → user_name/user_email/language）、`oauth_password_claim`、`oauth_auth_type`。

> Web UI 登入層可完全用原生 OIDC 設定完成，符合「優先用原生設定、不改 auth core」。**難題不在 Web UI，而在 IMAP/SMTP 認證**（見 §3）。

---

## 3. 關鍵議題：Web UI OIDC ≠ IMAP/SMTP 認證

Roundcube 是 IMAP/SMTP 的 client。使用者在 Web UI 用 PGID 登入後，Roundcube 仍必須「代替使用者」連上 mail backend 收發信。這條路徑有三種模式：

### 3.1 XOAUTH2 / OAUTHBEARER（首選，若 backend 支援）

**Owner 已選此路徑，具體為 Dovecot introspection + XOAUTH2。** 這是後續
maintenance-window 的部署方向，不代表本輪已重新確認 production Dovecot
版本、設定或能力。

- Roundcube 用 OIDC 拿到的 access token，透過 SASL `XOAUTH2` 或 `OAUTHBEARER` 直接登入 IMAP/SMTP。
- 設定：`oauth_auth_type`（`'XOAUTH2'` / `'OAUTHBEARER'` / `null` 自動）；`oauth_scope` 必須包含 mail backend 接受的 scope；`imap_host` / `smtp_host` 用 `ssl://` 或 `tls://`。
- **硬性前提**：mail backend（IMAP + SMTP）必須支援對應 SASL 機制，且能**驗證 PGID 簽發的 token**：
  - Dovecot：`auth_mechanisms = xoauth2 oauthbearer`，並把 OAuth2 validation
    固定指向 PGID scoped introspection endpoint。Current Path A 的
    `pg72_at_` access token 是 opaque，不能改用 PGID JWKS 本地驗證。
  - Postfix（SMTP submission）：經 Dovecot SASL 或 backend 支援 `XOAUTH2`/`OAUTHBEARER`。
- PGID current-source contract 只允許固定 service client `pgid-mail-introspect`
  introspect `pg72-webmail` 的 opaque access token。Caller 用
  `client_secret_post`，不可用 Basic。Eligible token 必須有 live central
  session、`email` scope、active user 與 verified email；成功 response 只含
  `active`、`client_id`、`scope`、`iss`、`exp`、`iat`、`email`、
  `email_verified`，刻意不含 `sub`/`sid`。不符合或無權檢查的 token 精確回
  `{"active":false}`。
- token 效期是問題：IMAP 連線可能長於 access token 效期，需 refresh 並重連；`1.7.2` 已把 password/token 取得整理為經 token 或 userinfo。實測長連線 refresh 行為為 GO/NO-GO 項。

### 3.2 短效 credential bridge（backend 不支援 SASL OAuth 時）

- `oauth_password_claim`（預設 `null`）：Roundcube 從 OIDC token/userinfo 取一個 claim 當「短效密碼」登入 IMAP/SMTP，效期至少與 token 相同、隨 refresh 更新。
  - 需 PGID 在 token 內放此 claim，且 mail backend 能以此短效憑證做一般 password 認證（例如 backend 端對 PGID 驗證此值）。
  - 這把「PGID 是否能發、mail backend 是否能驗短效密碼」變成 PGID + backend 的協同需求，非 Roundcube 單方能決定。
- **App password（替代）**：若 backend 完全不吃 OAuth，也不吃短效 claim，退回「每使用者一組長效 app password」存於 backend，Roundcube 以固定密碼登入。缺點：與 PGID 撤銷脫鉤（app password 不隨 PGID 撤銷失效），需獨立生命週期管理，屬最後手段且應在 audit 明列。

### 3.3 快照中的 mail backend 線索

- 快照僅有測試用途線索，**無 production mail backend 設定**：
  - `config/defaults.inc.php`：`imap_host = 'localhost:143'`、`smtp_host = 'localhost:587'`（純預設值，非部署事實）。
  - `.ci/compose.yaml`：測試用 `greenmail/standalone`（`-Dgreenmail.auth.disabled`）、IMAP `tls://mailhost:3143`、SMTP `mailhost:3025`——這是 CI 測試 harness，**不是** production backend。
  - 無 `docker-compose`（production）、無 Dovecot/Postfix/mailcow/docker-mailserver 設定樣板。
- 原始結論是 snapshot 無法辨識 production mail backend。後續 owner 已選
  Dovecot Path A，因此不再等待 A/B 選型；但本輪沒有重新查 production，
  實際版本、SASL capabilities、introspection 設定、SMTP 經 Dovecot SASL
  的路徑與 rollback 仍須由 owner 在維護窗口前確認。

---

## 4. 建議架構

以 Roundcube 原生 OIDC 接 PGID 做 Web UI 登入，mail backend 採 owner 已選
的 Dovecot introspection + XOAUTH2 Path A。不改 auth core，僅用設定與
`oauth_cache` 所需的 DB/Redis；§3.2 保留為 rollback/重新設計參考，不是
目前 deployment target。

### 元件與 pinned 版本

| 元件 | 建議 pinned 版本 | 角色 | 查證來源（查證日 2026-07-15） |
|---|---|---|---|
| Roundcube | **`1.7.2`**（by release tarball checksum / image digest） | Web UI + 原生 OIDC client | <https://github.com/roundcube/roundcubemail/releases> |
| PHP | `8.3.x`（1.7 需 ≥ 8.1；CI 用 php8.3） | runtime | <https://roundcube.net/news/2026/05/10/roundcube-1.7.0-released> |
| `oauth_cache` 後端 | DB（既有）或 Redis（pin digest） | JWKS/token cache，backchannel 必需 | 依部署查證 |
| Mail backend | **Dovecot Path A（owner decision）** | IMAP/SMTP XOAUTH2，以 PGID introspection 驗 token | Production version/config 本輪未重新查證 |

打包規則：從 `1.7.2` release tarball（核對 checksum）或鎖 image digest 自行打包；不使用 `1.8-git` 快照、不使用 `latest`。實際打包前重新查 stable 與 advisories。

### 架構圖（文字）

```
                       (公網 HTTPS)
   使用者瀏覽器
        │  Web UI 登入
        ▼
  ┌────────────────────────┐  OIDC Auth Code + PKCE(S256)   ┌───────────────────┐
  │ Roundcube 1.7.2        │ ─────────────────────────────► │      PGID          │
  │ (原生 oauth_provider)  │ ◄───────────────────────────── │ sso.pg72.tw       │
  │ oauth_config_uri=PGID  │   id/access/refresh token       │ Google + Passkey  │
  │ oauth_pkce=S256        │                                 │ JWKS / discovery  │
  │ oauth_jwks_uri + cache │ ◄── back-channel logout token ──│                   │
  │  /index.php/login/backchannel                            └───────────────────┘
  └───────────┬────────────┘
              │  代使用者登入 (SASL)
              ▼
   ┌───────────────────────────────────────────────┐
   │ Mail backend（owner 選 Dovecot Path A）          │
   │  XOAUTH2 → PGID introspection                    │
   │  service client: pgid-mail-introspect            │
   │  production/VPS 尚未套用                         │
   └───────────────────────────────────────────────┘
```

---

## 5. Roundcube 設定要點（`config/config.inc.php`）

Web UI OIDC（值為示意，實際依 PGID discovery）：

```php
$config['oauth_provider']      = 'generic';          // 非 google/outlook 內建
$config['oauth_provider_name'] = 'PGID';
$config['oauth_client_id']     = 'pg72-webmail';
$config['oauth_client_secret'] = '<走 secret store，勿入 source/log>';
$config['oauth_config_uri']    = 'https://sso.pg72.tw/.well-known/openid-configuration';
$config['oauth_issuer']        = 'https://sso.pg72.tw';
$config['oauth_pkce']          = 'S256';
$config['oauth_scope']         = 'openid email profile <mail backend 所需 scope>';
$config['oauth_cache']         = 'db';   // 或 'redis'；backchannel 必需
$config['oauth_cache_ttl']     = '8h';
$config['oauth_login_redirect']= true;   // 直接導向 PGID（Google/Passkey 在 PGID 選）
// redirect URL 登記於 PGID： https://webmail.pg72.tw/index.php/login/oauth
// back-channel logout 登記於 PGID： https://webmail.pg72.tw/index.php/login/backchannel
```

Identity mapping（**用 `sub` 不用 email**）：

- codex.md 要求以不可變 `sub` 識別使用者。Roundcube 傳統以 IMAP username 當帳號鍵，`oauth_user_create_map` 預設把 `name`/`email` 映射到 user_name/user_email。
- 需確認 Roundcube 當版能否以 `sub` 作內部使用者鍵；若其帳號模型綁 IMAP login name，則「使用者主鍵」實質由 mail backend 決定。此處與 §3 的 backend 選型耦合，**需 owner 與 mail backend 設計一併決定**：Roundcube user 與 PGID `sub` 的對應如何維持穩定（例如 backend 以 `sub` 當 mailbox 鍵）。
- Path A introspection response 的 verified `email` 只供 Dovecot 對應既有
  mailbox username，不把 email 升格為 PGID/Roundcube 的身分主鍵，也不可
  用它靜默合併身分。

IMAP/SMTP（依 §3 路徑）：

```php
// 路徑 A（backend 支援 SASL OAuth）
$config['imap_host']     = 'ssl://<mail-backend>:993';
$config['smtp_host']     = 'ssl://<mail-backend>:465';
$config['oauth_auth_type']= 'XOAUTH2';   // 或 'OAUTHBEARER' / null 自動
// oauth_scope 須含 backend 接受的 mail scope

// 路徑 B（backend 不支援 SASL OAuth）
$config['oauth_password_claim'] = '<PGID token 內的短效密碼 claim>'; // 需加入 oauth_scope
```

Dovecot introspection 另使用固定 client ID `pgid-mail-introspect` 與只顯示
一次的 secret。Secret 只能在 owner 完成 production Passkey step-up 後，
透過 PGID same-origin admin provisioning 取得並存進 VPS secret
configuration；不能共用 `pg72-webmail` 的 OIDC client secret，也不能寫入
此檔、source、D1 明文、log、issue 或聊天。

---

## 6. Mail backend 認證分析（XOAUTH2 / OAUTHBEARER 路徑）

Current target 是第一列的 Dovecot Path A。其餘列只保留為 rollback 或重新
設計參考；本輪沒有重新登入 VPS 驗證實際 production capability。

| 條件 | 採用路徑 | 需要的 backend 支援 |
|---|---|---|
| backend 支援 `XOAUTH2`/`OAUTHBEARER` 且能驗 PGID token | §3.1（首選） | Dovecot `auth_mechanisms` 含 xoauth2/oauthbearer；OAuth2 validation 固定使用 PGID scoped introspection；SMTP submission 同步。JWKS 不驗 opaque access token |
| backend 不支援 SASL OAuth，但可驗短效密碼 | §3.2 credential bridge | PGID 於 token 放 password claim；backend 以此值做 password 驗證，效期對齊 token |
| backend 完全不支援 | app password（最後手段） | backend 產生/儲存長效 app password；與 PGID 撤銷脫鉤，需獨立管理 |

要點：

- access token 效期通常短於 IMAP 連線壽命，必須實測 token refresh 後重連是否順暢（GO/NO-GO）。
- Introspection 只接受 `POST application/x-www-form-urlencoded`，body 內帶
  `client_id`、`client_secret`、`token`；Basic/`Authorization`、GET、重複
  single-value fields 與超過 4 KiB body 都被拒絕。無效或未授權 token 回
  HTTP 200 + 精確 `{"active":false}`，錯誤 client credential 回 401。
- Production normal-flow smoke 只驗 active/inactive/401。`429` exhaustion 與
  `503` limiter failure 必須在 isolated Preview 或 controlled local test
  驗證；不得對 production flood 或故意破壞 binding。
- PGID 是「單一 audience」策略（見 SECURITY.md，因 `GHSA-p2fr-6hmx-4528` 補償控制拒絕 RFC 8707 `resource`）。Path A 不要求 Dovecot 解碼 audience：Dovecot 把 opaque token 送到固定的 scoped introspection pair，由 PGID 驗 token client、live session、scope 與 verified mailbox identity。不得改成同 audience + JWKS 本地驗，也不得另發 resource-specific token。

---

## 7. Back-channel logout 落地與取捨

- **原生可用**：Roundcube `1.7.x` 內建 `/index.php/login/backchannel`，驗 `logout_token`、要求 `sub`、拒 `nonce`，並以 `sub` 排程撤銷 Web session。將此 URL 登記至 PGID。
- **`jti` 去重**：PGID 要求以 `jti` 去重。Roundcube 內建實作以 `sub` 為撤銷鍵；需確認當版是否對重複 `logout_token`（相同 `jti`）冪等處理。若不足，於前置反代或小型 receiver 補 `jti` 去重（記錄已見 `jti`，重放直接 200 冪等回應），符合 codex.md「以 `jti` 去重」。
- **撤銷 cache 上限**：`oauth_cache` + `oauth_cache_ttl`（預設 `8h`）影響 JWKS/token 判定新鮮度。對「公開服務撤銷 cache 上限 30 秒」的要求，back-channel logout 是即時 push（不受 8h cache 限制）；但若 back-channel 未達或漏送，撤銷生效會延到 token/session 自然過期。取捨：
  - 縮短 Roundcube session 與 access token 效期，作為 back-channel 之外的保險。
  - **IMAP/SMTP 側的撤銷是獨立問題**：Web session 登出不等於已建立的 IMAP 連線立即斷。路徑 A（SASL OAuth）下 token 過期 + refresh 失敗會使重連失敗；app password（最後手段）則完全不隨 PGID 撤銷失效，是最大缺口。
- **全域登出**：PGID 為撤銷 source of truth。Roundcube 收 logout token 清 Web session；mail backend 側需依 §6 路徑各自失效（token 過期或 app password 手動撤銷）。

---

## 8. 部署驗收清單

- [x] PGID local source 已完成 scoped mail introspection。
- [x] Local source 已實作真正的 Passkey step-up，涵蓋 required UV、exact origin/RP ID、session/user-bound one-time challenge、replay/expiry/credential isolation 與六條 client mutation gate。
- [ ] Owner 安排獨立安全 review，並在 production 套用 migration / deploy 後完成實機 ceremony smoke；`<10m` session-age freshness 仍不能代替 step-up。
- [ ] Owner 已重新確認 production `pg72-webmail` exact metadata，並建立 private D1 backup / Time Travel 記錄。
- [ ] Owner 已依序套用 local migrations `0013`、`0014`（最新既有 production record 只有 `0012`）。
- [ ] PGID Worker 已部署，`PASSKEY_STEP_UP_MAX_AGE_SECONDS=600`，且 `INTROSPECTION_IP_RATE_LIMITER` namespace `1004` 與 `INTROSPECTION_CLIENT_RATE_LIMITER` namespace `1005` bindings 均存在。
- [ ] 完成 Passkey step-up 後，以 same-origin fresh admin session provision `pgid-mail-introspect`，並立即將一次性 secret 放入 approved secret store/VPS secret config。
- [ ] Production active/inactive/401 normal-flow smoke 通過；429/503 僅在 isolated Preview/controlled local test 驗證，沒有對 production flood/failure injection。
- [ ] 從 `1.7.2` release（checksum/digest 鎖定）打包，**不使用 `1.8-git` 快照**，未改 auth core。
- [ ] PHP ≥ 8.1（建議 8.3），`public_html/` 為對外 entry-point（1.7 強制）。
- [ ] `oauth_config_uri` 指向 PGID discovery，`oauth_pkce=S256`，`oauth_issuer=https://sso.pg72.tw`。
- [ ] `oauth_cache` 已啟用（backchannel 必需），`oauth_cache_ttl` 已依撤銷需求評估。
- [ ] Redirect URL（`/index.php/login/oauth`）於 PGID 精確登記，HTTPS、無 wildcard。
- [ ] Web UI 完整 flow 實測：Google 與 Passkey 各一次 → 成功進 Roundcube。
- [ ] 抓封包確認 authorize 帶 `code_challenge`（S256）、token 交換帶 `code_verifier`。
- [ ] **mail backend 認證路徑確定並實測**（A/B/最後手段）；長連線 token refresh/重連通過。
- [ ] Back-channel logout：PGID 送 `logout_token` → `/index.php/login/backchannel` 回 200，Web session 失效。
- [ ] `jti` 去重：重放同一 `logout_token` 為冪等（原生或前置 receiver 補齊）。
- [ ] 撤銷演練：PGID 撤銷後 Web session 及（路徑 A）mail 連線於預期時間內失效；app password（若採用）撤銷流程演練。
- [ ] Identity 主鍵：Roundcube user 與 PGID `sub` 對應穩定，非以 email 為主鍵。
- [ ] Secret（client secret、cache 後端認證、app password 若有）走 Secrets Store，不入 source/config/log。
- [ ] 單一 audience 相容：mail backend 對 PGID token 的驗證未依賴 RFC 8707 `resource`（與 SECURITY.md 補償控制相容）。

---

## 9. 風險清單

| 風險 | 嚴重度 | 說明 | 緩解 |
|---|---|---|---|
| production Dovecot 狀態未重新查證 | 高 | Owner 已選 Path A，但本輪沒有確認實際版本、SASL capability、introspection/SMTP path 或 rollback | 維護窗口前由 owner 唯讀查證；未確認前不 cut over |
| Passkey step-up 尚未部署 / 獨立審查 | 高 | Local implementation 與 regression 不代表 production ceremony 已可用 | 先套 `0014`、部署、獨立審查並 smoke，再 provision/rotate system client |
| PGID prerequisite 尚未部署 | 高 | Local tests 通過不代表 production 已有 0013/0014、rate bindings 或 service client | 依 handoff owner runbook 逐步 deploy/provision/smoke，保留 rollback |
| Web UI OIDC 假象 | 高 | Web 登入成功不代表 IMAP/SMTP 已通過認證 | 明確分開 §3 兩層，各自驗收 |
| app password 與撤銷脫鉤 | 高 | 最後手段下，PGID 撤銷無法讓 mail 憑證失效 | 僅作最後手段；獨立生命週期管理 + audit；優先推 backend 支援 OAuth |
| 單一 audience 與 mail token 衝突 | 中-高 | SECURITY.md 拒 RFC 8707 `resource`；mail backend 若要求自行驗專屬 audience 會衝突 | 固定使用 scoped introspection，不讓 Dovecot 以 JWKS 解 opaque token；若 backend 不接受此模式則停止 Path A rollout |
| `1.8-git` 誤用 | 中 | 快照為 dev branch，codex.md 明令不可部署 | 一律以 `1.7.2` stable 打包 |
| `jti` 去重不足 | 中 | 原生以 `sub` 排程撤銷，重放冪等性待確認 | 確認當版行為；不足時前置 receiver 補 `jti` 去重 |
| token 短於 IMAP 連線壽命 | 中 | 長連線需 refresh 重連，失敗會中斷收發 | 實測 refresh/重連；縮短連線或加重連邏輯 |
| 撤銷延遲（back-channel 漏送） | 中 | logout token 未達時撤銷延到自然過期 | 縮短 session/token 效期作保險；監控 back-channel 送達 |
| 上游安全更新頻繁 | 低-中 | 1.7.x/1.6.x 常出安全 patch | pin 已修版、定期升級並重跑 regression |

---

## 10. 需 owner 決定的開放問題

Path A 已選，不再把 A/B 選型列為開放問題。進 production 前仍需 owner 關閉：

1. 誰負責 Passkey step-up 的獨立 review、production `0014` / Worker rollout 與 ceremony smoke，並記錄 GO/NO-GO？
2. Production Dovecot/Postfix 實際版本與設定是否支援預定 XOAUTH2 + introspection 路徑？SMTP submission 是否確實經 Dovecot SASL？
3. Roundcube 使用者主鍵與 PGID `sub` 的對應如何維持穩定；verified email 作 mailbox username mapping 時，變更與衝突如何處理？
4. 單一 audience 策略下（SECURITY.md 拒 RFC 8707 `resource`），Dovecot 是否能直接使用 current opaque-token introspection contract？
5. `jti` 去重是否需在 Roundcube 前置 receiver 補足；Web session 與既有 IMAP connection 的撤銷 SLA 各是多少？
6. Owner maintenance window、legacy auth rollback、監控與 secret rotation 負責人何時確認？
