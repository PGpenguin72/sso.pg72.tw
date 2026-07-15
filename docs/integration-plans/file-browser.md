# File Browser 接入 PGID 整合計畫

狀態：草案（規劃階段，僅供評估）
撰寫日期：2026-07-15
對應產品：PGID（issuer `https://sso.pg72.tw`，OAuth 2.1 / OIDC Authorization Code + PKCE S256）
方針：不維護 fork；production 從鎖定版本、checksum/digest 的 upstream stable 自行打包，優先用 gateway/設定，不改上游 auth core。

---

## 1. 快照版本查證

- 本機唯讀快照：`/Users/pgpenguin72/sso.pg72.tw/原專案代碼/file.pg72.tw`
- `version/version.go` 的 `Version` 為 `"(untracked)"`（build 時才注入），因此不能只看該檔判定版本。
- 判定依據：
  - `CHANGELOG.md` 最新條目為 `2.63.18`（2026-07-04）。
  - 快照內 git HEAD 為 commit `fe7efb2e6afe66774cd86a5b0a03033bd514d0c0`，訊息 `chore(release): 2.63.18`（Sat Jul 4 2026）。
- 結論：**快照對應 File Browser `v2.63.18`**。

### 上游最新 stable（2026-07-15 時點）

- File Browser 最新 stable 為 **`v2.63.18`（2026-07-04）**，與快照同版。
  - 查證來源：<https://github.com/filebrowser/filebrowser/releases>（查證日 2026-07-15）
  - 查證來源：<https://github.com/filebrowser/filebrowser/releases/tag/v2.63.18>（查證日 2026-07-15）
- 說明：專案採 patch 快速迭代，`v2.63.x` 為活躍線。實際打包時必須「重新」查最新 patch 與 advisories，勿沿用本文版本號。

---

## 2. 認證選項評估（上游現況）

File Browser 內建 auth 方法（`settings.AuthMethod`）：`json`（帳密 + bcrypt）、`proxy`（信任 header）、`none`、`hook`。

- **原生無 OAuth/OIDC**：File Browser 本身沒有 OIDC client，無法直接接 PGID 的 Authorization Code flow。
- **`proxy` 方法**：讀取設定的 header（`auth.header`）當使用者名，`usr.Get(...)` 找不到就 **自動建立使用者**。程式碼在快照 `auth/proxy.go` L21-28（`Auth`）與 L30-66（`createUser`），對 header **零防禦**（不驗來源 IP、無 shared secret、無簽章）。
  - 設定方式：`filebrowser config set --auth.method=proxy --auth.header=<HeaderName>`
  - 查證來源：<https://filebrowser.org/authentication.html>（查證日 2026-07-15）

### 關鍵安全風險：CVE-2026-54089（必讀）

- GHSA：`GHSA-xqp3-jq6g-x3qm` / CVE-2026-54089，「Authentication Bypass via Proxy Auth Header Forgery」。
- 影響版本：`>= 2.0.0-rc.1, <= 2.63.18`，**`first_patched_version` 為 `null`（截至 2026-07-15 無修補版）**。
- CVSS 3.1 向量 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`，GitHub 評 **Critical（v3 score 9.1）**。
- 內容：只要啟用 `auth.method=proxy` 且 origin 可被直接連到，攻擊者送一個偽造 header（例如 `X-Remote-User: admin`）即可冒充任意使用者（含 admin），或以不存在的名稱觸發自動建帳。
- 查證來源：GitHub Advisory API `GHSA-xqp3-jq6g-x3qm`（查證日 2026-07-15）；<https://github.com/advisories/GHSA-xqp3-jq6g-x3qm>

> 結論：`proxy` 方法本身沒有錯，但它把**全部安全性外包給網路隔離**。因為目前沒有修補版，「origin 只接受 gateway 流量 + gateway 強制覆寫 identity header」不是 best practice 而是**唯一可行的補償控制**，必須被當成硬性部署需求，不可省略。

---

## 3. 建議架構：外部 OIDC gateway + proxy header

由外部 OIDC reverse proxy 完成與 PGID 的完整 Authorization Code + PKCE flow，驗證通過後注入 identity header 給 File Browser。File Browser 只信任 gateway 注入的 header，且**只能**經 gateway 連到。

### 元件與 pinned 版本

| 元件 | 建議 pinned 版本 | 角色 | 查證來源（查證日 2026-07-15） |
|---|---|---|---|
| OIDC gateway | **oauth2-proxy `v7.15.3`**（2026-06-09） | 對 PGID 跑 OIDC + PKCE，注入 identity header | <https://github.com/oauth2-proxy/oauth2-proxy/releases> |
| File Browser | **`v2.63.18`**（proxy auth 模式） | 檔案服務，僅信任 gateway header | <https://github.com/filebrowser/filebrowser/releases/tag/v2.63.18> |
| Session store | Redis（pin 官方 image digest，例如 `redis:7.x` by digest） | oauth2-proxy session/refresh 存放 | 依部署時查證 |
| 前端反代（可選） | nginx / Caddy（pin by digest） | TLS 終端、把 gateway 前置於公網 | 依部署時查證 |

打包規則（依 CLAUDE.md / codex.md）：所有 image 用 **digest（`@sha256:...`）鎖定**，不使用 `latest`；binary 下載核對 checksum。實際打包前重新查 stable tag 與 security advisories。

為什麼選 oauth2-proxy：CNCF 專案、原生 OIDC + PKCE + refresh、成熟的 header 注入與 `--reverse-proxy` / `--trusted-proxy-ip` 控制，且能設定 header 覆寫，正好對應「strip/overwrite 使用者自帶 identity header」需求。替代品（Authelia、Authentik、Caddy `forward_auth`、Vouch）皆可行；oauth2-proxy 最輕量且與「單一 RP + header 注入」情境最契合，故為首選。

### 架構圖（文字）

```
                         (公網 HTTPS)
   使用者瀏覽器 ──────────────────────────────────┐
        │                                          │
        ▼                                          ▼
  ┌──────────────┐   OIDC Auth Code + PKCE   ┌───────────────────┐
  │ 前端反代     │ ───────────────────────►  │      PGID          │
  │ nginx/Caddy  │ ◄───────────────────────  │ sso.pg72.tw       │
  │ (TLS 終端)   │        id_token/回呼       │ Google + Passkey  │
  └──────┬───────┘                            └───────────────────┘
         │  轉發 (內網)
         ▼
  ┌───────────────────────────┐        session ┌──────────┐
  │ oauth2-proxy (gateway)    │◄──────────────►│  Redis   │
  │ - 驗證 OIDC session       │                └──────────┘
  │ - STRIP 用戶端自帶 header │
  │ - 注入 X-Forwarded-User=sub│
  └──────────────┬────────────┘
                 │  僅 gateway → origin（127.0.0.1 / 專用內網 / mTLS）
                 ▼
      ┌────────────────────────────┐
      │ File Browser v2.63.18      │
      │ auth.method=proxy          │
      │ auth.header=X-Forwarded-User│
      │ 綁定 127.0.0.1，不開放公網 │
      └────────────────────────────┘
```

---

## 4. Gateway（oauth2-proxy）設定要點

以「單一 RP、header = OIDC `sub`、origin 鎖定」為目標。所有 flag 名稱查證來源：<https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/> 與 `.../providers/openid_connect`（查證日 2026-07-15）。

- Provider：
  - `--provider=oidc`
  - `--oidc-issuer-url=https://sso.pg72.tw`（啟用 OIDC discovery / JWKS）
  - `--client-id` / `--client-secret`：由 PGID 管理員預先建立（dynamic client registration 關閉）。secret 走 Secrets Store，不落 config/log。
  - `--redirect-url=https://file.pg72.tw/oauth2/callback`：**精確** HTTPS redirect URI，需在 PGID 端逐字登記。
  - PKCE：oauth2-proxy OIDC provider 支援 PKCE；部署時確認啟用 `code_challenge_method=S256`（依版本以 `--code-challenge-method=S256` 或 provider 預設）。實測 callback 交換時確有 `code_verifier`。
- Identity 對應（**用 `sub` 不用 email**）：
  - `--set-xauthrequest=true`（產生 `X-Auth-Request-User` 等 header）與/或 `--pass-user-headers=true`（預設 true，產生 `X-Forwarded-User` 等）。
  - oauth2-proxy 的 "user" claim 預設即 `sub`（`session.User` 來源），`X-Forwarded-User` 因此帶 `sub`。明確設 `--user-id-claim=sub`（或 alpha config `oidcConfig.userIDClaim=sub`）以固定行為；不要用 `--prefer-email-to-user`。
  - 注意上游 bug：alpha/oidcConfig 的 `userIDClaim` 曾有未正確映射到 `UserClaim` 的問題（#3165 / #1973）。GO/NO-GO 驗收時**必須實測** `X-Forwarded-User` 內容確為 PGID `sub`，而非 email、session id 或空值。
- Origin lockdown 前置條件（reverse proxy 模式）：
  - `--reverse-proxy=true`
  - `--trusted-proxy-ip`（TOML `trusted_proxy_ips`）**務必設定**為前端反代來源；預設 `0.0.0.0/0, ::/0` 會信任所有來源、允許 forwarded header 偽造。
- Session / 撤銷相關：
  - `--session-store-type=redis` + `--redis-connection-url=...`
  - `--cookie-secret`（隨機）、`--cookie-secure=true`
  - `--cookie-refresh`：設短（見 §7）以觸發對 PGID 的 refresh/重驗，逼近「撤銷 ≤ 30 秒」語意。
  - `--cookie-expire`（預設 `168h`，需縮短）。
- 使用者體驗：`--skip-provider-button=true` 直接導向 PGID（PGID 才是 Google/Passkey 選擇點）。
- header 覆寫（關鍵）：oauth2-proxy 會設定它自己的 auth header（`--skip-auth-strip-headers` 預設 true 會剝除 auth 樣式 header）。但**注入給 upstream 的 identity header 名稱，必須是 File Browser 端設定為信任的那個**，且要確保用戶端自帶的同名 header 被覆寫或剝除（見 §6）。

---

## 5. File Browser 設定要點

- 打包：從 `v2.63.18`（by digest）自行打包，不改 auth core（符合「不維護 fork」）。
- 啟用 proxy 認證：
  - `filebrowser config set --auth.method=proxy --auth.header=X-Forwarded-User`
  - `auth.header` 名稱必須與 gateway 實際注入者**逐字一致**。
- 停用其他登入面：確認 `signup=false`（禁自助註冊），移除/不建立本機管理帳密登入入口（避免 `json` 面殘留）。
- Identity mapping：File Browser 以 header 值作 username。gateway 注入 `sub` → File Browser 的 username 即 `sub`（不可變、非 email，符合 codex.md「以 OIDC `sub` 識別使用者」）。
  - 副作用：`createUser` 會以 username 建 home dir，故目錄名會是 `sub`。若需人類可讀顯示名，另由 gateway 傳非 identity 用途的顯示 header，或後續以管理流程維護；**主鍵維持 `sub`**。
  - 自動建帳：proxy 模式下 `createUser` 無法關閉（上游行為）。因為 origin 已鎖定，只有通過 PGID 的 `sub` 會到達；風險由 origin lockdown 承擔，但需在 audit 監控新帳建立。
- 綁定與網路：容器 `--address 127.0.0.1`（或僅監聽內部 interface），**不 publish 到 `0.0.0.0`**。Docker 情境避免 `-p 8080:80` 直接對公網。

---

## 6. Origin lockdown 手段（對抗 CVE-2026-54089）

因無修補版，以下至少擇一並優先多層並用：

1. **網路隔離**：File Browser 只監聽 loopback 或專用內網 segment；公網僅暴露前端反代 → gateway。防火牆 / security group 限制 origin port 僅 gateway 可連。
2. **Header 覆寫（必做）**：gateway 對每個轉往 origin 的請求，**無條件覆寫或刪除** `auth.header`（`X-Forwarded-User`）與相關 `X-Auth-Request-*`、`X-Forwarded-*`，使用戶端自帶值不可能通過。設定 `--pass-user-headers` / `--set-xauthrequest` 讓 gateway 以自身值覆蓋。前端反代（nginx/Caddy）亦應在入口先 `proxy_set_header X-Forwarded-User "";` 清掉客端輸入，只由 gateway 填。
3. **傳輸層綁定**：gateway → origin 用 mTLS 或 Unix socket / 專屬 docker network，並在 origin 端（若以 nginx sidecar 前置）僅接受帶正確 client cert / 來源的連線。
4. **深度防禦**：origin 前放一個極小 nginx，`deny all` 例外 gateway，並再次 strip identity header。

驗收時必須「從 origin 網段直接打」測 header 偽造被擋（見 §8）。

---

## 7. Back-channel logout 落地與取捨

現況：File Browser **沒有** OIDC，也沒有 back-channel logout endpoint、無 `sid`/`jti` 概念，且以自簽 JWT（`X-Auth`）維持 session。PGID 要求第一方 RP 實作冪等 back-channel logout 並以 `jti` 去重——File Browser 本體無法滿足，需由 gateway 層承接。

可行做法（依成本排序）：

- **A. 縮短 session + 主動重驗（建議起點）**：
  - gateway `--cookie-refresh` 設 **≤ 30 秒**、`--cookie-expire` 設短（例如 1 小時）。cookie-refresh 到期時 oauth2-proxy 會用 refresh token 向 PGID 重換 token；PGID 端撤銷後 refresh 失敗即登出。這逼近 codex.md「公開服務撤銷 cache 上限 30 秒」的語意。
  - 取捨：refresh 太頻繁會增加 PGID token endpoint 負載與延遲；需搭配 PGID rate limit 評估。File Browser 自身簽的 `X-Auth` JWT 有其效期，logout 後該 JWT 在到期前仍可能被重用——因此必須把 File Browser JWT 效期也設短，並確保新請求都經 gateway（origin lockdown 使舊 JWT 無法繞過 gateway 重驗）。
- **B. Gateway 承接 back-channel logout（進階）**：
  - 若採支援 OIDC back-channel logout 的 gateway（oauth2-proxy 對 RP-initiated / back-channel logout 支援有限，需查當版能力），由 PGID 送 logout token 到 gateway 的 logout endpoint，gateway 依 `jti` 去重、清 Redis session。File Browser 端因 session 短效 + origin lockdown 隨即失效。
  - 若 oauth2-proxy 當版不支援，替代為在 gateway 前放一支極小的第一方 logout receiver（驗 PGID JWKS、驗 `jti`/`aud`/`sub`、刪 Redis session key），符合 codex.md「第一方 RP 實作冪等 back-channel logout」。
- **C. 全域登出**：PGID 撤銷 + Redis session 清除為 source of truth；File Browser 無獨立 session store 需清（其 JWT 為 stateless），故關鍵在讓短效 JWT 過期且新請求必經已失效的 gateway session。

決策待 owner：是否投入 B（gateway 承接 back-channel logout）以達成 codex.md 對第一方 RP 的硬性要求，或先以 A 的短效 session 過渡並記錄為技術債。

---

## 8. 部署驗收清單

- [ ] File Browser 由 `v2.63.18`（digest 鎖定）打包，未修改 auth core。
- [ ] `auth.method=proxy`、`auth.header` 與 gateway 注入名稱逐字一致。
- [ ] `signup=false`，無殘留 `json` 帳密登入面。
- [ ] oauth2-proxy `v7.15.3`（digest 鎖定），`--provider=oidc`、`--oidc-issuer-url=https://sso.pg72.tw`。
- [ ] Redirect URI 在 PGID 端精確登記，無 wildcard，HTTPS。
- [ ] 實測完整 flow：瀏覽器 → gateway → PGID（Google 與 Passkey 各測一次）→ 回 File Browser 可讀檔。
- [ ] 實測 `X-Forwarded-User` 內容 == PGID `sub`（非 email / 非空 / 非 session id）。
- [ ] PKCE：抓封包確認 authorize 帶 `code_challenge`（S256）、token 交換帶 `code_verifier`。
- [ ] **Origin lockdown**：從 origin 網段直接 `curl -H "X-Forwarded-User: admin" http://origin/api/login` 應被拒（連不到或無效），證明 CVE-2026-54089 不可利用。
- [ ] Gateway 覆寫/剝除用戶端自帶 `X-Forwarded-User` / `X-Auth-Request-*`：客端偽造 header 經 gateway 後不生效。
- [ ] `--trusted-proxy-ip` 已設為前端反代，非預設全信任。
- [ ] Session 短效：`--cookie-refresh` ≤ 30s、`--cookie-expire` 與 File Browser JWT 效期皆已縮短並記錄。
- [ ] 登出/撤銷演練：PGID 撤銷後，≤ 30 秒內 File Browser 存取失效。
- [ ] Secret（client secret、cookie-secret、redis 認證）走 Secrets Store，不在 config/image/log。
- [ ] 結構化 log：identity header 值、token、cookie 皆 redaction。

---

## 9. 風險清單

| 風險 | 嚴重度 | 說明 | 緩解 |
|---|---|---|---|
| CVE-2026-54089 無修補版 | 高 | proxy header 偽造 = admin 接管；上游無 patch | Origin lockdown（網路隔離 + header 覆寫 + mTLS/socket），列為硬性需求並持續監控上游修補 |
| origin 意外對公網暴露 | 高 | Docker 預設 publish `0.0.0.0`、debug 開 port、雲端 SG 誤設 | 綁 127.0.0.1、firewall、部署後主動掃描 origin port |
| `X-Forwarded-User` 帶錯 claim | 中 | oauth2-proxy `userIDClaim` 映射 bug（#3165/#1973）可能落成 email/session id | 驗收硬性實測；固定 `--user-id-claim=sub` 並抓封包確認 |
| 自動建帳無法關閉 | 中 | proxy 模式 `createUser` 恆開；若 header 走漏會生帳號 | origin lockdown + audit 監控新帳建立 |
| 無原生 back-channel logout | 中 | 不符 codex.md 第一方 RP 要求 | 短效 session（A）過渡，評估 gateway 承接（B） |
| File Browser stateless JWT 重用 | 中 | logout 後 JWT 在到期前仍有效 | JWT 效期設短 + 新請求必經已失效 gateway session |
| gateway 版本落後帶 CVE | 中 | oauth2-proxy 歷史有 `X-Forwarded-Uri` 偽造等 bypass（v7.15.x 已修） | pin 已修版本、定期升級並重驗 |
| refresh 過頻壓垮 PGID token endpoint | 低-中 | `cookie-refresh` ≤30s 放大請求量 | 與 PGID rate limit 併同評估，必要時放寬並接受撤銷延遲 |
| 顯示名以 `sub` 呈現不友善 | 低 | 目錄/使用者名為 opaque `sub` | 另傳顯示用 header，主鍵維持 `sub` |

---

## 10. 需 owner 決定的開放問題

1. Back-channel logout：採 A（短效 session 過渡）還是投入 B（gateway 承接 logout token、`jti` 去重）以滿足 codex.md 第一方 RP 硬性要求？
2. Origin lockdown 傳輸層：mTLS、Unix socket、專屬 docker network 或 nginx sidecar，選哪一種為主？
3. `cookie-refresh` 目標值：是否接受 ≤30s 的 PGID token endpoint 負載，或放寬並明確記錄撤銷延遲上限？
4. gateway 選型：確認 oauth2-proxy（vs Authelia/Authentik）；若 oauth2-proxy 當版不支援 back-channel logout，是否接受自建小型 logout receiver？
5. 使用者顯示名策略：是否需要 `sub` 以外的人類可讀名，來源與維護方式為何？
6. 由於 CVE-2026-54089 無 patch，是否需要在 Security Gate 明列此為「已知未修補、以補償控制承擔」的 accepted risk（含 owner、期限、重評時點）？
