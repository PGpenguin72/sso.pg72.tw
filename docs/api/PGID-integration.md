# PGID 串接 API 手冊

> 類型：技術參考（reference）
> 對象：要把服務接上 PGID 的第一方 / 受管開發者
> Issuer：`https://sso.pg72.tw`
> 協議：OAuth 2.1 / OpenID Connect，Authorization Code + PKCE S256
> 最後對照程式碼：`apps/sso/worker/auth.ts`、`apps/sso/worker/index.ts`、`apps/sso/worker/admin-clients.ts`、`apps/test-rp/worker/index.ts`

本手冊是**精簡技術參考**：端點、scopes、claims、token 壽命、client 認證方式與可複製的串接範例。教學導向、逐步導覽與一般使用者說明在 [`wiki/`](../../wiki/SUMMARY.md)；完整架構規格與安全設計以 [`codex.md`](../../codex.md) 為準。若本文件與 `codex.md` 衝突，以 `codex.md` 為準並在同一變更修正本文件。

所有端點值請以 **discovery 文件為單一事實來源**；不要在服務內硬編碼未公開的內部路徑。下列數值於撰寫時對照現行程式碼，實際整合時仍應讀取 discovery 再使用。

---

## 1. Discovery

| 項目 | 值 |
| --- | --- |
| Issuer | `https://sso.pg72.tw` |
| OpenID discovery | `https://sso.pg72.tw/.well-known/openid-configuration` |
| OAuth AS metadata | `https://sso.pg72.tw/.well-known/oauth-authorization-server` |

任何符合規範的 OIDC client library 都應先抓 discovery 再取用端點。`oauth4webapi` 用 `discoveryRequest` + `processDiscoveryResponse`（見第 8 節）。

Discovery 目前回報的重點欄位（對照 `@better-auth/oauth-provider@1.6.23`）：

| Metadata 欄位 | 值 |
| --- | --- |
| `issuer` | `https://sso.pg72.tw` |
| `authorization_endpoint` | `https://sso.pg72.tw/oauth2/authorize` |
| `token_endpoint` | `https://sso.pg72.tw/oauth2/token` |
| `userinfo_endpoint` | `https://sso.pg72.tw/oauth2/userinfo` |
| `jwks_uri` | `https://sso.pg72.tw/.well-known/jwks.json` |
| `introspection_endpoint` | `https://sso.pg72.tw/oauth2/introspect` |
| `revocation_endpoint` | `https://sso.pg72.tw/oauth2/revoke` |
| `end_session_endpoint` | `https://sso.pg72.tw/oauth2/end-session` |
| `registration_endpoint` | 未提供（dynamic client registration 關閉） |
| `scopes_supported` | `["openid", "profile", "email", "offline_access"]` |
| `response_types_supported` | `["code"]` |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `["authorization_code", "client_credentials", "refresh_token"]` |
| `code_challenge_methods_supported` | `["S256"]` |
| `token_endpoint_auth_methods_supported` | `["none", "client_secret_post"]` |
| `id_token_signing_alg_values_supported` | `["EdDSA"]` |
| `subject_types_supported` | `["public"]` |
| `claims_supported` | `["https://pg72.tw/role"]` |
| `authorization_response_iss_parameter_supported` | `true` |

`grant_types_supported` 是伺服器層級能力；**單一 client 實際可用的 grant 由該 client 的註冊決定**（見第 5 節）。`client_credentials` 不用於瀏覽器登入的人類使用者。

---

## 2. 端點

| 端點 | URL | 用途 |
| --- | --- | --- |
| Authorization | `https://sso.pg72.tw/oauth2/authorize` | 啟動 Authorization Code flow（瀏覽器導向） |
| Token | `https://sso.pg72.tw/oauth2/token` | 以 code 換 token、refresh token 換發 |
| UserInfo | `https://sso.pg72.tw/oauth2/userinfo` | 用 access token 取得使用者 claims |
| JWKS | `https://sso.pg72.tw/.well-known/jwks.json` | ID token 簽章公鑰（EdDSA） |
| Introspection | `https://sso.pg72.tw/oauth2/introspect` | 查詢 access/refresh token 是否有效 |
| Revocation | `https://sso.pg72.tw/oauth2/revoke` | 撤銷 access/refresh token |
| End Session | `https://sso.pg72.tw/oauth2/end-session` | RP-initiated logout（需 client 開啟 `enableEndSession`） |

Google 社群登入的 callback（`https://sso.pg72.tw/callback/google`）是 **PGID 內部**與 Google 之間的路徑，RP 不會用到，也不應設定為自己的 redirect URI。

---

## 3. Scopes 與 Claims

支援 scopes：`openid`、`profile`、`email`、`offline_access`。任何授權請求必須包含 `openid`。

| Scope | 產生的 claims / 效果 |
| --- | --- |
| `openid` | `sub`（不可變使用者主鍵）、`iss`、`aud`、`exp`、`iat`、`auth_time`、`nonce`、`sid`。**必填**。 |
| `profile` | `name`、`picture` 等標準 profile claims。 |
| `email` | `email`、`email_verified`。 |
| `offline_access` | 核准後才會發 refresh token。未帶此 scope 不發 refresh token。 |

自訂 claim（一律有 namespace）：

| Claim | 說明 | 出現位置 |
| --- | --- | --- |
| `https://pg72.tw/role` | 平台角色：`bootadmin` / `admin` / `developer` / `user`。 | ID token 與 UserInfo |

`https://pg72.tw/role` 是**平台**角色，代表在 PGID 本身的權限，**不等於**你服務內的 app 角色。各服務的業務授權（例如 `link:admin`、`status:operator`）由服務自行維護，不要把平台 `role` claim 當成你服務的管理權限來源。

### email_verified 檢查（必做）

PGID 在建立帳號時已強制 Google 回傳 `email_verified`（否則拒絕，`EMAIL_NOT_VERIFIED`）。但 RP 若要用 email 做一次性 legacy binding，**仍須自行檢查 `email_verified === true`**，且只在綁定當下使用；日常識別一律用不可變的 `sub`。Email 可被使用者變更，不可作為 foreign key 或永久主鍵。

---

## 4. 安全參數與 token 壽命

### 4.1 強制條件

- **PKCE S256 必需**：所有 Authorization Code flow 都要帶 `code_challenge` + `code_challenge_method=S256`。`plain` 與無 PKCE 會被拒絕（`code_challenge_methods_supported` 只有 `S256`）。
- **redirect URI 精確比對**：完整字串比對，production 只允許 HTTPS，不允許 wildcard、port 或 path 差異。本機開發 callback 要註冊成獨立 development client。
- **state 與 nonce 必用**：RP 必須產生並驗證 `state`（CSRF / mix-up 防護）與 `nonce`（ID token replay 防護）。
- **issuer / audience 驗證**：驗 ID token 的 `iss` 必為 `https://sso.pg72.tw`，`aud` 必為你的 `client_id`。
- **`iss` 回傳參數**：authorization response 會帶 `iss`（`authorization_response_iss_parameter_supported: true`），client library 應驗證它以防 mix-up。
- **Authorization code 單次使用**：60 秒過期、重放會被拒絕。
- **Consent 不可略過**：每個 client（含第一方）首次授權或請求新 scope 時，使用者一定會看到 PGID consent 畫面，無法跳過。
- **RFC 8707 `resource` 參數被拒絕**：Worker 邊界會拒絕 `/oauth2/authorize` 與 `/oauth2/token` 的所有 `resource` 參數（補償控制，見 [`SECURITY.md`](../../SECURITY.md)），回 `invalid_target`。不要送 `resource`。

### 4.2 Token 壽命（對照 `auth.ts`）

| 項目 | 值 | 備註 |
| --- | --- | --- |
| Authorization code | 60 秒、單次使用 | `codeExpiresIn` |
| Access token | 15 分鐘 | opaque，前綴 `pg72_at_`；用於 UserInfo / introspection |
| ID token | 10 分鐘 | EdDSA JWT |
| Refresh token | 30 天、rotation | 前綴 `pg72_rt_`；需核准 `offline_access` |
| JWT `aud` | `https://api.pg72.tw` | 單一 audience |
| Role claim | `https://pg72.tw/role` | ID token + UserInfo |

Access token 是 **opaque**（非 JWT），要判斷有效性請用 introspection 或呼叫 UserInfo；不要嘗試在本地解析 access token。ID token 是 EdDSA 簽章 JWT，用 JWKS 驗章。

---

## 5. Client 契約

### 5.1 Client 由管理員 / developer 建立（無 dynamic registration）

Dynamic client registration **關閉**。Client、redirect URI、scopes、grant types 由 PGID 管理員或具 `developer`/`clients.manage` 權限者透過受驗證的 admin API 明確建立。RP 不能自助註冊。

Client 建立時的實際契約（對照 `apps/sso/worker/admin-clients.ts`）：

| 欄位 | 規則 |
| --- | --- |
| `redirectUris` | 至少一個；每個都要通過精確 HTTPS 比對（production）；不可重複。 |
| `scopes` | 預設 `["openid","profile","email"]`；只能是允許集合；必含 `openid`。 |
| `grantTypes` | 預設 `["authorization_code"]`；必含 `authorization_code`。含 `refresh_token` 時 scopes 必含 `offline_access`（否則 `refresh_token_requires_offline_access`）。 |
| `public` | `true` = public client（無 secret，`token_endpoint_auth_method: none`）；`false` = confidential（發一次性 secret）。 |
| `tokenEndpointAuthMethod` | 由 `public` 推導：public → `none`；confidential → `client_secret_post`。 |
| `enableEndSession` | 是否啟用 `end_session_endpoint`。 |
| `tos` / `policy` | consent 畫面顯示的服務條款 / 隱私權連結。 |
| `developerName` | consent 畫面顯示的開發者身分。 |

Client secret 為 `pg72_cs_<suffix>` 格式，**只在建立時回傳一次**，資料庫只存 hash。遺失只能重新輪替。

所有 client mutation（建立、trust metadata 更新、secret rotation、停用 / 啟用、刪除與 system-client provisioning）都必須使用有效的登入 session cookie，且請求的 `Origin` 必須精確等於 PGID 的 `AUTH_BASE_URL`；mutation 缺少 `Origin` 或來源不符時回 `403 {"error":"invalid_origin"}`。這些操作也要求 session 的 `createdAt` 距目前時間小於 10 分鐘；過期或未來時間都回精確的 `403 {"code":"SESSION_NOT_FRESH","error":"fresh_session_required"}`。

此處的 fresh 只代表 session age gate，**不等於**使用者剛重新登入或完成 Passkey 驗證。高風險 client 操作的 Passkey step-up 尚未實作，仍是 production cutover 前必須關閉的安全欠項。

### 5.2 Client 類型

| 類型 | 認證 | 用途 |
| --- | --- | --- |
| Confidential Web App | Authorization Code + PKCE S256 + client secret | 有安全後端可保存 secret 的第一方 Web 服務（Copy、Link…） |
| Public / Native | Authorization Code + PKCE S256，**無** secret（`none`） | 純瀏覽器 / 原生 app，無法保存 secret（如本機 test RP） |

即使是 confidential client 也必須用 PKCE（`requirePKCE = 1`）。

### 5.3 Client 認證方式（重要）

**建議一律使用 `client_secret_post`**：把 `client_id` 與 `client_secret` 放進 token 請求的 `application/x-www-form-urlencoded` body。

原因與坑：現行 `@better-auth/oauth-provider@1.6.23` 對 HTTP **Basic** authorization header 的 client credential 不會執行 RFC 6749 要求的 form URL decode；`oauth4webapi` 等標準 client 會先編碼 `-`、`_` 等字元，因此可能導致 `invalid_client`。所以：

- **要用 `client_secret_post`**（credential 在 form body）。
- **避免 `client_secret_basic`**（`Authorization: Basic ...`）。若你的 library 預設用 Basic，請顯式切成 post。
- PGID token endpoint discovery 只宣告 `none` 與 `client_secret_post`；introspection 只宣告 `client_secret_post`；revocation 宣告 `none` 與 `client_secret_post`，讓 public client 能以 `client_id` 撤銷自己的 token。Pinned provider 的 token endpoint runtime 仍接受 legacy raw Basic 請求，但不對外宣告；introspection 的 Worker preflight 會拒絕 `Authorization` header。在上游 percent-decode 問題修正並通過 regression 前，不把 Basic 當成 PGID 支援契約。

`oauth4webapi` 對應寫法：confidential 用 `oauth.ClientSecretPost(secret)`，public 用 `oauth.None()`（見第 8 節）。

### 5.4 Mail introspection system client

這是 Mail Path A 的固定基礎設施契約，不是一般 RP 可申請的 cross-client 權限。一般 client 仍只能 introspect 自己的 token；唯一例外是：

```text
introspection client: pgid-mail-introspect
token audience/client: pg72-webmail
token kind: opaque access token (pg72_at_...)
```

三項必須同時精確相符。JWT（包含 ID token 與任何已簽章 access token）、refresh token、簽給其他 client 的 opaque access token，以及由其他 introspection client 提交的 token，都不會取得 delegated 結果。`token_type_hint` 只改變 access/refresh 的查詢順序；即使 hint 猜錯，provider 仍會嘗試另一種 token，但不會因此放寬上述授權。

即使配對相符，active 結果仍要求 token：

- 尚未過期或撤銷，且 `pg72-webmail` client 仍為 enabled；
- 保留可驗證、未過期的 central session；session 被撤銷、刪除或與 token 脫鉤時 fail closed；
- 含 `email` scope；
- 對應到目前存在且 `status=active` 的 user；
- user 的 email 非空且 `emailVerified=true`。

任一條件不成立都只回 inactive，不透露是哪一項失敗。此 verified email 只供 Dovecot 對應既有 mailbox username，不是 PGID 或其他 RP 的身分主鍵。

#### 5.4.1 Provisioning 與 secret

此 service client 不能走一般 client 建立流程。具 `clients.manage_all` 權限的管理員使用 `POST /api/admin/clients/provision-mail-introspector` 建立它；請求還必須帶有效的 PGID session cookie、精確等於 `AUTH_BASE_URL` 的 `Origin`，而且 session 的 `createdAt` 必須是過去 10 分鐘內。端點沒有 request 欄位，應送空 body；在 4 KiB admin body 上限內，即使送了 body 也不會拿來設定 client。

成功回 `201` 與只顯示一次的 `clientSecret`；已存在時回 `409 {"error":"client_exists"}`。明文 secret 不寫入資料庫，資料庫只存 suffix 的 hash。Client 為 unowned system service client，沒有 redirect URI、scope 或可簽發 token 的 OAuth grant；內部 `urn:pg72:grant-type:introspection-only` sentinel 只用來防止 provider 套用預設 grant，不能拿來換 token 或走 authorize。

`pgid-mail-introspect` 與 `pg72-webmail` 都是 system-reserved client ID，developer 不能 claim。Provision、secret rotation、停用與刪除都要求 `clients.manage_all` 與上述 cookie / Origin / fresh-session gate。10 分鐘 session age gate **不等於**重新認證；高風險操作的 Passkey step-up 尚未實作，是 production cutover 前必須關閉的安全欠項。

目前 repository 的 local source 已實作此行為並通過本地完整 regression gate；production 尚未部署它，也尚未 provision `pgid-mail-introspect`。不要把下列 local contract 解讀成已上線狀態。

#### 5.4.2 Introspection request

只接受 `POST`、`Content-Type: application/x-www-form-urlencoded`，完整 body 上限為 4096 bytes。Client credentials 必須用 `client_secret_post` 放在 form body；任何 `Authorization` header（包含 Basic）都會被拒絕。

以下是單行 form body 範本；大寫項目是 placeholder，必須以 form URL encoding 代入 secret store 的 `PGID_MAIL_INTROSPECTION_CLIENT_SECRET` 與 Webmail 收到的 access token。範例不含任何 secret 或 token 值：

```http
POST /oauth2/introspect HTTP/1.1
Host: sso.pg72.tw
Content-Type: application/x-www-form-urlencoded

client_id=pgid-mail-introspect&client_secret=URL_ENCODED_SECRET_FROM_PGID_MAIL_INTROSPECTION_CLIENT_SECRET&token=URL_ENCODED_WEBMAIL_OPAQUE_ACCESS_TOKEN&token_type_hint=access_token
```

`client_id`、`client_secret`、`token`、`token_type_hint` 是四個 single-value 欄位；其中任何一個重複出現都回 `400 invalid_request`。`token_type_hint` 可省略；提供時只作查詢順序提示，不是型別斷言。不要把 secret 或 token 寫進 URL、log、issue、commit 或聊天。

#### 5.4.3 Introspection response

授權且有效時回 HTTP `200`。Mail response 使用欄位 allowlist：必有 `active`、`client_id`、`scope`、`email`、`email_verified`，並只在 provider 有值時加入 `iss`、`exp`、`iat`。不會回 `sub`、`sid` 或 `token_type`，也不應由 caller 推導或依賴這些欄位。

```json
{
  "active": true,
  "client_id": "pg72-webmail",
  "scope": "openid email",
  "iss": "https://sso.pg72.tw",
  "exp": 1800000000,
  "iat": 1799999100,
  "email": "verified-user@example.invalid",
  "email_verified": true
}
```

已成功認證的 caller 遇到未知、過期、撤銷、無權查看或不符合 Mail 條件的 token 時，一律回 HTTP `200` 與精確內容：

```json
{"active":false}
```

這也包含 malformed JWT、缺少或找不到 `kid` 的 JWT、簽章 / claim 驗證失敗、ID token、其他 signed JWT 與 refresh token。這些都是由輸入 token 控制的 inactive 情況；JWKS 損毀、同一 `kid` 對到多把 key 或內部 dependency failure 則仍是 server error，caller 必須 fail closed。

所有 introspection JSON response 都帶 `Cache-Control: no-store` 與 `Pragma: no-cache`。Dedicated IP limiter 先於 body 與協議解析執行；通過 body size 與足以判定 client class 的 form preflight 後，client-class / IP limiter 會在 duplicate-field rejection 與 provider validation 前執行。因此 limiter 的 `429` / `503` 可能先於部分 protocol error。Local `wrangler.jsonc` 目前的兩層上限分別是每 IP 每分鐘 1200 次，以及每個 `mail` / `other` client class + IP 每分鐘 600 次；Cloudflare rate-limit binding 是防濫用控制，不應被 caller 當成精確的 distributed quota。

其餘狀態契約如下：

| HTTP | JSON `error` / 意義 | Caller 行為 |
| --- | --- | --- |
| `200` | 上述 active allowlist 或精確 `{"active":false}` | 只有 `active === true` 才接受；其餘拒絕登入。 |
| `400` | `invalid_request` | 修正 request/form 欄位驗證、malformed form、Authorization header、重複 single-value 欄位或不合法 hint；不要帶原 request 到 log。 |
| `401` | `invalid_client` | Secret 錯誤、client 不存在或 disabled；拒絕請求並由 operator 檢查 credential / client 狀態。 |
| `405` | `invalid_request` | 改用 `POST`。 |
| `413` | `invalid_request` | Body 超過 4096 bytes；拒絕，不要截斷 token 後重送。 |
| `415` | `invalid_request` | 改用 `application/x-www-form-urlencoded` media type（可帶合法 media-type 參數）。 |
| `429` | `rate_limited` | Fail closed，使用有上限且帶 jitter 的 backoff；不可把它當 inactive cache。 |
| `503` | `temporarily_unavailable` | Dedicated limiter binding 無法判定；fail closed 並短暫重試。 |

更精簡的 operator / developer 導覽見 [`wiki/developers/mail-introspection.md`](../../wiki/developers/mail-introspection.md)。

---

## 6. 完整 Authorization Code + PKCE 流程

```text
1. RP 產生 state、nonce、code_verifier，計算 code_challenge = S256(code_verifier)
2. RP 把 state / nonce / code_verifier 存在 server 端（D1 / session），瀏覽器只拿到 HttpOnly 交易 cookie
3. 導向 authorization_endpoint，帶 client_id / redirect_uri / response_type=code
   / scope / code_challenge / code_challenge_method=S256 / state / nonce
4. 使用者在 PGID 完成 Google 或 Passkey 登入，並在 consent 畫面核准
5. PGID 302 回 redirect_uri，帶 code / state / iss
6. RP 驗 state 與 iss，取回對應交易，標記交易已消耗（防重放）
7. RP 在後端呼叫 token_endpoint：grant_type=authorization_code、code、
   redirect_uri、code_verifier，並以 client_secret_post 帶 client 認證（confidential）
8. RP 驗 ID token 簽章（JWKS/EdDSA）、iss、aud、exp、nonce
9. RP 用 access token 呼叫 userinfo_endpoint，檢查 email_verified
10. RP 以 sub 對應本機帳號，建立自己的 server-side session（保存 sid、sub），
    token 不進 localStorage
```

授權請求範例（換行僅為易讀）：

```text
https://sso.pg72.tw/oauth2/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &code_challenge=BASE64URL_S256_OF_VERIFIER
  &code_challenge_method=S256
  &state=RANDOM_STATE
  &nonce=RANDOM_NONCE
```

Token 請求範例（`client_secret_post`）：

```http
POST /oauth2/token HTTP/1.1
Host: sso.pg72.tw
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=RECEIVED_CODE
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
&code_verifier=ORIGINAL_CODE_VERIFIER
&client_id=YOUR_CLIENT_ID
&client_secret=pg72_cs_XXXXXXXX
```

Refresh 請求範例：

```http
POST /oauth2/token HTTP/1.1
Host: sso.pg72.tw
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=pg72_rt_XXXXXXXX
&client_id=YOUR_CLIENT_ID
&client_secret=pg72_cs_XXXXXXXX
```

Refresh token 會 rotation：每次換發可能回傳新的 refresh token，RP 必須改存新值並丟棄舊值；偵測到舊 token 重用應視為異常。

---

## 7. 錯誤處理

- Authorization 端點錯誤：以 OAuth 標準 `error` / `error_description` 回到 redirect_uri（例如使用者取消為 `access_denied`）。RP 應優雅顯示，不要把原始錯誤丟給使用者。
- Token 端點錯誤：標準 JSON，如 `invalid_grant`（code 過期 / 已用 / redirect 不符）、`invalid_client`（client 認證失敗）、`invalid_request`。
- 送了 `resource` 參數：`400 invalid_target`（PGID 刻意拒絕，見 4.1）。
- Rate limit：敏感 auth 端點有 per-IP 限流，超過回 `429 rate_limited`。
- 一般原則：RP 的錯誤訊息不得洩漏帳號是否存在、token 狀態或內部例外；記 log 時遮蔽 token、code、完整 email/IP。
- 交易安全：`state` 不符、交易過期或重放一律中止 flow 並要求重新登入，不要沿用舊交易。

---

## 8. 串接範例 A：`oauth4webapi`（BFF，對照 test RP / Link）

`apps/test-rp/worker/index.ts` 是可運作的 public client 範例。以下擷取關鍵段落並標註 confidential client 的差異。

### 8.1 Client 與 discovery

```ts
import * as oauth from "oauth4webapi";

const issuer = new URL("https://sso.pg72.tw");

// Public client（無 secret）
const client: oauth.Client = {
  client_id: env.OIDC_CLIENT_ID,
  token_endpoint_auth_method: "none",
  id_token_signed_response_alg: "EdDSA",
};

// Confidential client 改為：
// const client: oauth.Client = {
//   client_id: env.OIDC_CLIENT_ID,
//   id_token_signed_response_alg: "EdDSA",
// };
// 並在 token 請求用 clientAuth = oauth.ClientSecretPost(env.OIDC_CLIENT_SECRET)

const as = await oauth.processDiscoveryResponse(
  issuer,
  await oauth.discoveryRequest(issuer, { algorithm: "oidc" }),
);
```

### 8.2 發起授權（產生並保存 state / nonce / PKCE）

```ts
const state = oauth.generateRandomState();
const nonce = oauth.generateRandomNonce();
const codeVerifier = oauth.generateRandomCodeVerifier();
const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);

// 把 state / nonce / codeVerifier 存 server 端（D1），瀏覽器只給 HttpOnly 交易 cookie
await saveTransaction({ state, nonce, codeVerifier, redirectUri });

const authUrl = new URL(as.authorization_endpoint!);
authUrl.searchParams.set("client_id", client.client_id);
authUrl.searchParams.set("redirect_uri", redirectUri);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("scope", "openid profile email offline_access");
authUrl.searchParams.set("code_challenge", codeChallenge);
authUrl.searchParams.set("code_challenge_method", "S256");
authUrl.searchParams.set("state", state);
authUrl.searchParams.set("nonce", nonce);
return Response.redirect(authUrl.href, 302);
```

### 8.3 Callback：驗 state、換 token、驗 ID token、取 UserInfo

```ts
const tx = await loadAndConsumeTransaction(transactionId); // 一次性，重放即拒絕

// 驗 state 與 authorization response（含 iss 檢查）
const params = oauth.validateAuthResponse(as, client, new URL(request.url), tx.state);

// Public client 用 oauth.None()；confidential client 用 oauth.ClientSecretPost(secret)
const clientAuth = oauth.None(); // confidential: oauth.ClientSecretPost(env.OIDC_CLIENT_SECRET)

const tokenResponse = await oauth.authorizationCodeGrantRequest(
  as, client, clientAuth, params, tx.redirectUri, tx.codeVerifier,
);

const tokens = await oauth.processAuthorizationCodeResponse(
  as, client, tokenResponse,
  { expectedNonce: tx.nonce, requireIdToken: true }, // 驗 nonce
);
await oauth.validateApplicationLevelSignature(as, tokenResponse); // 驗 ID token 簽章

const claims = oauth.getValidatedIdTokenClaims(tokens);
if (!claims) throw new Error("missing id token claims");
// claims.sub, claims.sid, claims["https://pg72.tw/role"] 可用

const userInfo = await oauth.processUserInfoResponse(
  as, client, claims.sub,
  await oauth.userInfoRequest(as, client, tokens.access_token),
);

// email_verified 檢查（若要用 email 做一次性綁定）
if (userInfo.email && userInfo.email_verified !== true) {
  throw new Error("email not verified");
}

// 以 sub 對應本機帳號，建立自己的 server-side session（存 sid + sub）
await createLocalSession({
  subject: claims.sub,
  sid: typeof claims.sid === "string" ? claims.sid : null,
  email: typeof userInfo.email === "string" ? userInfo.email : null,
});
```

重點：`oauth4webapi` 內建 issuer / audience / nonce / signature / PKCE 驗證，請用它提供的 `validateAuthResponse`、`processAuthorizationCodeResponse`、`validateApplicationLevelSignature`，不要自己手寫 JWT 驗證。

---

## 9. 串接範例 B：通用步驟版（任何語言 / library）

適用於用其他 OIDC library（如 `openid-client`、Authlib、各語言 SDK）的服務。

1. **抓 discovery**：`GET https://sso.pg72.tw/.well-known/openid-configuration`，取出各端點與 `jwks_uri`。
2. **設定 client**：`client_id`、`redirect_uri`（精確 HTTPS）、`scope=openid profile email offline_access`。confidential 另設 `client_secret`，token 端點認證選 **`client_secret_post`**。
3. **產生並保存**：`state`、`nonce`、`code_verifier`；計算 `code_challenge = BASE64URL(SHA256(code_verifier))`。存在 server 端 session。
4. **導向 authorization endpoint**：帶第 6 節的所有參數（含 `code_challenge_method=S256`）。
5. **接收 callback**：驗 `state` 與 `iss`；用一次性交易紀錄防重放。
6. **換 token**：`POST /oauth2/token`，`grant_type=authorization_code` + `code` + `redirect_uri` + `code_verifier`，confidential 以 form body 帶 `client_id` / `client_secret`。
7. **驗 ID token**：用 `jwks_uri` 的 EdDSA 公鑰驗章，並檢查 `iss = https://sso.pg72.tw`、`aud = client_id`、`exp` 未過、`nonce` 相符。
8. **取 UserInfo**：`GET /oauth2/userinfo`，`Authorization: Bearer <access_token>`。檢查 `email_verified`。
9. **建立本機 session**：以 `sub` 對應帳號，保存 `sid` + `sub`；token 存 server 端，不進 `localStorage` 或可被 JS 讀取的 cookie。
10. **登出**：本機登出清自己 session；若要跨服務登出，日後接中央 `sid` 與 back-channel logout（見 `codex.md` §11）。啟用 `enableEndSession` 的 client 可用 `end_session_endpoint` 做 RP-initiated logout。

### Introspection / Revocation（選用）

- Introspection：`POST /oauth2/introspect`，`application/x-www-form-urlencoded` body 帶 `client_id`、`client_secret` 與 `token`（`client_secret_post`）；body 上限 4 KiB，不接受 Basic 或 GET。`client_id`、`client_secret`、`token`、`token_type_hint` 這四個單值欄位各自出現超過一次時會拒絕；不要把此規則解讀成所有擴充欄位都禁止重複。`token_type_hint` 只是查詢順序提示，猜錯時仍會查另一種 token。
- 已成功認證的 caller 查詢無效、過期、撤銷或無權查看的 token 時，回 HTTP `200` 與精確的 `{"active":false}`，不洩漏原因。錯誤 client credential 回 `401 invalid_client`；協議錯誤回 `400`/`405`/`413`/`415`；限流與 limiter failure 分別回 `429`/`503`。
- Mail Path A 還要求 access token 有 live central session、`email` scope，且目前 user 存在、為 `active`、`emailVerified=true`。成功回應只保留 `active`、`client_id`、`scope`、`iss`、`exp`、`iat`、`email`、`email_verified`，刻意不回 `sub` 或 `sid`。Email 只用於 Dovecot 既有 mailbox username 映射，不成為 PGID 或其他 RP 的身分主鍵。
- Revocation：`POST /oauth2/revoke`，帶 token 與 client 認證。撤銷後該 token 不可再用。

---

## 10. 整合檢查清單

- [ ] Client 由管理員 / developer 透過 admin API 建立，redirect URI 精確 HTTPS。
- [ ] 授權請求帶 `code_challenge_method=S256`、`state`、`nonce`。
- [ ] Callback 驗 `state`、`iss`，交易一次性防重放。
- [ ] Token 交換在後端進行；confidential 用 `client_secret_post`（**不用 Basic**）。
- [ ] ID token 驗 `iss` / `aud` / `exp` / `nonce` 與 EdDSA 簽章。
- [ ] UserInfo 檢查 `email_verified`；以 `sub`（非 email）識別使用者。
- [ ] 不送 `resource` 參數。
- [ ] Server-side session 保存 `sid` + `sub`；token 不進 `localStorage`。
- [ ] 錯誤訊息不洩漏帳號存在與否；log 遮蔽 token / code / 完整 email / IP。
- [ ] 規劃冪等 back-channel logout endpoint（Phase 2 契約，見 `codex.md` §11.2）。

---

## 11. 參考

- 架構規格：[`codex.md`](../../codex.md)（單一事實來源）
- 安全政策與已接受 finding：[`SECURITY.md`](../../SECURITY.md)
- 使用者 / 開發者教學站：[`wiki/`](../../wiki/SUMMARY.md)
- 可運作 RP 範例：`apps/test-rp/worker/index.ts`
- Better Auth OAuth Provider：<https://better-auth.com/docs/plugins/oauth-provider/>
- `oauth4webapi`：<https://github.com/panva/oauth4webapi>
