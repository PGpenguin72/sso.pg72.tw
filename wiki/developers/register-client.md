# 建立 OAuth Client

PGID **不開放動態自助註冊**。每個 client 由 standard access 的 PGID 管理員或具 `developer` 權限的開發者透過受驗證的 admin 操作明確建立。Restricted account 即使 session 中有 stale role 也會被 server 重新讀取 D1 後拒絕，且不能新建或接管 client；restrict 不會自動停用既有 owned RP。Production 目前仍是 invite-only，restricted path 尚未部署。這一頁說明你要提供哪些資訊，以及建立後會拿到什麼。

## 建立 client 前要決定的事

| 項目 | 說明 |
| --- | --- |
| Client 名稱 | 顯示在使用者的 consent 授權畫面上。 |
| 開發者名稱（`developerName`） | 顯示在 consent 畫面，讓使用者知道是誰做的。 |
| Redirect URI | 你的 callback 網址。production 必須是精確的 HTTPS URL，不允許 wildcard。可有多個。 |
| 是 public 還是 confidential | 有安全後端可保存 secret → confidential；純瀏覽器 / 原生 app → public（無 secret）。 |
| Scopes | 預設 `openid profile email`；要 refresh token 就加 `offline_access`。必含 `openid`。 |
| Grant types | 預設 `authorization_code`；要長期登入就加 `refresh_token`（此時 scopes 必含 `offline_access`）。 |
| 服務條款 / 隱私權連結 | 顯示在 consent 畫面。 |
| 是否啟用 end-session | 若你要用 RP-initiated logout 端點。所有 user ID token 都會帶 central `sid`；此設定只控制端點權限。 |
| Back-channel logout URI | 選填的精確 receiver endpoint。Production 必須 HTTPS，不接受 wildcard、fragment 或任何 `@`；development HTTP loopback 必須含 port。需依 [Back-Channel Logout](backchannel-logout.md) 驗證並依 `sid` 冪等刪除本機 session。 |

## 建立後你會拿到

* `client_id`
* confidential client 會拿到**一次性**的 `client_secret`（格式 `pg72_cs_...`）——只顯示一次，資料庫只存 hash。請立刻存進你後端的 secret 儲存（例如 Wrangler secrets），遺失只能重新輪替。
* confidential client 固定登記為 `client_secret_post`；RP 必須在後端以 form body 傳送 client credentials。
* public client 沒有 secret。

建立、更新、輪替 secret、停用 / 啟用或刪除 client 都是同源 admin mutation：請求必須帶有效的 PGID session cookie，且 `Origin` 必須精確等於 PGID 的 `AUTH_BASE_URL`。這些操作只接受 `createdAt` 距目前時間小於 10 分鐘的 session；不符合時固定回 `403` 與 `{"code":"SESSION_NOT_FRESH","error":"fresh_session_required"}`。

Local source 還要求同一個 D1 session 最近完成 Passkey step-up。帳號中心會在 mutation 前啟動原生 Passkey 驗證；取消或驗證失敗時不會送出原操作。10 分鐘 session age 只是額外 gate，不能替代 step-up。沒有 Passkey 時不提供 bypass，包含 `bootadmin`；先用既有 Google fresh session 註冊 Passkey，再操作 client。Local recovery-code flow 只能替換 Passkey，完成後仍須一般登入；它不會寫入 step-up timestamp 或授權 client mutation。Production 尚未套用 `0019` 或啟用 recovery。

Step-up 使用同源的 `POST /api/account/passkey-step-up/challenge` 與 `POST /api/account/passkey-step-up/verify`。Challenge 兩分鐘內有效、只能使用一次，並綁定目前的 user 與 D1 session；WebAuthn 必須完成 user verification。Step-up 有效期只能設定為 60–600 秒，目前為 600 秒。沒有 Passkey 時回 `PASSKEY_ENROLLMENT_REQUIRED`；未完成或已過期時，client mutation 回 `PASSKEY_STEP_UP_REQUIRED`。Production 尚未套用 `0014` 或部署此行為。

## 本機開發

本機 callback（例如 `http://localhost:5174/callback`）要註冊成**獨立的 development client**，不要把本機網址混進 production client 的 redirect URI。

## 設定範例（放你服務的環境變數 / secret）

```text
OIDC_ISSUER=https://sso.pg72.tw
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=pg72_cs_xxxxxxxx   # 僅 confidential，放 secret 儲存，勿進原始碼
OIDC_REDIRECT_URI=https://app.example.com/callback
OIDC_SCOPE=openid profile email offline_access
OIDC_BACKCHANNEL_LOGOUT_URI=https://app.example.com/backchannel-logout
```

## Client 認證方式（重要）

confidential client 換 token 時，請把 `client_id` / `client_secret` 放在 **token 請求的 form body**（`client_secret_post`），**不要**用 HTTP Basic header。現行 OAuth provider 版本對 Basic header 的 client credential 處理與標準不相容，可能導致認證失敗。實作方式見 [跑通 OIDC 登入流程](oidc-flow.md) 的 confidential client token exchange。

## System-reserved clients

`pg72-webmail` 與 `pgid-mail-introspect` 是 PGID 保留的 system client ID，developer 不能建立或接管。`pgid-mail-introspect` 是無登入 grant 的 unowned service client，只能由 `clients.manage_all` 管理員透過專用 provisioning 操作建立；該端點應送空 body，secret 只顯示一次且資料庫只存 hash。它只能 introspect `pg72-webmail` 的 opaque access token，不能查其他 client、JWT 或 refresh token，也不能自行取得 token。完整操作方式、wire contract 與 fail-closed response handling 見 [Mail Token Introspection](mail-introspection.md)。

## 下一步

[跑通 OIDC 登入流程](oidc-flow.md)
