# 建立 OAuth Client

PGID **不開放動態自助註冊**。每個 client 由 PGID 管理員或具 `developer` 權限的開發者透過受驗證的 admin 操作明確建立。這一頁說明你要提供哪些資訊，以及建立後會拿到什麼。

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
| 是否啟用 end-session | 若你要用 RP-initiated logout 端點。 |

## 建立後你會拿到

* `client_id`
* confidential client 會拿到**一次性**的 `client_secret`（格式 `pg72_cs_...`）——只顯示一次，資料庫只存 hash。請立刻存進你後端的 secret 儲存（例如 Wrangler secrets），遺失只能重新輪替。
* confidential client 固定登記為 `client_secret_post`；RP 必須在後端以 form body 傳送 client credentials。
* public client 沒有 secret。

## 本機開發

本機 callback（例如 `http://localhost:5174/callback`）要註冊成**獨立的 development client**，不要把本機網址混進 production client 的 redirect URI。

## 設定範例（放你服務的環境變數 / secret）

```text
OIDC_ISSUER=https://sso.pg72.tw
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=pg72_cs_xxxxxxxx   # 僅 confidential，放 secret 儲存，勿進原始碼
OIDC_REDIRECT_URI=https://app.example.com/callback
OIDC_SCOPE=openid profile email offline_access
```

## Client 認證方式（重要）

confidential client 換 token 時，請把 `client_id` / `client_secret` 放在 **token 請求的 form body**（`client_secret_post`），**不要**用 HTTP Basic header。現行 OAuth provider 版本對 Basic header 的 client credential 處理與標準不相容，可能導致認證失敗。細節與範例見 [PGID 串接 API 手冊 §5.3](../../docs/api/PGID-integration.md#53-client-認證方式重要)。

## 下一步

[跑通 OIDC 登入流程](oidc-flow.md)
