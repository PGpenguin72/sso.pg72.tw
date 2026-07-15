# Consent 與 Scopes

## Consent（授權畫面）不可略過

每個 client——包含第一方服務——在使用者**首次授權**或**請求新的 scope** 時，一定會看到 PGID 的 consent 授權畫面，**無法跳過**。畫面會顯示：

* 你註冊的 client 名稱與開發者身分（`developerName`）。
* 使用者將被導向的 redirect host。
* 你請求的每個 scope 與逐項說明（`offline_access` 會特別標示）。
* 服務條款 / 隱私權連結（你在建立 client 時提供）。
* 目前登入的帳號，以及「取消 / 允許」。

使用者按「取消」時，PGID 會以 `access_denied` 回你的 redirect URI。

> consent 畫面顯示的所有欄位都來自管理員寫入的 client 註冊資料，授權請求的 query 參數無法影響它——這防止某個 client 冒充另一個應用的名稱、開發者或目的地。

## 支援的 Scopes

| Scope | 意義 | 你會拿到 |
| --- | --- | --- |
| `openid` | OIDC 必填 | `sub`、`sid` 等基本 claim |
| `profile` | 基本個人資料 | `name`、`picture` |
| `email` | 電子郵件 | `email`、`email_verified` |
| `offline_access` | 長期存取 | refresh token（核准後才發） |

只請求你真正需要的 scope。要 refresh token 才加 `offline_access`。

## 你會拿到的 Claims

ID token 與 UserInfo 會包含（依 scope）：

```text
iss sub aud exp iat auth_time nonce sid
email email_verified name picture
```

自訂 claim：

| Claim | 說明 |
| --- | --- |
| `https://pg72.tw/role` | 使用者的**平台**角色（`bootadmin` / `admin` / `developer` / `user`），出現在 ID token 與 UserInfo。 |

### 重要：平台角色 ≠ 你服務的角色

`https://pg72.tw/role` 是使用者在 PGID **平台**的角色，**不代表**他在你服務裡是管理員。你服務的業務授權（例如誰能管理你服務的內容）必須由你自己維護，例如以 `sub` 對應你資料庫裡的 app 角色。不要把平台 `role` claim 當成你服務的管理權限來源，避免單一 claim 過度授權。

## 用 sub，不用 email

* `sub` 是不可變的使用者主鍵，跨所有服務一致——用它作帳號對應。
* email 可被使用者更換，只適合在綁定既有 legacy 帳號時**一次性**使用，且務必檢查 `email_verified === true`。

## 下一步

[社群登入說明](social-login.md)
