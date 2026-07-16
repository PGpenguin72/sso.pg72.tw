# Mail Token Introspection

這一頁給維護 PG72 Webmail / Dovecot 的 operator 與串接者。它描述固定的 Mail Path A trust relationship，不是一般 OAuth client 可申請的功能。精確 wire contract 與完整狀態表見 [PGID 串接 API 手冊 §5.4](../../docs/api/PGID-integration.md#54-mail-introspection-system-client)。

> 狀態：repository 的 local source 已實作 introspection 與真正的 Passkey step-up，並通過本地 regression gate；production 尚未套用 `0013`/`0014`、部署、完成獨立 review，或 provision `pgid-mail-introspect`。

## 固定的 trust boundary

只有 `pgid-mail-introspect` 可以跨 client 檢查 `pg72-webmail` 的 opaque access token。兩個 client ID 與 token kind 都是固定值：

| 角色 | 固定值 |
| --- | --- |
| Introspection service client | `pgid-mail-introspect` |
| Token-owning client | `pg72-webmail` |
| 可 delegated 的 token | `pg72_at_...` opaque access token |

一般 client 只能 introspect 自己的 token。Mail service client 不會取得 JWT、ID token、refresh token、其他 client token 的內容，也不能用自己的 credential 簽發 token 或啟動登入流程。

Active 還要求 access token 未過期 / 未撤銷、webmail client enabled、central session 仍存在且未過期、含 `email` scope，以及目前 user 為 active 且 email 已驗證。任一條件失敗只會得到 `{"active":false}`，不會知道原因。

## Operator provisioning contract

固定 endpoint 是 `POST /api/admin/clients/provision-mail-introspector`。只有 `clients.manage_all` actor 可以使用，而且請求必須同時具備：

* 有效的 PGID session cookie；
* `Origin` 精確等於 PGID `AUTH_BASE_URL`；
* session `createdAt` 在過去 10 分鐘內，不能是 stale 或 future-dated；
* 該 exact D1 session 最近完成 Passkey step-up，且 timestamp 仍在設定窗口內。

Endpoint 沒有 request 欄位，建議送空 body；在 4 KiB admin body 上限內，即使送了 body 也會被忽略，不會用來設定 client。成功回 `201`，其中 `clientSecret` 只出現一次；立即存入指定的 secret store。Repository、D1、log、issue 與聊天都不得保存明文。D1 只存 secret suffix hash。重複 provisioning 回 `409 client_exists`。

建立出的 client 是 unowned、hash-only、introspection-only 的 system service client，沒有 redirect URI、scope 或 token-issuing grant。Secret rotation、停用與刪除同樣只允許 `clients.manage_all` actor，並要求 same-origin cookie、fresh session 與 recent Passkey step-up。

10 分鐘 session age 只是 freshness gate，不能替代 Passkey assertion。沒有 Passkey 時沒有 `bootadmin` bypass；先以既有 Google fresh session 註冊 Passkey，再完成 step-up。若 Google 與所有 Passkey 都遺失，目前沒有可用的自助 recovery/break-glass flow。Production 套用 `0014`、部署、獨立 review 與實機 smoke 前，不得把此 local contract 宣稱為已上線。

## Runtime request

Introspection 只接受 form `POST`，body 最多 4096 bytes。把 `client_id` 與 `client_secret` 放進 body（`client_secret_post`）；不要送 `Authorization` / Basic header。以下是單行 form body 範本；大寫項目須經 form URL encoding 代入，範例只使用 secret 名稱而不包含值：

```http
POST /oauth2/introspect HTTP/1.1
Host: sso.pg72.tw
Content-Type: application/x-www-form-urlencoded

client_id=pgid-mail-introspect&client_secret=URL_ENCODED_SECRET_FROM_PGID_MAIL_INTROSPECTION_CLIENT_SECRET&token=URL_ENCODED_WEBMAIL_OPAQUE_ACCESS_TOKEN&token_type_hint=access_token
```

`client_id`、`client_secret`、`token` 或 `token_type_hint` 任一欄重複都會回 `400`。Hint 可省略，而且只是 access/refresh 查詢順序提示；猜錯不會授權原本不允許的 token。

Dedicated IP limiter 在 body / 協議解析前執行；通過 body size 與足以判定 client class 的 form preflight 後，client-class / IP limiter 會在 duplicate-field rejection 與 provider validation 前執行。因此 `429` 或 limiter failure 的 `503` 可能先於部分 protocol error。Local config 目前是每 IP 每分鐘 1200 次，以及每個 `mail` / `other` client class + IP 每分鐘 600 次。這是防濫用控制，不是 caller 可依賴的精確 distributed quota。

## Fail-closed response handling

Active response 的唯一可用欄位是：

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

`iss`、`exp`、`iat` 只在 provider 有值時出現；其他欄位是 active response 的必要條件。Response 刻意沒有 `sub`、`sid`、`token_type`。Mail 才能用 verified email 對應既有 mailbox username；其他服務仍必須以 `sub` 作身分主鍵。

所有無效或不授權的 token，包括 JWT 與 refresh token，都回 HTTP `200`：

```json
{"active":false}
```

Dovecot / gateway 只應在 HTTP `200` 且 `active === true`、`client_id === "pg72-webmail"`、`email_verified === true`、scope 含 `email` 時接受。`400`、`401`、`405`、`413`、`415`、`429`、`503`、其他 `5xx`、網路錯誤、JSON 解析失敗與缺欄位都必須拒絕登入。`429` 可做有上限的 jitter backoff；`503` 代表 limiter binding 無法完成 fail-closed 判斷，適合短暫重試。不要把 transport / server error 快取成 token inactive，也不要在 log 寫 token、secret 或完整 email。

## Patch 與升級 gate

目前行為依賴 exact-pinned `@better-auth/oauth-provider@1.6.23` patch。Missing / unknown `kid`、malformed JWT 與由 token 控制的 JOSE 驗證失敗會正規化為 inactive；JWKS 損毀、同 `kid` 多 key 等基礎設施問題仍保留為 server error。

升級 provider 前先讀 [`patches/README.md`](../../patches/README.md)。只有 stable upstream 完整取代 fixed-pair hook、live-session 資訊、same-client default、JWT/refresh denial、`kid` / JOSE fail-closed 分類、hint fallback 與 inactive error handling，且 frozen install 與完整 regression gate 都通過時，才能移除 patch。
