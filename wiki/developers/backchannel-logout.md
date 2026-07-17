# 實作 Back-Channel Logout

PGID 的 local source 已實作以中央 `sid` 為單位的 durable OIDC
Back-Channel Logout。這不代表 production 已上線：migration `0018`、專用
Queue/DLQ、各服務 receiver、隔離 Preview 驗收與外部告警仍須逐項完成。

## Client 設定

建立或更新 OAuth client 時，提供一個精確的 `backchannelLogoutUri`。Production
只能使用 HTTPS，不接受 wildcard、fragment、任何 `@` 或跨環境 endpoint。本機
HTTP loopback URI 必須含明確 port，且只供獨立 development client 使用。

每個 user ID token 都帶 nonempty central `sid`。RP 在 callback 驗證 ID token
後，必須把 `sid` 和不可變 `sub` 一起保存在自己的 server-side session；不要把
token 或 `sid` 放進 `localStorage`。

## Receiver 契約

Receiver 接受 `POST` 與
`application/x-www-form-urlencoded`，body 只有一個 `logout_token`。驗證時至少
要確認：

* 使用 PGID discovery 的 `jwks_uri` 驗證 EdDSA signature 與 `kid`。
* `iss` 精確等於 PGID issuer，`aud` 包含自己的 `client_id`。
* `iat` / `exp` 有效且 token 壽命不超過五分鐘；PGID 目前簽發 120 秒 lifetime。
* `events` 包含 OIDC Back-Channel Logout event URI。
* 有 nonempty `sid` 與 `jti`，而且**沒有** `nonce`。
* 同一 `jti` 重送時冪等成功；同一 `jti` 若搭配不同 `sid` 必須拒絕。

驗證成功後，在同一個後端 transaction 中記錄 `jti` 並刪除所有符合 `sid` 的
本機 sessions，然後回 HTTP `200` 或 `204`。PGID 只把這兩個狀態視為成功。
Timeout/network error、`408`、`425`、`429` 與 `5xx` 會 retry；其餘任何 HTTP
status（包含 `201`、redirect 與其他 `4xx`）都視為 permanent failure。
不要在 response、log 或 telemetry 中輸出 logout token、完整 session ID 或使用者
資料。

```text
PGID durable D1 row
        |
        v
dedicated Queue (at least once)
        |
        v
RP validates logout_token + deletes by sid
        |
        +--> 200/204: delivered
        +--> retryable failure: bounded retry
        +--> permanent/exhausted: operator review
```

Queue 可能重複或延後投遞，因此冪等不是選配。PGID 已先撤銷中央 session 與
tokens；Receiver 暫時故障不能要求恢復中央登入狀態。

## 驗收

在隔離 Preview 至少測試：有效與重複 token、錯誤 issuer/audience/signature/event、
過長 lifetime、帶 `nonce`、同 `jti` 不同 `sid`、timeout、`429`、`5xx`、永久
`4xx`，以及一個中央 session 同時登入兩個 RP 的全域撤銷。確認 receiver 只刪除
目標 `sid`，其他裝置不受影響。

完整的部署、故障演練、人工 replay 與 rollback 步驟由 repository operator
runbook `docs/runbooks/global-logout.md` 維護；它不屬於對外 wiki route。
