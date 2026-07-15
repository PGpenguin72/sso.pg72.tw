# 社群登入說明

## 你的服務不直接接 Google

一個常見誤解是「接 PGID 還要不要自己接 Google？」答案是**不用**。

PGID 是身分提供者，它**代替**你的服務處理 Google 登入與 Passkey。你的服務只接 PGID 一家（標準 OIDC），使用者選擇用 Google 還是 Passkey 登入是在 PGID 端發生的，你的服務不需要、也不應該自己再接一次 Google OAuth。

```text
你的服務(RP)  ──OIDC──▶  PGID  ──▶  Google / Passkey
```

好處：

* 你只維護一套標準 OIDC 整合。
* 你不必保管 Google client secret。
* 未來 PGID 增加登入方式時，你的服務不用改。

## PGID 端的社群登入

PGID v1 的日常登入方式是：

* **Google**：`openid email profile` 最小授權；只在 email 已驗證時建立帳號。
* **Passkey**：WebAuthn 無密碼登入，RP ID 固定為 `sso.pg72.tw`。

v1 **不提供**密碼、Email OTP、TOTP、GitHub 或 Discord 登入。

## 對你服務的意義

* 你拿到的使用者身分不分「Google 使用者」或「Passkey 使用者」——都是同一個 PGID 帳號，以同一個不可變 `sub` 呈現。
* 使用者換登入方式（例如今天用 Google、明天用 Passkey）不影響 `sub`，你對應到的還是同一個帳號。
* 你不會、也不需要拿到使用者的 Google token。

## 帳號連結

同一個 email 的帳號**不會**被 PGID 自動合併。若使用者要把新的登入方式連到現有帳號，必須在 PGID 已登入的狀態下明確操作。你的服務不需處理這件事。

## 下一步

* 精簡技術參考：[PGID 串接 API 手冊](../../docs/api/PGID-integration.md)
* [常見問題 FAQ](../faq.md)
