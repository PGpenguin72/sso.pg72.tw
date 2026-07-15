---
description: PGID 使用者與開發者教學站，wiki.sso.pg72.tw 的內容源。
---

# 認識 PGID

歡迎使用 **PGID**——PG72 自己掌控的單一登入（SSO）身分系統。用一個帳號登入所有 PG72 服務，日常以 Google 與 Passkey（無密碼）登入，並在一個地方管理你的裝置、授權與安全紀錄。

> Issuer：`https://sso.pg72.tw`
> 這是**教學站**。若你要找端點與參數的精簡技術參考，請看 [PGID 串接 API 手冊](../docs/api/PGID-integration.md)。

## 這個 Wiki 有什麼

### 給一般使用者

* [開始使用：註冊與登入](users/getting-started.md)——第一次使用 PGID。
* [用 Google 登入](users/google-login.md)——用 Google 帳號登入。
* [設定與使用 Passkey](users/passkey.md)——無密碼登入的設定與管理。
* [帳號管理與安全](users/account-management.md)——裝置 session、已授權應用、撤銷與帳號刪除。

### 給開發者

* [串接總覽](developers/overview.md)——把服務接上 PGID 的整體圖像。
* [建立 OAuth Client](developers/register-client.md)——從申請 client 到拿到設定值。
* [跑通 OIDC 登入流程](developers/oidc-flow.md)——Authorization Code + PKCE 全流程。
* [Consent 與 Scopes](developers/consent-and-scopes.md)——授權畫面與 scope / claim。
* [社群登入說明](developers/social-login.md)——PGID 與 Google 的關係。

### 其他

* [常見問題 FAQ](faq.md)
* [聯絡我們](contact.md)——`contact@pg72.tw`

## PGID 的核心理念

* **統一身分**：所有服務用同一個不可變帳號 ID（`sub`）認得你。
* **無密碼優先**：日常登入用 Google 與 Passkey，沒有密碼可被外洩。
* **你掌控**：隨時查看與撤銷任一裝置的登入、撤銷已授權的應用程式。
* **隱私**：Email 不是主鍵、最小授權、由 PG72 自行營運。

更完整的介紹見 [認識 PGID（介紹文）](../docs/about-PGID.md)。
