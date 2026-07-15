# 常見問題 FAQ

## 一般使用者

**Q：PGID 是什麼？**
A：PG72 自己掌控的單一登入系統。一個帳號登入所有 PG72 服務，日常用 Google 與 Passkey 登入。詳見[認識 PGID](README.md)。

**Q：我需要記密碼嗎？**
A：不需要。日常登入用 Google 或 Passkey（指紋 / 臉部 / 硬體金鑰），沒有密碼。

**Q：可以只用 Passkey，不用 Google 嗎？**
A：目前第一次建立帳號是透過 Google 登入（需已驗證 email）。建立帳號後可註冊 Passkey，之後即可用 Passkey 登入。註冊 Passkey 需要先有帳號並已登入。

**Q：我換了 Google 的 email，帳號會不見嗎？**
A：不會。識別你的是不可變的帳號 ID，不是 email。

**Q：懷疑帳號被盜怎麼辦？**
A：到帳號中心「裝置 / sessions」撤銷其他 / 所有裝置，並檢查安全紀錄。必要時[聯絡我們](contact.md)。

**Q：可以刪除帳號嗎？**
A：可以，但需要剛登入（fresh session）。Bootstrap 管理員帳號受保護不能自我刪除。刪除後重新註冊會拿到全新帳號 ID。

**Q：為什麼登入某服務時要在 PGID 按「允許」？**
A：那是授權畫面，讓你確認要把哪些基本資料提供給該服務。首次授權或請求新權限時一定會出現，無法略過。

## 開發者

**Q：我可以自己註冊 OAuth client 嗎？**
A：不行。PGID 關閉動態註冊，client 由管理員 / developer 明確建立。見[建立 OAuth Client](developers/register-client.md)。

**Q：接 PGID 還要自己接 Google 嗎？**
A：不用。PGID 代替你處理 Google 與 Passkey，你只接 PGID 一家標準 OIDC。見[社群登入說明](developers/social-login.md)。

**Q：支援哪個 flow？**
A：只有 Authorization Code + PKCE S256。ID token 用 EdDSA 簽章。

**Q：redirect URI 可以用 wildcard 嗎？**
A：不行。精確比對，production 必須 HTTPS。

**Q：client 認證要用 Basic 還是 post？**
A：用 `client_secret_post`（credential 放 token 請求的 form body）。現行 provider 對 HTTP Basic 的處理與標準不相容，避免使用。見[手冊 §5.3](../docs/api/PGID-integration.md#53-client-認證方式重要)。

**Q：我要怎麼識別使用者？**
A：用不可變的 `sub`，不要用 email。email 只適合一次性綁定既有帳號，且要檢查 `email_verified`。

**Q：`https://pg72.tw/role` 是我服務的管理權限嗎？**
A：不是。那是平台角色。你服務的業務授權要自己維護。見 [Consent 與 Scopes](developers/consent-and-scopes.md)。

**Q：為什麼我送 `resource` 參數被拒？**
A：PGID 目前刻意拒絕所有 RFC 8707 `resource` 參數（回 `invalid_target`），這是暫時的補償控制。不要送 `resource`。

**Q：怎麼拿 refresh token？**
A：client 要有 `offline_access` scope 與 `refresh_token` grant，且使用者需在 consent 核准。refresh token 會 rotation，每次換發後要改存新值。

## 還是找不到答案？

[聯絡我們](contact.md)。
