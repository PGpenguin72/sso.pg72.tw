# 開始使用：註冊與登入

這一頁帶你完成第一次使用 PGID。

## PGID 帳號是什麼

PGID 帳號是你在已接入 PGID 的 PG72 服務間共用的身分。你不需要為每個已接入
的服務各記一組帳密；登入這些服務時都會回到 PGID 完成登入。

每個帳號有一個**不可變的帳號 ID**，這是各服務認得你的依據。你的 email 之後可以更換，但帳號 ID 不會變。

## 第一次註冊

Production 目前是 **invite-only beta**。Google email 已驗證只是必要條件，
不會繞過邀請；未受邀者目前不能自行建立帳號。第一次建立帳號的方式是：

1. 先由管理員對你的 email 建立有效邀請。
2. 前往 PGID（`https://sso.pg72.tw`）或任一已接入 PGID 的服務登入頁。
3. 選擇「用 Google 登入」，並選擇邀請所對應、email 已驗證的 Google 帳號。
4. PGID 同時確認有效邀請與 verified email 後，才會建立帳號並消耗邀請。

> 公開註冊的 local source 已加入 Turnstile 驗證、目前服務條款/隱私權政策
> 的明確同意與一次性註冊 intent，但 production 尚未套用 migration、配置或
> 啟用。未來即使經完整安全 gate、獨立審查與 owner 核准切換至 public，
> Google 仍必須提供 verified email，而且是唯一的公開建帳 provider；Passkey、Telegram
> 與其他可選社群登入都不能建立新帳號。未受邀公開建立的帳號會先是「受限」：
> 一般登入、帳號設定、Passkey 與服務的 OIDC 登入仍可使用，但不能新增其他
> provider、建立 OAuth client 或使用 PGID 管理功能；只有管理員明確審核提升後
> 才會成為標準帳號。這個 restricted path 目前也只是 local source，尚未部署。

註冊完成後，強烈建議立刻[設定一組 Passkey](passkey.md)，之後就能無密碼快速登入，也多一層安全保障。

Telegram 不提供 verified email，所以不能用來建立新 PGID 帳號。Telegram identity 只有在 standard 既有帳號的 authenticated session 中明確連結後，才可用來登入同一個帳號；帳號之後若受限，既有 Telegram link 仍可用於普通登入。

## 邀請

邀請是目前 production 建立帳號的必要條件。如果管理員以你的 email 發了邀請，
你第一次完成 Google 登入時會取得邀請指定的角色（例如管理權限）。邀請是
一次性的，用過即失效；未來若 public 模式經核准啟用，邀請機制仍會保留。

## 登入

之後每次登入，你可以選：

* **Google 登入**：適合換裝置或還沒設 Passkey 時。
* **Passkey 登入**：用指紋、臉部辨識或硬體安全金鑰，快速且無密碼。

登入 PG72 的某個服務時，PGID 會把三件事分開處理：

1. **選擇帳號**：如果目前瀏覽器記得仍有效的 PGID 帳號，先選這次要使用哪一個。選擇既有帳號不等於再次用 Google 或 Passkey 登入。
2. **驗證身分**：沒有可選帳號、選「使用其他帳號」，或服務要求重新確認身分時，PGID 會顯示目前可用的登入方式。選「使用其他帳號」不會移除原本記得的帳號。
3. **授權應用程式**：第一次使用某個服務，或服務要求新增權限時，才會看到授權畫面。選帳號本身不代表已按「允許」。

PGID 選擇器只顯示目前瀏覽器仍有效的 PGID 帳號，不是你在 Google 裡的所有帳號。完成必要步驟後，PGID 才會把你帶回原本的服務。

## 下一步

* [用 Google 登入](google-login.md)
* [設定與使用 Passkey](passkey.md)
* [帳號管理與安全](account-management.md)
