# 認識 PGID

> 這份文件說明 PGID 是什麼、解決什麼問題、怎麼用，以及為什麼值得用。
> 內容供前端 `/about` 頁引用，也供對外介紹使用。
> Issuer：`https://sso.pg72.tw`

## PGID 是什麼

PGID 是 PG72 自行掌控的**單一登入（SSO）身分系統**。你只要在 PGID 建立一個帳號，就能用同一個身分登入所有 PG72 服務——不必每個網站各記一組帳密，也不必每個服務各自把你的資料存一份。

技術上，PGID 是一個標準的 OAuth 2.1 / OpenID Connect 身分提供者（Identity Provider）。它跑在 Cloudflare Workers 與 D1 上，用 Google 登入與 Passkey（無密碼）作為日常登入方式，並為每位使用者提供一個**不可變的帳號識別碼**，讓所有服務都認得「這是同一個人」。

## 它解決什麼問題

在有 PGID 之前，PG72 的每個服務各自為政：有的用 Google OAuth、有的用 Cloudflare Access、有的用自己的帳密。這造成：

- 使用者要在不同服務重複登入，每個服務對「你是誰」的認定還不一樣。
- 沒有統一的使用者 ID、角色與存取政策。
- 無法集中查看或撤銷自己在各裝置上的登入。
- 帳號被盜時，無法可靠地一次從所有服務登出。
- 登入與安全事件散落各處，沒有統一稽核。

PGID 把「你是誰」這件事集中到一個由 PG72 自己掌控的地方，讓每個服務只要信任 PGID 就好。跨服務即時登出的完整 delivery contract 仍在建置中，不能只因中央帳號中心已上線就視為完成。

## 怎麼用

一般使用者：

1. 受邀使用者用 Google 登入 PGID（首次登入仍要求 Google 已驗證 email）；production 目前不開放未受邀者自行建立帳號。
2. 在帳號中心註冊一組 Passkey，之後可用指紋 / 臉部 / 硬體金鑰無密碼登入。
3. 之後登入任何 PG72 服務時，會被導到 PGID 完成登入並在授權畫面按「允許」，就回到該服務。
4. 在帳號中心管理個人資料、Passkey、登入中的裝置、已授權的應用程式與安全紀錄，並可隨時撤銷單一裝置、其他裝置或全部裝置。

開發者 / 服務：把服務註冊成一個 OIDC client（由管理員或 developer 建立），走標準 Authorization Code + PKCE 流程接上 PGID。細節見 [PGID 串接 API 手冊](./api/PGID-integration.md) 與 [教學 wiki](../wiki/SUMMARY.md)。

## 相較於直接用 Google 或自建帳號系統的優勢

**相較於「每個服務各自接 Google」**

- **統一身分**：所有服務用同一個不可變 `sub` 認得你，不再靠會變動的 email 東拼西湊。
- **集中撤銷與登出**：在一個地方就能看到並撤銷所有裝置的登入，而不是逐一到各服務處理。
- **集中稽核**：登入與安全事件集中記錄。
- **不外流的最小授權**：PGID 只向 Google 要 `openid email profile`，不碰 Gmail / Drive；各服務也只拿到它需要的 claim。

**相較於「自己做一套帳密系統」**

- **無密碼、更安全**：日常登入用 Google 與 Passkey，沒有密碼可被外洩、猜測或重用。
- **不重造輪子**：OAuth / OIDC / WebAuthn 這些容易出錯的協議由專門的成熟引擎處理，服務端只要接標準流程。
- **一致的安全基線**：PKCE、精確 redirect 比對、consent 不可略過、host-only session cookie、token 不進瀏覽器 `localStorage` 等安全預設，所有服務共享。

**隱私與掌控**

- **PG72 自己掌控**：身分系統由 PG72 自行營運，不把登入 / 授權層外包給第三方存取閘道。
- **Email 不是主鍵**：email 可以換，識別你的是不可變的帳號 ID，降低資料錯接的風險。
- **明確連結**：同 email 的帳號不會被靜默合併，必須由你在已登入狀態下明確操作。

## 現況與邊界（誠實揭露）

PGID 目前是部署於 `https://sso.pg72.tw` 的 invite-only beta；既有部署紀錄顯示 Copy 與 Link 已使用 PGID production 登入，但這不代表完整 Production GO。以下為刻意的產品邊界：

- v1 日常登入主力是 Google 與 Passkey；另提供 Discord、GitHub、Facebook、Apple、Telegram 社群登入作為額外選項，各 provider 未設定 secret 時會自動隱藏。Telegram 不提供 verified email，只能登入已從 authenticated PGID session 明確連結的既有帳號，不能直接建立 PGID 帳號。不提供密碼、Email OTP 或 TOTP 登入。
- 服務的 OIDC client 由管理員 / developer 明確建立，不開放動態自助註冊。
- Production `REGISTRATION_MODE` 仍是 `invite`；公開註冊程式路徑已備妥，但安全 gate 與 owner 核准尚未完成。
- 中央 `sid`、back-channel logout（跨服務即時登出）、復原演練與完整 Production GO gate 仍在進行中，完整清單見 [`codex.md`](../codex.md) §9.2。

任何安全宣稱都以可驗證的自動化 gate 與獨立審查為準，不用文件聲明取代驗證。

## 想接上 PGID 或有問題？

- 串接技術參考：[PGID 串接 API 手冊](./api/PGID-integration.md)
- 使用者 / 開發者教學：[PGID Wiki](../wiki/SUMMARY.md)
- 聯絡：`contact@pg72.tw`
