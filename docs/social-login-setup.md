# 社群登入申請與設定教學(A4)

PGID 已支援 Discord / GitHub / Facebook / Apple / Telegram 登入,但**目前都沒設定 secret,所以登入頁不會顯示這些按鈕**(自動隱藏,不影響 Google/Passkey)。你到各平台開發者後台申請後,把值交給我(或自己)進 secret store,按鈕就會出現且可用。

## 共通:設定 secret 的方式

在 `apps/sso/` 目錄用 Wrangler 設(值不會落地、不進 git):

```bash
cd /Users/pgpenguin72/sso.pg72.tw/apps/sso
# 每設一個 secret 跑一次;會提示貼入值
npx wrangler secret put <SECRET_NAME>
```

設完**不需重新部署**(Worker secret 即時生效;若沒生效再 `wrangler deploy --config dist/pg72_id/wrangler.json`)。你也可以把值貼給我,我幫你進。

各 provider 的 **callback / redirect URI 一律填**:
```
https://sso.pg72.tw/callback/<provider>
```
（Telegram 例外,見下。）

---

## 1. Discord

1. 開 https://discord.com/developers/applications → New Application。
2. 左側 OAuth2 → 複製 **Client ID** 與 **Client Secret**。
3. OAuth2 → Redirects 加入:`https://sso.pg72.tw/callback/discord`。
4. 設定 secret:
   - `DISCORD_CLIENT_ID`
   - `DISCORD_CLIENT_SECRET`

## 2. GitHub

1. 開 https://github.com/settings/developers → OAuth Apps → New OAuth App。
2. **Authorization callback URL** 填:`https://sso.pg72.tw/callback/github`。
3. 建立後複製 **Client ID**,並 Generate 一個 **Client Secret**。
4. 設定 secret:
   - `GITHUB_CLIENT_ID`
   - `GITHUB_CLIENT_SECRET`

## 3. Facebook

1. 開 https://developers.facebook.com/apps → 建立 App(類型選 Consumer/None)。
2. 加入 **Facebook Login** 產品 → Settings → Valid OAuth Redirect URIs 填:`https://sso.pg72.tw/callback/facebook`。
3. App 設定 → 基本 → 複製 **App ID** 與 **App Secret**。
4. 設定 secret:
   - `FACEBOOK_CLIENT_ID`（= App ID）
   - `FACEBOOK_CLIENT_SECRET`（= App Secret）
5. 上線前把 App 從「開發中」切成「上線」,並在使用案例加入 email 權限。

## 4. Apple（最麻煩,secret 是 JWT）

需要 Apple Developer 付費帳號。
1. 開 https://developer.apple.com/account → Certificates, IDs & Profiles。
2. 建一個 **App ID**(或 Services ID)作為 client:記下 **Services ID**（= `APPLE_CLIENT_ID`）。
3. Services ID 設定 Sign in with Apple → 網域填 `sso.pg72.tw`、Return URL 填 `https://sso.pg72.tw/callback/apple`。
4. 建一把 **Sign in with Apple 用的 Key**(.p8),記下 **Key ID** 與 **Team ID**,下載 .p8 私鑰。
5. **`APPLE_CLIENT_SECRET` 是用 .p8 + Key ID + Team ID 產生的 ES256 JWT**(有效期最長 6 個月,到期要換)。這一步較複雜,把 .p8 內容、Key ID、Team ID、Services ID 給我,我可以幫你產生 JWT 並教你之後怎麼自動輪替。
6. 設定 secret:
   - `APPLE_CLIENT_ID`（Services ID）
   - `APPLE_CLIENT_SECRET`（產生的 JWT）
   - （選)`APPLE_APP_BUNDLE_IDENTIFIER`

## 5. Telegram（不是 OAuth,用 Login Widget）

1. 在 Telegram 找 **@BotFather** → `/newbot` 建一個 bot,記下 **bot token** 與 **bot username**。
2. 對 BotFather 用 `/setdomain` 把 bot 的登入網域設為 `sso.pg72.tw`。
3. 設定 secret / 變數:
   - `TELEGRAM_BOT_TOKEN`（bot token,secret）
   - `TELEGRAM_BOT_USERNAME`（bot 的 username,例如 `pgid_login_bot`;這個是公開的,登入頁 widget 需要)
4. Telegram 不需要 `callback/telegram`;widget 驗證後會 POST 到 `/api/auth/telegram`(後端已做 HMAC 驗證)。

---

## 注意

- 每個 provider **只有兩個(id+secret)都設好才會啟用**;沒設的就自動隱藏,不會壞。
- 這些 secret 只放 Wrangler secret store,**不要**貼進 git、`wrangler.jsonc`、log 或聊天(給我進 store 可以,我不會寫進檔案)。
- Google 與 Passkey 是主力登入,社群登入是額外選項。
