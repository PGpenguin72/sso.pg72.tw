# 社群登入申請與設定教學

PGID 已支援 Discord / GitHub / Facebook / Apple / Telegram 登入,但**目前都沒設定 secret,所以登入頁不會顯示這些按鈕**(自動隱藏,不影響 Google/Passkey)。Secret 值只能由授權 operator 直接寫入 Cloudflare secret store,不得貼到聊天或寫入檔案。Telegram 只可登入已從 authenticated PGID session 明確連結的既有帳號,不能在 invite 或 public mode 直接建立帳號。

## 共通:設定 secret 的方式

Production secret 設定是授權 operator 在維護窗口執行的 deployment action。只有在準備同步完成 smoke/rollback 時才可執行:

```bash
cd apps/sso
# 每設一個 secret 跑一次;會提示貼入值
npx wrangler secret put <SECRET_NAME>
```

若要先建立尚未部署的 version,可使用 `wrangler versions secret put`,再依核准的 maintenance-window runbook 控制 deployment。無論採哪一條路,值都只在 Wrangler 的互動式 secret prompt 由授權 operator 輸入,不進 shell history、source、log、issue 或聊天。

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
5. **`APPLE_CLIENT_SECRET` 是用 .p8 + Key ID + Team ID 產生的 ES256 JWT**(有效期最長 6 個月,到期要換)。應在受控環境以經審核的工具自行產生並規劃輪替;`.p8` 私鑰、產出的 JWT 與相關 secret 不得貼到聊天。
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
5. Telegram 不提供 verified email,因此這個 endpoint 只會登入已從 authenticated PGID session 明確連結的既有帳號。未綁定 identity 在 invite/public 兩種 mode 都會被拒絕,不會建立 placeholder-email 帳號。

---

## 注意

- 每個 provider **只有兩個(id+secret)都設好才會啟用**;沒設的就自動隱藏,不會壞。
- 這些 secret 只放 Wrangler secrets / Secrets Store,**不要**貼進 git、`wrangler.jsonc`、log、issue 或聊天。
- Google 與 Passkey 是主力登入,社群登入是額外選項。
