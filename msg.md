# 給 Owner 的訊息收件匣 (msg.md)

Claude 把「需要你決策 / 需要你動手 / 想讓你知道」的事寫在這裡。
你查閱後,把答案接在對應項目下(或直接貼回聊天)即可。已解決的會移到底部「已完成」。

> 更新時間:2026-07-16 02:50 CST

---

## 🔴 需要你決策

### D1. 公開註冊何時開放?
目前 `REGISTRATION_MODE=invite`(依你指示先不開)。公開註冊路徑與濫用防護(註冊專用 rate limit)已就緒,但完整安全 gate 尚未全過:缺 **Turnstile、獨立安全審查、DAST、Terms/Privacy 同意記錄、備援/金鑰輪替演練**。
→ **你的決定**:要我把這些 gate 項目也排進 subagent 待辦嗎?還是先維持邀請制、之後再說?

### D2. Telegram 登入方案
Telegram 不是標準 OAuth/OIDC,是用 Login Widget + hash 驗證(需 bot token)。後端 agent 會先做骨架。
→ **你的決定**:確認要用 Telegram Login Widget 方案嗎?(其他 Discord/GitHub/Facebook/Apple 是標準 OAuth,直接做。)

### D3. webmail 的 mail backend 是什麼?
Roundcube 的 Web 登入可用 OIDC,但收發信(IMAP/SMTP)能不能免密碼,取決於你的郵件伺服器是否支援 XOAUTH2/OAUTHBEARER。
→ **你的決定**:你的 mail backend 是哪一套(Dovecot/Postfix/其他?)、有沒有開 XOAUTH2?若不支援,要走「短效密碼 bridge」還是「app password」?

### D4. 設計統一(階段 30)的風格定調
輪到統一各專案 CSS 前,我會先提一份設計語言(色票、字體、亮暗模式、圓角/間距風格)給你看。
→ **你的決定**:有沒有既定的品牌色/偏好風格(極簡黑白?某個主色?),還是完全交給我提案?

---

## 🟡 需要你動手(只有你能做)

### A1. 撤銷舊的 Telegram bot token
Status(XUGOU)專案的 **git 歷史**裡還留著舊的硬編碼 Telegram bot token。原始碼已清乾淨,但歷史裡的 token 若曾有效需撤銷。
→ **請到 Telegram BotFather 撤銷/重設該 bot token。**

### A2. 移除 production 的 `pg72-diary-dev` client
SSO production D1 裡有一個 `pg72-diary-dev`(localhost redirect 的 public client),那是你另一個 Claude 分頁 seed 進去的,違反「production 只允許 HTTPS 精確 redirect」。`pg72-diary` 本體沒問題。
→ **請在那個分頁請它移除 `pg72-diary-dev`**,或允許我移除。

### A3. (可選)清理 Link 的舊 secret
Link 的 Pages 還留著切換前的 `ALLOWED_EMAIL`、`GOOGLE_CLIENT_ID`、`GOOGLE_CLIENT_SECRET`,現在 PGID 登入已成功,這三個沒用了。
→ 要清的話跟我說,我給你指令(或你自己在 PGpenguin72 帳號的 Pages 設定刪)。

### A4. 驗證 Copy 登出
Copy 登出修復已部署(`351552a`)。
→ **有空到 copy.pg72.tw 測一下登出/重新登入是否正常。**

---

## 🟢 給你知道(不需動作)

- Link 登入已修好上線(根因:oauth4webapi 對 client_id 的 `-`/`_` 過度編碼,改用 ClientSecretPost)。
- SSO 已上 `5ae88125`:角色/使用者面板/consent/個資/公開註冊路徑(invite 模式)。
- 6 個建置 agent(前端重構/後端/文件/file/upload/webmail)背景執行中,完成我會彙整。
- 社群登入的 client id/secret 目前全用**偽值**;真值要你日後在各平台開發者後台申請後,交給我進 secret store(每個 provider 的 callback URL 我會列給你)。

---

## ✅ 已完成 / 已回覆

(空)
