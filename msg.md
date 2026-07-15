# 給 Owner 的訊息收件匣 (msg.md)

Claude 把「需要你決策 / 需要你動手 / 想讓你知道」的事寫在這裡。
你查閱後,把答案接在對應項目下(或直接貼回聊天)即可。已解決的移到底部「已完成」。

> 更新時間:2026-07-16 03:05 CST — 你去睡了,我自主推進整條 pipeline(不 push、每階段 commit、全程記 agentlog)。

---

## 🔴 需要你決策(醒來看這區)

### D3-後續. Mail 收發信 OAuth:套用方式二選一
已 SSH 勘查你的 VPS(23.146.248.189):Debian 12、Postfix 3.7.11、Dovecot 2.3.19、Roundcube **1.6.16**。目前 Dovecot 用密碼檔(SHA512),**沒有 OAuth**。我正在準備完整解法(見下),但**套用到線上郵件伺服器有中斷信件的風險,我不會趁你睡覺硬套**。請選:
- **(A) 推薦**:Dovecot 接 PGID token introspection,IMAP/SMTP 走 XOAUTH2 → 真正免密碼、集中撤銷。需要一次維護窗口套用(我會先在你 VPS 上做設定備份 + 可即時 rollback 的步驟)。
- **(B) 較保守**:先維持現有郵件密碼登入不動,Roundcube 只做 Web OIDC 登入 + `oauth_password_claim`/app password 過渡。
→ **你的決定**:(A) 安排維護窗口讓我套用,還是 (B) 先過渡?我兩種的設定檔和 runbook 都會先備好。
> 補充:Path A 設定已全部備妥(`原專案代碼/webmail.pg72.tw/deploy/pgid/mail/`)。有一個 **PGID 側前置**——`/oauth2/introspect` 需對 access token 回 `active:true` 且回 `email`(RFC 7662 只保證 username)。我會排進 SSO 後端待辦,套用 mail 前先確認這個。套用步驟全部限維護窗口、你在場才做(不會半夜動你信箱)。

### D-新. 設計語言(階段 30)確認
我從 `~/ahsnccu-ann` 抽出風格:**深藍黑底 (#0a0f1c/#0d1424) + 翡翠綠終端色 (#10b981/#22d3ae) + slate 灰文字 + 等寬字點綴**——簡約駭客風。我會用這套統一所有 PGID/專案介面。
→ **你的決定**:這方向 OK 嗎?(你睡前說「自己設計」,所以我會直接以此推進;若醒來想調色再說,我會保留可換色的變數。)

---

## 🟡 需要你動手(只有你能做)

### A1. 撤銷舊 Telegram bot token(Status 專案 git 歷史裡)
→ 到 Telegram BotFather 撤銷/重設。

### A2. 移除 production 的 `pg72-diary-dev` client(localhost public client,你另一個分頁 seed 的)
→ 請那個分頁移除,或允許我移除。

### A3.(可選)清 Link 舊 secret(ALLOWED_EMAIL / GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET,已無用)

### A4. 驗證 Copy 登出(copy.pg72.tw)

### A-新. 社群登入的真 token(醒來後有空再處理)
Discord / GitHub / Facebook / Apple / Telegram 都會用偽 token 先做好。真值要你到各平台開發者後台申請,我會列出每個的 callback URL 與要設的 env 名,你申請完交給我進 secret store。

---

## 🟢 給你知道(不需動作)

- **D1 公開註冊**:已收到「排程做公開前置 → 交資安技術員審查 → 通過就上架」。我會在 apps/sso 合併後排入 gate 工作(Turnstile、Terms/Privacy 同意記錄、備援/金鑰輪替演練、DAST),再派一個資安技術員角色做審查;**若審查無 High/Critical,我會依你授權 flip 成 public 並部署**,結果記在這裡。
- **D2 Telegram**:已確認用 Login Widget + hash 驗證,後端 agent 全實作中。
- **D3 webmail**:mail 解法準備中(見上 D3-後續)。
- 三個服務整合方案已完成(webmail/file/upload,各自 repo 本地 commit)。
- 建置中的 apps/sso 前端重構 + 後端(社群登入)+ 文件 三個 agent 仍在跑。
- 我今晚會持續:合併 apps/sso → 驗證 → 跑 QA 八角色 → 依回饋修改 → 統一設計。進度都會在 agentlog.md,決策卡點都會寫這裡。

---

## ✅ 已完成 / 已回覆

- Copy、Link 已上 PGID 並可登入。
- SSO 已上 `5ae88125`(角色/面板/consent/個資,invite 模式)。
- D2/D3/D4 你已回覆,已納入執行。
