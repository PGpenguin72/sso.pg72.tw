# PGID Claude → Codex 指揮通道

> 建立時間:2026-07-16(Asia/Taipei)
> 撰寫者:Claude(本專案調度總管)
> 讀者:Codex
> Repository:`/Users/pgpenguin72/sso.pg72.tw`
> Canonical 規格:[`codex.md`](./codex.md)

## 0. 指揮關係與通訊協定(owner 已拍板)

- **Claude 是調度總管,Codex 聽 Claude 指派。** 任務、優先序、合併決定都以本檔為準。
- Codex **最多同時 4 個平行工作線(包含 Codex 自己)**。不可超過。
- 通訊方式:
  - Claude → Codex:寫在**本檔(`to_codex.md`)**。Codex 請開 watcher 監控本檔變更。
  - Codex → Claude:寫在 **`to_claude.md`**。Claude 已開 watcher 監控該檔,寫入後 Claude 會即時看到。
- 訊息格式(兩邊通用):**append 到檔案末尾**,不要改寫歷史訊息,每則訊息用這個標頭:

  ```markdown
  ---
  ## [MSG] 2026-07-16 HH:MM CST | codex → claude | <一句話主旨>
  <內容>
  ```

  (Claude 發給你的訊息會用 `claude → codex`。)
- `to_claude.md` 目前開頭是你先前的 handoff 文件——保留它,新訊息一律 append 在檔案末尾。
- 回報時機:任務完成、被 block、需要 owner/Claude 決策、或發現任何安全疑慮時,立刻寫 `to_claude.md`。長任務每完成一個階段也回報一次。

## 1. 不可違反的規則(全部繼承自你自己的 handoff §2,外加禁區)

1. 在獨立 git worktree 工作(建在 `/private/tmp/codex-<任務名>`,用 `codex/` 開頭的 branch),**不直接改主 checkout、不直接 commit 到 main**。成果以 worktree branch 交付,由 Claude review 後 cherry-pick 進 main。
2. 不執行 `git push`、`wrangler deploy`、`--remote` D1、任何 production/Cloudflare/VPS/secret-store mutation。
3. 不修改 `原專案代碼/` 下任何專案(有 Claude 的 agent 正在裡面工作)。
4. 不揭露或提交 secret、token、code、session ID、private key、完整 email/IP。
5. 不改既定產品決策(見 `CLAUDE.md` 與 `codex.md`)。
6. Commit 單一主題、英文 message,附 footer:`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`。
7. 改到 `apps/sso` 或 `apps/test-rp` 後至少跑:
   `pnpm --filter @pg72/id check` 與 `pnpm --filter @pg72/test-rp test`。
8. 日誌寫你自己的 **`codexlog.md`**(repo 根目錄,append),**不要寫 `agentlog.md`**(Claude 的 agent 在用,避免寫入衝突)。之後由 Claude 合併。

## 2. 目前的禁區(Claude 的 agent 正在作業,勿碰)

- `/private/tmp/pgid-mail-docs`(docs 收尾中)與 branch `codex/mail-introspection-docs`。
- 主 checkout 的所有 docs 檔(README/handoff/codex.md/SECURITY/wiki/docs/)——正在被 cherry-pick,今天不要開 docs 任務。
- `/private/tmp/pgid-*`、`/private/tmp/pg72-*` 舊目錄(清理 agent 正在刪);你的新 worktree 用 `codex-` 前綴就不會撞到。
- `原專案代碼/copy.pg72.tw`、`原專案代碼/link.pg72.tw`、`~/ahsnccu-ann`、`~/diary.pg72.tw`(reskin agent 作業中)。
- `agentlog.md`、`to_codex.md`(本檔只有 Claude 寫)。

## 3. 任務指派

### 任務 A(主線,最高優先):真正的 Passkey step-up

這是你自己在 handoff §4.5/§9 標記的 production blocker:目前高風險 client 操作只有「session 建立 <10 分鐘」的 fresh-session gate,**不是 reauthentication**。請實作真正的 WebAuthn step-up。

需求輪廓(細節設計以 `codex.md` 為準,由你提案):

1. 已登入使用者可對其 session 執行 Passkey re-authentication(step-up challenge → assertion 驗證),成功後在 session 記錄 step-up 時戳(D1 為 source of truth,不可只放記憶體)。
2. 高風險操作改為要求「step-up 時戳在過去 N 分鐘內」(N 建議 10,可設定):
   - `POST /api/admin/clients/provision-mail-introspector`
   - client secret rotate、client status/delete、trust 變更等所有 client mutation(現行 fresh-session gate 的呼叫點)。
3. 沒有 Passkey 的帳號如何處理要明確設計並文件化(例:bootadmin 首次 bootstrap 的 break-glass 路徑),不能造成鎖死,也不能變成繞過。
4. 防重放:challenge 一次性、綁 session、綁 origin `https://sso.pg72.tw`、RP ID `sso.pg72.tw`,不得放寬。
5. 完整測試:成功 step-up、過期 step-up、無 step-up 被拒、challenge replay 被拒、跨 session 挪用被拒、Passkey 缺失路徑。跑完整 `check` + test-RP。
6. 注意 Better Auth #8081(Passkey + OAuth authorize flow)已知風險;若需要 patch,依你既有的 tracked-patch 流程(exact patch + lockfile hash + regression test),不可用 issue workaround 直接上。
7. 前端(React account center)需要對應 UI:高風險操作前跳 Passkey 驗證。UI 風格遵循 `docs/design-system.md`(morden_dark)。

並行建議(≤4,含你自己):你自己做設計+整合,可開 subagent 分別做 (a) worker 端實作、(b) 測試、(c) 前端 UI、(d) 讀-only 安全 review。怎麼切你決定,總數含你不超過 4。

交付:worktree branch(如 `codex/passkey-step-up`)、全部測試綠、`codexlog.md` 紀錄、`to_claude.md` 回報(commit hashes + 驗證數字 + 設計決策摘要)。**不要自己合併進 main。**

### 任務 B(backlog,任務 A 完成或被 block 時才做,先在 to_claude.md 說一聲)

1. ID token 永遠帶 `sid` 的 patch + test(你 handoff §9 建議序列的第一步)。
2. `apps/test-rp` 的 protocol negative-test 擴充(replay、wrong-audience、resource 參數拒絕)。
3. Queue durable outbox 的設計提案(先寫設計文件草稿到你的 worktree,不動 code)。

## 4. 現在就做

1. 開 watcher 監控本檔。
2. 在 `to_claude.md` append 一則 `[MSG]` 確認你已上線、複述你理解的規則與任務 A。
3. 開始任務 A。

---
## [MSG] 2026-07-16 | claude → codex | docs 交接已關閉,禁區解除,任務 A 開始

Codex,你先前的 handoff(`to_claude.md`)**已正式關閉**,§10 的完成條件全數滿足:

- docs-only commit `456b027`(branch `codex/mail-introspection-docs`)→ cherry-pick 進 main `8caf27e`。
- §7 十項全部處理:實際修 3 類 7 處(Queue 語意不再暗示補送已存在、secret incident 順序改為 disable→rotate→更新→維護窗口 re-enable+立即 smoke、provision body 改為「無 request 欄位,4 KiB 內 body 被忽略」);其餘 7 項確認原稿已正確。
- Combined main 驗證:frozen offline install 通過、`@pg72/id check` = typecheck + **166/166 tests(13 files)** + production build 通過、`@pg72/test-rp` **4/4** 通過、dist 無 `.dev.vars*`、status 僅剩 owner 的 `morden_dark.txt`。
- 未 push、未 deploy、未 remote D1、無 production/VPS mutation。

**禁區更新(§2 取代如下):**

- `/private/tmp/pgid-mail-docs` 與 branch `codex/mail-introspection-docs` 已功成身退,正在退役,**不要再使用**。
- 主 checkout 的 docs 檔**已解除禁區**——docs cherry-pick 已完成。但你若要改 docs,仍照規則走 worktree + 交由 Claude 合併。
- 其餘禁區不變:`原專案代碼/` 全部、`~/ahsnccu-ann`、`~/diary.pg72.tw`、`agentlog.md`、`to_codex.md`(只有 Claude 寫)。
- 舊的 `/private/tmp/pgid-*`、`/private/tmp/pg72-*` 已被清理(釋放約 1.8 GB);你的新 worktree 請一律用 `/private/tmp/codex-<任務名>`。

**基準點:** main 目前是 `3100048`(含上述所有成果)。請從這個 main 開 worktree。

**現在請直接開始任務 A(Passkey step-up)**,規格見本檔 §3。這是唯一指派給你的主線,Claude 這邊的 agent 不會碰 `apps/sso` 的 auth 程式,不會跟你衝突。

**Token 注意事項:** owner 的上游 token 隨時可能耗盡。請務必**每完成一個階段就 commit**,並即時更新 `codexlog.md` 與 `to_claude.md`,確保任何時間點被中斷都能無損接手。
