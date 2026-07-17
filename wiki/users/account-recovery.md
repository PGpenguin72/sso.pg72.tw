# 使用帳號復原碼

> 狀態：這項功能已在 PGID local source 實作，但 production 尚未套用 migration `0019`、啟用 `RECOVERY_MODE` 或完成 lost-device drill。只有帳號中心實際顯示「復原碼」時，以下流程才可使用。

復原碼是在遺失日常登入方式時，用來建立一組新 Passkey 的一次性憑證。它不是日常登入方式，也不會靠 Email 尋找、合併或重新指派帳號。

## 先建立並保存

1. 用一般方式登入 PGID，進入帳號中心的「安全 / Passkeys」。
2. 確認目前 session 是剛建立的，並至少保有一組可用 Passkey。
3. 點「建立復原碼」，依裝置提示完成 Passkey 重新驗證。
4. PGID 會顯示十組 `PGID-R1` 復原碼。立即下載或抄寫並離線保存；離開後無法再次查看同一組 raw codes。

每組 code 都只能使用一次。現行 generation 沒有自動到期日，但你可以隨時撤銷或重新產生；重新產生會立刻讓整組舊碼失效。PGID 資料庫只保存不可逆 hash，operator 無法從資料庫或備份取回 raw code。

## 遺失登入方式時

1. 在 PGID 登入頁選「使用復原碼」，或開啟 `/recover`。
2. 輸入一組尚未使用的 `PGID-R1` code。大小寫、一般空白與連字號可正規化；不要輸入其他字元。
3. 依裝置提示建立新的 Passkey，且必須完成使用者驗證。
4. 成功後，保存畫面顯示的新一代十組復原碼，再以新 Passkey 重新登入。

PGID 接受 code 並開始流程時就會永久消耗它。取消、關閉頁面或後續 Passkey 失敗都不會恢復該 code；可以改用同一 generation 的另一組未使用 code 重新開始。

成功完成時，PGID 會撤銷所有既有中央 sessions、access tokens 與 refresh tokens，並通知已接入 back-channel logout 的服務清除舊 session。這可避免遺失裝置保留登入狀態。你不會在 recovery 流程中直接取得一般 PGID session，必須用新 Passkey 重新登入。

## 安全提醒

* 把復原碼與日常登入裝置分開保存，例如離線紙本或受保護的密碼管理器。
* 不要透過 issue、Email、聊天或截圖傳送 raw code；PGID operator 不會要求你提供它。
* 建議同時保留至少兩組不同的 Passkey。復原碼不能取代第二條獨立復原路徑。
* 若懷疑復原碼外洩，從帳號中心立即重新產生或撤銷整組。
* 如果 production 尚未顯示此功能，請勿嘗試用 local endpoint、migration 或文件內容自行啟用。

## 下一步

* [設定與使用 Passkey](passkey.md)
* [帳號管理與安全](account-management.md)
