# 用 Google 登入

Google 是 PGID 的其中一種登入方式，也是第一次建立帳號最常用的方式。

## 怎麼登入

1. 在登入頁選「用 Google 登入」。
2. PGID 會把你導到 Google，Google 會請你選擇帳號（每次都會問，不會自動用上次的）。
3. 選好 Google 帳號並完成登入後，回到 PGID。服務需要的新授權會由 PGID 另外顯示。

## Google 選帳號與 PGID 選帳號不同

PGID 的選擇器是在登入服務時，讓你從目前瀏覽器仍有效的 PGID 帳號中選擇身分。選擇其中一個既有 PGID 帳號，通常不需要再次前往 Google，也不等於同意服務取得權限。

如果選「使用其他帳號」，PGID 會顯示當時可用的登入方式；若其中包含 Google，選擇後才會看到 Google 自己的帳號選擇畫面。Google 的選擇器決定用哪個 Google 身分完成驗證，PGID 的選擇器則決定這次授權流程使用哪個既有 PGID 帳號，兩份清單不一定相同。

## PGID 向 Google 要哪些資料

PGID 只向 Google 要最基本的登入資訊：`openid`、`email`、`profile`。也就是你的：

* email 與是否已驗證
* 名稱與大頭貼

PGID **不會**要求存取你的 Gmail、Google Drive 或其他 Google 產品資料，也不會為了登入而要求 Google 的長期離線存取權。

## 為什麼需要「已驗證的 email」

PGID 只在 Google 明確表示你的 email 已驗證時才建立帳號。這能避免有人拿未經證實的 email 建立帳號。如果你看到「需要已驗證的 email」的訊息，請先到 Google 帳號完成 email 驗證再試一次。

## Google 帳號與 PGID 帳號的關係

* 你的 PGID 帳號以 Google 的使用者識別碼綁定，不只是比對 email。
* 同一個 email 的帳號**不會**被自動合併。如果你想把另一個登入方式連結到現有帳號，必須在已登入的狀態下明確操作。
* 你更換 Google 端的 email 不會改變你的 PGID 帳號 ID。

## 常見狀況

* **在 Google 畫面按了取消**：這次 Google 身分驗證不會完成；服務也不會因此取得新的授權。
* **想換既有 PGID 帳號**：在 PGID 選擇器直接選另一個仍有效的帳號。
* **想用另一個 Google 帳號**：在 PGID 進入「使用其他帳號」流程；如果當時可用的登入方式包含 Google，選擇後再到 Google 的畫面選帳號。

## 下一步

設好一組 [Passkey](passkey.md)，之後就能無密碼登入，即使不透過 Google 也能進入帳號。
