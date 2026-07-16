# 用 Google 登入

Google 是 PGID 的其中一種登入方式，也是第一次建立帳號最常用的方式。

## 怎麼登入

1. 在登入頁選「用 Google 登入」。
2. PGID 會把你導到 Google，Google 會請你選擇帳號（每次都會問，不會自動用上次的）。
3. 選好帳號並同意後，回到 PGID 完成登入。

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

* **在 Google 畫面按了取消**：會回到服務並顯示「已取消授權」，重新點登入即可。
* **想換 Google 帳號**：因為 PGID 每次都會請 Google 讓你選帳號，直接選另一個即可。

## 下一步

設好一組 [Passkey](passkey.md)，之後就能無密碼登入，即使不透過 Google 也能進入帳號。
