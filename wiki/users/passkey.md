# 設定與使用 Passkey

Passkey 是一種無密碼登入方式，用你裝置上的指紋、臉部辨識或硬體安全金鑰來證明身分。它比密碼更安全，而且不會被釣魚或外洩。

## 為什麼用 Passkey

* **無密碼**：沒有密碼可被猜測、外洩或重用。
* **防釣魚**：Passkey 綁定 `sso.pg72.tw`，假網站無法騙取。
* **快速**：一個指紋或臉部辨識就能登入。

## 註冊 Passkey

> 註冊 Passkey **需要先有帳號並已登入**。如果你還沒有帳號，請先[用 Google 登入](google-login.md)建立帳號。

1. 登入 PGID，進入帳號中心的「安全 / Passkeys」。
2. 點「新增 Passkey」。
3. 依裝置提示完成驗證（指紋、臉部、裝置 PIN 或插入 / 觸碰硬體安全金鑰）。
4. 為這組 Passkey 取一個好認的名字（例如「我的 MacBook」「YubiKey」），方便日後辨識。

你可以在不同裝置上各註冊一組 Passkey。同步型 Passkey（例如透過 iCloud 鑰匙圈或 Google 密碼管理員同步）也支援。

## 用 Passkey 登入

在登入頁選 Passkey 登入，依裝置提示完成驗證即可，不需輸入任何密碼。

## 管理你的 Passkey

在「安全 / Passkeys」你可以：

* **查看**所有已註冊的 Passkey，以及每組是綁定單一裝置還是可多裝置 / 可同步。
* **重新命名**（名稱上限 64 個字元）。
* **刪除**不再使用的 Passkey。

## 敏感的 client 管理操作

具有 client 管理權限的使用者在建立、修改、輪替 secret、停用或刪除 OAuth client 前，PGID 會要求再完成一次 Passkey 驗證。取消或驗證失敗時，原本的操作不會送出；成功結果只在目前這個登入 session 的短時間窗口內有效。

這項 step-up 與「session 剛建立」是兩個獨立條件。沒有 Passkey 的帳號不能略過，包含 `bootadmin`；請先透過既有 Google 登入建立 fresh session 並註冊 Passkey。若 Google 與所有 Passkey 都遺失，目前沒有可用的自助 recovery/break-glass flow；相關設計與演練尚未完成，不能用 client 管理 API 繞過。

### 重要保護

* **不能刪到一個登入方式都不剩**：系統會確保你至少保留一種可登入的方式。
* **刪除最後一組 Passkey 需要「剛登入」**：如果你要刪除最後一組 Passkey，且距離上次登入超過 10 分鐘，系統會要求你先登出再重新登入（fresh session），以防他人趁你離開時操作。

## 建議

* 至少註冊**兩組**不同的 Passkey（例如手機一組、硬體金鑰一組），避免單一裝置遺失就進不了帳號。
* 管理員應保留至少兩條獨立的復原路徑。

## 下一步

* [帳號管理與安全](account-management.md)
