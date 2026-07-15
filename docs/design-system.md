# PGID 設計語言 (Design System)

> 風格定調:**簡約 + 駭客/終端風**,深色優先、雙模式(light/dark)。
> 基礎取自 owner 的參考站 `ann.ahsnccu.pg72.tw`(`~/ahsnccu-ann`),抽離為品牌無關的可換色 token。
> 用途:階段 30「統一所有 PGID 專案視覺」的唯一依據。所有專案(sso / copy / link / status / upload / file / webmail)以此對齊。

## 1. 設計原則

1. **深色優先的終端美學**:近黑深藍底、細邊框、克制的螢光綠強調色。像一個乾淨的 IDE / 終端機,不是花俏的 SaaS。
2. **雙模式**:所有顏色以 CSS 變數定義,light/dark 兩套值;預設 dark,可切換,`prefers-color-scheme` 尊重系統。
3. **資訊優先、克制裝飾**:留白、對齊、層級清楚;不用漸層轟炸、不用大陰影。強調靠**大寫等寬小標 + letter-spacing**,不是靠顏色亂撒。
4. **可及性**:文字對比達 WCAG AA;焦點可見(focus ring 用 accent);不僅靠顏色傳達狀態(配圖示/文字)。
5. **一致的元件語彙**:卡片、pill/badge、按鈕、輸入框、表格在所有專案長一樣。

## 2. 色票 Tokens(CSS 變數)

```css
:root, [data-theme="dark"] {
  --bg:      #05070d;  /* 頁面底 */
  --panel:   #0d1424;  /* 卡片/面板 */
  --panel-2: #111a30;  /* 次級面板/hover */
  --line:    #1c2947;  /* 邊框 */
  --grid:    #14203a;  /* 分隔線/格線 */
  --text:    #e2e8f5;  /* 主文字 */
  --dim:     #93a0ba;  /* 次要文字 */
  --faint:   #5d6b89;  /* 更弱/佔位 */
  --accent:  #5b9dff;  /* 連結/互動主色(藍) */
  --ok:      #22d3ae;  /* 成功/終端綠(品牌強調) */
  --warn:    #c47a1d;  /* 警告 */
  --bad:     #fb7185;  /* 錯誤/危險 */
  --focus:   #5b9dff;  /* 焦點環 */
}
[data-theme="light"] {
  --bg:      #f4f6fb;
  --panel:   #ffffff;
  --panel-2: #eef1f8;
  --line:    #dde4f0;
  --grid:    #e3e9f4;
  --text:    #16233f;
  --dim:     #5d6b89;
  --faint:   #7787a8;
  --accent:  #2563eb;
  --ok:      #0ca678;
  --warn:    #c47a1d;
  --bad:     #e5484d;
  --focus:   #2563eb;
}
```

> 換色只需改這兩組值;元件一律引用變數,不寫死顏色。owner 若要換品牌主色,改 `--ok`/`--accent` 即可。

## 3. 字體與文字

- **本文**:`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`。
- **等寬/代碼/資料**:`ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace`。
- **小標/標籤(駭客風關鍵)**:等寬或 sans、`text-transform: uppercase`、`letter-spacing: .12em–.14em`、字級 11–12px、色 `--dim`。用於區塊標題、欄位 label、狀態標籤。
- 標題層級:h1 24–28px / h2 18–20px / h3 15–16px,字重 600;本文 14–15px / 1.55 行高;`--dim` 作輔助說明。
- 數字/ID/token/時間戳一律用等寬字。

## 4. 形狀、間距、動態

- **圓角**:卡片 `9px`;小元件(badge/按鈕)`6px`;pill/標籤 `999px`;大容器 `13px`。
- **邊框**:`1px solid var(--line)`;面板之間靠邊框與底色分層,不靠陰影。
- **陰影**:極克制;僅 modal/浮層用一層柔和陰影。狀態呼吸動畫可用 `box-shadow` pulse(如 --ok 的 online 指示)。
- **間距**:8px 網格(4/8/12/16/24/32);卡片內距 16–20px;區塊間距 24–32px。
- **動態**:過場 120–180ms ease;hover 只改底色/邊框,不位移。尊重 `prefers-reduced-motion`。

## 5. 核心元件規格

- **卡片/面板**:`background: var(--panel); border:1px solid var(--line); border-radius:9px; padding:16–20px`。標題用第 3 節的大寫小標。
- **按鈕**:
  - Primary:實心 `--accent` 底、白字(dark 下可用 `--ok` 作 CTA);hover 提亮。
  - Secondary:透明底、`1px solid var(--line)`、`--text` 字;hover `--panel-2`。
  - Danger:`--bad` 邊框/字,hover 才填色;破壞性操作用。
  - 尺寸:高 34–38px、`border-radius:6px`、`padding:0 14px`;等寬 label 選配。
- **輸入框**:`background: var(--panel-2); border:1px solid var(--line); border-radius:6px`;focus 時 `border-color:var(--focus)` + 2px focus ring。
- **Badge/狀態 pill**:`border-radius:999px`、11px 大寫、色用語意變數的 12–18% 底 + 該色字(`color-mix(in srgb, var(--ok) 15%, transparent)`)。狀態:active/online=`--ok`、suspended/error=`--bad`、pending=`--warn`、info=`--accent`。
- **表格/清單**:列以 `--grid` 分隔;表頭用大寫小標;hover 列 `--panel-2`;數值靠右、等寬。
- **側欄導覽(sso 帳號中心)**:深底 `--bg`、分組小標(大寫 `--dim`)、當前項 `--ok` 左側指示條 + `--panel-2` 底。
- **焦點**:`outline: 2px solid var(--focus); outline-offset:2px`,鍵盤可見。

## 6. 品牌標記

- 目前臨時品牌是企鵝 emoji;統一時可用「PGID」等寬字標 + 一個小型單色標記(方形/圓角、`--ok` 描邊)。克制、單色、可在 light/dark 都清楚。
- consent / 登入頁的 brand 要小而定位明確(不要與主標題間留大空隙——這是目前 consent 畫面被點名的問題)。

## 7. 落地方式(階段 30)

1. 把第 2 節的變數收斂成單一 `theme.css`(或各專案等效的 token 檔),各專案 import。
2. 逐專案把寫死顏色/字體替換為變數;元件對齊第 5 節規格。
3. 亮暗模式一致;加 `data-theme` 切換 + 系統偏好。
4. 每個專案改完各自驗證(build/視覺),再由設計審查角色複核一致性。

> 註:此為 Claude 依 owner「簡約+駭客風、參考 ann.ahsnccu」自訂的提案。owner 醒來若要調整主色/風格,改第 2 節變數即可,元件無需重寫。
