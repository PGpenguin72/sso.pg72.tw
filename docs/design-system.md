# PGID 設計語言 (Design System)

> **權威主題:`morden_dark.txt`(owner 於 2026-07-16 指定)** — 風格為「Linear / Modern」深色系。
> 本檔是該主題套用到 PGID/各專案的落地指南。若與 `morden_dark.txt` 衝突,以 `morden_dark.txt` 為準。
> 用途:階段 30「統一 owner 自有專案視覺」的唯一依據。

## 0. 階段 30 適用範圍(重要)

- **要統一**:owner 自己 vibe 出來的原創專案(sso.pg72.tw 及 apps、copy、link、status、upload,以及其他自有原創前端)。
- **不要碰**:
  - `anzhiyu`、`fuwari` 這兩個部落格(保留各自主題);
  - 任何從**別人倉庫 clone** 下來的內容(保持上游樣式);
  - 上游快照專案 file(File Browser)、webmail(Roundcube)的**核心**(只在自有的 gateway/包裝層套用,不改上游 UI)。
- 進行前先列出 `~` 下的專案資料夾,逐一判定「自有原創 vs clone/blog」,不確定的先問(寫進 msg.md),不亂改。

## 1. 風格定調(Linear / Modern)

深空近黑底(`#050506`,非純黑)+ 單一飽和靛藍強調(`#5E6AD2`)+ 分層環境光。氛圍:電影感的技術極簡——像夜裡透過霧面玻璃看一個高階桌面應用。深但不壓迫、技術但不冷硬、精確但不僵。核心手法:**分層環境光 + 互動深度**(多層背景漸層、緩動的模糊光暈 blob、滑鼠追蹤 spotlight、多層陰影、200–300ms expo-out 微互動)。

## 2. 色票 Tokens(以 morden_dark 為準)

```css
:root {
  --background-deep:     #020203; /* 最深:footer/最底層 */
  --background-base:     #050506; /* 頁面主底 */
  --background-elevated: #0a0a0c; /* 抬升面/mock 介面 */
  --surface:        rgba(255,255,255,0.05); /* 卡片/容器 */
  --surface-hover:  rgba(255,255,255,0.08);
  --foreground:        #EDEDEF; /* 主文字(亮但非純白) */
  --foreground-muted:  #8A8F98; /* 內文/描述/中繼 */
  --foreground-subtle: rgba(255,255,255,0.60);
  --accent:        #5E6AD2; /* 主互動色:按鈕/連結/光暈 */
  --accent-bright: #6872D9; /* hover */
  --accent-glow:   rgba(94,106,210,0.30);
  --border-default: rgba(255,255,255,0.06);
  --border-hover:   rgba(255,255,255,0.10);
  --border-accent:  rgba(94,106,210,0.30);
  --input-bg:       #0F0F12;
}
```

> 主題為深色優先。若某專案需要 light mode,另派生一組對應值,但 PGID 品牌識別以此深色 Linear look 為主。換色只需改變數。

## 3. 字體與文字

- **字體**:`"Inter", "Geist Sans", system-ui, sans-serif`。
- Type scale:Display 7xl–8xl / H1 5–6xl / H2 3–4xl / H3 xl–2xl，皆 `font-semibold` + `tracking-tight`(Display `-0.03em`);Body sm–base `font-normal` `leading-relaxed`;**Label `text-xs` `font-mono` `tracking-widest`**(區塊小標/中繼——技術感關鍵)。
- 標題可用漸層填色:`from-white via-white/95 to-white/70` bg-clip-text;強調可用 accent shimmer 漸層。

## 4. 圓角 / 邊框 / 陰影

- 圓角:大容器/卡片 `rounded-2xl`(16px)、按鈕/輸入 `rounded-lg`(8px)、圖示容器 `rounded-xl`(12px)、badge `rounded-full`。
- 邊框:卡片 `border-white/[0.06]`;輸入 `border-white/10`;badge `border-accent/30`;hover 提亮。
- 陰影(多層):
  - 卡片預設 `0 0 0 1px rgba(255,255,255,.06), 0 2px 20px rgba(0,0,0,.4), 0 0 40px rgba(0,0,0,.2)`
  - 卡片 hover 加 `0 0 80px rgba(94,106,210,.1)` 的 accent glow
  - CTA `0 0 0 1px rgba(94,106,210,.5), 0 4px 12px rgba(94,106,210,.3), inset 0 1px 0 0 rgba(255,255,255,.2)`
  - 抬升面上緣內高光 `inset 0 1px 0 0 rgba(255,255,255,.1)`

## 5. 元件

- **Primary 按鈕**:實心 `#5E6AD2`、白字、多層 accent glow;hover `#6872D9` + glow 增強;active `scale-[0.98]`;hover 有 shine sweep。
- **Secondary**:`bg-white/[0.05]`、`#EDEDEF` 字、inset 邊;hover `bg-white/[0.08]` + 微光。
- **Ghost**:透明、muted 字;hover `bg-white/[0.05]` + 字提亮。
- **卡片**:`bg-gradient-to-b from-white/[0.08] to-white/[0.02]`、1px 6% 邊、`rounded-2xl`、上緣 1px 漸層高光;可加滑鼠追蹤 spotlight(300px 徑向、accent 15%)。
- **輸入**:`bg-[#0F0F12]`、`border-white/10`;focus `border-[#5E6AD2]` + accent glow ring;placeholder `text-gray-500`。
- **hover 原則**:位移 4–8px、200–300ms、easing `[0.16,1,0.3,1]`(expo out)、邊框提亮 + glow + 微 scale。
- **focus**:`ring-2 ring-[#5E6AD2]/50 ring-offset-2 ring-offset-[#050506]`。
- **active**:`scale-[0.98]`、陰影減弱。

## 6. 背景系統(招牌)

分層:①頂部徑向漸層 `radial-gradient(ellipse_at_top,#0a0a0f,#050506,#020203)` ②SVG noise `opacity .015` 防 banding ③緩動模糊 blob(900–1400px、blur 100–150px、accent 10–25%,`float` 8–10s)④64px grid overlay `opacity .02`。互動面加滑鼠 spotlight;hero 可 scroll parallax。尊重 `prefers-reduced-motion`。

## 7. 落地(階段 30)

1. 把第 2 節 tokens 收斂成單一主題檔(CSS 變數或 Tailwind theme extend),各自有專案 import。
2. 逐專案替換寫死色/字為 tokens、元件對齊第 5 節、背景用第 6 節分層。
3. 只套用於**自有原創專案**(見第 0 節範圍);排除 anzhiyu/fuwari/clone 內容。
4. 每專案改完各自 build/視覺驗證,再由設計審查角色複核跨專案一致性。

> 主題來源:owner 提供的 `morden_dark.txt`(Linear/Modern)。owner 若要調整,改該檔或第 2 節變數即可。
