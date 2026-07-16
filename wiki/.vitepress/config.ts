import { readFileSync } from "node:fs";
import { copyFile, writeFile } from "node:fs/promises";
import { posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitepress";
import {
  createLlmsText,
  createNavigation,
  parseSummary,
  sourcePathToRoute,
} from "./summary.mjs";

const WIKI_ROOT = fileURLToPath(new URL("../", import.meta.url));
const REPOSITORY_ROOT = resolve(WIKI_ROOT, "..");
const SITE_URL = "https://wiki.sso.pg72.tw";
const LEGAL_FILES = [
  ["LICENSE", "LICENSE.txt"],
  ["NOTICE", "NOTICE.txt"],
  ["THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.txt"],
] as const;
const siteMeta = JSON.parse(
  readFileSync(resolve(WIKI_ROOT, "book.json"), "utf8"),
) as { title: string; description: string };
const summary = parseSummary(
  readFileSync(resolve(WIKI_ROOT, "SUMMARY.md"), "utf8"),
);
const navigation = createNavigation(summary);

function canonicalRoute(relativePath: string) {
  return sourcePathToRoute(relativePath);
}

export default defineConfig({
  lang: "zh-TW",
  title: siteMeta.title,
  description: siteMeta.description,
  cleanUrls: true,
  rewrites: {
    "README.md": "index.md",
  },
  srcExclude: ["SUMMARY.md"],
  markdown: {
    config(md) {
      const renderLinkOpen =
        md.renderer.rules.link_open ??
        ((tokens, index, options, _env, self) =>
          self.renderToken(tokens, index, options));

      md.renderer.rules.link_open = (tokens, index, options, env, self) => {
        const token = tokens[index];
        const href = token.attrGet("href");
        if (href && !/^(?:[a-z]+:|\/|#)/i.test(href)) {
          const match = href.match(/^([^?#]*)(.*)$/);
          const sourceTarget = posix.normalize(
            posix.join(posix.dirname(env.relativePath ?? ""), match?.[1] ?? href),
          );
          if (sourceTarget === "README" || sourceTarget === "README.md") {
            token.attrSet("href", `/${match?.[2] ?? ""}`);
          }
        }
        return renderLinkOpen(tokens, index, options, env, self);
      };
    },
  },
  sitemap: {
    hostname: SITE_URL,
  },
  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
    ["meta", { name: "author", content: "PG72" }],
    ["meta", { name: "color-scheme", content: "light dark" }],
    ["meta", { property: "og:site_name", content: siteMeta.title }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:locale", content: "zh_TW" }],
    ["meta", { name: "twitter:card", content: "summary" }],
    [
      "meta",
      { name: "theme-color", content: "#fbfbfc", media: "(prefers-color-scheme: light)" },
    ],
    [
      "meta",
      { name: "theme-color", content: "#09090b", media: "(prefers-color-scheme: dark)" },
    ],
  ],
  transformPageData(pageData) {
    const route = canonicalRoute(pageData.relativePath);
    const canonicalUrl = new URL(route, SITE_URL).href;
    const pageTitle = pageData.title
      ? `${pageData.title} | ${siteMeta.title}`
      : siteMeta.title;

    pageData.frontmatter.head ??= [];
    pageData.frontmatter.head.push(
      ["link", { rel: "canonical", href: canonicalUrl }],
      ["meta", { property: "og:title", content: pageTitle }],
      ["meta", { property: "og:description", content: pageData.description }],
      ["meta", { property: "og:url", content: canonicalUrl }],
    );
  },
  async buildEnd(siteConfig) {
    await Promise.all([
      writeFile(
        resolve(siteConfig.outDir, "llms.txt"),
        createLlmsText(
          {
            title: siteMeta.title,
            description: siteMeta.description,
            siteUrl: SITE_URL,
          },
          summary,
        ),
        "utf8",
      ),
      ...LEGAL_FILES.map(([source, output]) =>
        copyFile(
          resolve(REPOSITORY_ROOT, source),
          resolve(siteConfig.outDir, output),
        ),
      ),
    ]);
  },
  themeConfig: {
    logo: "/favicon.svg",
    logoLink: "/",
    siteTitle: siteMeta.title,
    nav: navigation.nav,
    sidebar: navigation.sidebar,
    search: {
      provider: "local",
      options: {
        locales: {
          root: {
            translations: {
              button: {
                buttonText: "搜尋",
                buttonAriaLabel: "搜尋文件",
              },
              modal: {
                displayDetails: "顯示詳細結果",
                resetButtonTitle: "清除搜尋",
                backButtonTitle: "關閉搜尋",
                noResultsText: "找不到相符內容",
                footer: {
                  selectText: "選取",
                  selectKeyAriaLabel: "Enter 鍵",
                  navigateText: "移動",
                  navigateUpKeyAriaLabel: "向上鍵",
                  navigateDownKeyAriaLabel: "向下鍵",
                  closeText: "關閉",
                  closeKeyAriaLabel: "Esc 鍵",
                },
              },
            },
          },
        },
      },
    },
    outline: {
      level: [2, 3],
      label: "本頁目錄",
    },
    docFooter: {
      prev: "上一頁",
      next: "下一頁",
    },
    darkModeSwitchLabel: "外觀",
    lightModeSwitchTitle: "切換為淺色主題",
    darkModeSwitchTitle: "切換為深色主題",
    sidebarMenuLabel: "目錄",
    returnToTopLabel: "回到頂端",
    skipToContentLabel: "跳至主要內容",
    externalLinkIcon: true,
    notFound: {
      code: "404",
      title: "找不到這個頁面",
      quote: "這個連結可能已移動，請從目錄重新選擇。",
      linkLabel: "返回 PGID Wiki 首頁",
      linkText: "返回首頁",
    },
  },
});
