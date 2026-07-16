import {
  existsSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createLlmsText,
  parseSummary,
  sourcePathToRoute,
} from "../.vitepress/summary.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const wikiRoot = resolve(scriptDir, "..");
const repositoryRoot = resolve(wikiRoot, "..");
const distDir = resolve(wikiRoot, ".vitepress/dist");
const siteUrl = "https://wiki.sso.pg72.tw";
const siteMeta = JSON.parse(readFileSync(resolve(wikiRoot, "book.json"), "utf8"));
const summary = parseSummary(readFileSync(resolve(wikiRoot, "SUMMARY.md"), "utf8"));
const pages = summary.flatMap((section) => section.items);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function walk(directory, shouldPrune = () => false) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(directory, entry.name);
    if (!entry.isDirectory()) return [path];
    return shouldPrune(path) ? [] : walk(path, shouldPrune);
  });
}

function routeToOutput(route) {
  return route === "/"
    ? resolve(distDir, "index.html")
    : resolve(distDir, `${route.slice(1)}.html`);
}

function decodeAttribute(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'");
}

function idsIn(html) {
  return new Set(
    [...html.matchAll(/\bid="([^"]+)"/g)].map((match) =>
      decodeAttribute(match[1]),
    ),
  );
}

function internalRoute(pathname) {
  if (pathname === "/" || pathname === "") return "/";
  const normalized = pathname.replace(/\/$/, "");
  return normalized || "/";
}

assert(existsSync(distDir), `Missing build output: ${distDir}`);
for (const forbidden of [
  resolve(repositoryRoot, "functions"),
  resolve(wikiRoot, "functions"),
  resolve(wikiRoot, "wrangler.jsonc"),
  resolve(distDir, "_routes.json"),
  resolve(distDir, "_worker.js"),
]) {
  assert(
    !existsSync(forbidden),
    `Static Wiki must not include Pages runtime file: ${forbidden}`,
  );
}

const sourceOnlyDirectories = new Set([
  ".vitepress",
  "node_modules",
  "public",
  "scripts",
]);
const markdownInventory = walk(wikiRoot, (path) =>
  sourceOnlyDirectories.has(relative(wikiRoot, path).replaceAll("\\", "/")),
  )
  .map((path) => relative(wikiRoot, path).replaceAll("\\", "/"))
  .filter((path) => path.endsWith(".md") && path !== "SUMMARY.md")
  .sort();
const summaryInventory = pages.map((page) => page.sourcePath).sort();
const markdownSet = new Set(markdownInventory);
const summarySet = new Set(summaryInventory);

for (const path of markdownInventory) {
  assert(
    summarySet.has(path),
    `Markdown page is missing from SUMMARY.md: ${path}`,
  );
}
for (const path of summaryInventory) {
  assert(
    markdownSet.has(path),
    `SUMMARY.md target is not a content page: ${path}`,
  );
}
assert(
  markdownInventory.length === summaryInventory.length,
  `Markdown/SUMMARY inventory mismatch: ${markdownInventory.length} source pages, ${summaryInventory.length} entries`,
);

const routeOutputs = new Map();
for (const page of pages) {
  const source = resolve(wikiRoot, page.sourcePath);
  const route = sourcePathToRoute(page.sourcePath);
  const output = routeToOutput(route);
  assert(
    existsSync(source),
    `SUMMARY.md target does not exist: ${page.sourcePath}`,
  );
  assert(existsSync(output), `Missing output for ${route}: ${output}`);
  routeOutputs.set(route, output);
}

assert(existsSync(resolve(distDir, "404.html")), "Missing 404.html");
assert(
  !existsSync(resolve(distDir, "README.html")),
  "README.html must not be emitted",
);
assert(
  !existsSync(resolve(distDir, "SUMMARY.html")),
  "SUMMARY.html must not be emitted",
);

const htmlFiles = walk(distDir).filter((path) => extname(path) === ".html");
assert(
  htmlFiles.length === pages.length + 1,
  `Expected ${pages.length} pages plus 404.html, found ${htmlFiles.length} HTML files`,
);

const htmlByRoute = new Map(
  [...routeOutputs].map(([route, output]) => [
    route,
    readFileSync(output, "utf8"),
  ]),
);

for (const [route, html] of htmlByRoute) {
  assert(html.length > 1_000, `Suspiciously small HTML output for ${route}`);
  assert(/<html\s+lang="zh-TW"/.test(html), `Missing zh-TW lang on ${route}`);
  assert(/<title>[^<]+\| PGID Wiki<\/title>/.test(html), `Bad title on ${route}`);
  assert(
    /<meta\s+name="description"\s+content="[^"]+">/.test(html),
    `Missing description on ${route}`,
  );

  const canonical = new URL(route, siteUrl).href;
  assert(
    html.includes(`<link rel="canonical" href="${canonical}">`),
    `Bad canonical URL on ${route}: expected ${canonical}`,
  );
  assert(
    !/\b(?:href|src)="[^"]*(?:README|SUMMARY)(?:\.md|\.html)?/.test(html),
    `Source-only URL leaked on ${route}`,
  );

  for (const match of html.matchAll(
    /<(a|link|script|img)\b[^>]*?\b(href|src)="([^"]+)"[^>]*>/gi,
  )) {
    const [, tag, , rawValue] = match;
    const value = decodeAttribute(rawValue);
    if (/^(?:data:|mailto:|tel:|javascript:)/i.test(value)) continue;

    const url = new URL(value, new URL(route, siteUrl));
    const isExternal = url.origin !== new URL(siteUrl).origin;
    if (isExternal) {
      assert(
        tag.toLowerCase() === "a",
        `External ${tag} resource on ${route}: ${value}`,
      );
      continue;
    }

    const pathname = decodeURIComponent(url.pathname);
    const extension = extname(pathname);
    if (extension) {
      assert(
        extension !== ".html" && extension !== ".md",
        `Non-clean URL on ${route}: ${value}`,
      );
      const asset = resolve(distDir, pathname.slice(1));
      assert(
        existsSync(asset) && statSync(asset).isFile(),
        `Missing asset on ${route}: ${value}`,
      );
      continue;
    }

    const targetRoute = internalRoute(pathname);
    const targetOutput = routeOutputs.get(targetRoute);
    assert(targetOutput, `Unknown internal route on ${route}: ${value}`);

    if (url.hash) {
      const fragment = decodeURIComponent(url.hash.slice(1));
      const targetHtml = htmlByRoute.get(targetRoute);
      assert(
        idsIn(targetHtml).has(fragment),
        `Missing fragment target on ${route}: ${value}`,
      );
    }
  }
}

for (const file of [
  "_headers",
  "favicon.svg",
  "fonts/Inter-LICENSE.txt",
  "LICENSE.txt",
  "llms.txt",
  "NOTICE.txt",
  "robots.txt",
  "sitemap.xml",
  "THIRD_PARTY_NOTICES.txt",
]) {
  assert(existsSync(resolve(distDir, file)), `Missing static output: ${file}`);
}

const legalFiles = [
  ["LICENSE", "LICENSE.txt"],
  ["NOTICE", "NOTICE.txt"],
  ["THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.txt"],
];
for (const [source, output] of legalFiles) {
  assert(
    readFileSync(resolve(repositoryRoot, source)).equals(
      readFileSync(resolve(distDir, output)),
    ),
    `${output} must be byte-equivalent to repository ${source}`,
  );
}

const thirdPartyNotices = readFileSync(
  resolve(distDir, "THIRD_PARTY_NOTICES.txt"),
  "utf8",
);
for (const marker of [
  "## Inter Font",
  "## VitePress 1.6.4",
  "## Vue 3.5.39",
  "`@vue/shared`",
  "`@vue/reactivity`",
  "`@vue/runtime-core`",
  "`@vue/runtime-dom`",
  "## VueUse 12.8.2",
  "`@vueuse/core`",
  "`@vueuse/shared`",
  "`@vueuse/integrations`",
  "## focus-trap 7.8.0",
  "## tabbable 6.5.0",
  "## MiniSearch 7.2.0",
  "## mark.js 8.11.1",
]) {
  assert(
    thirdPartyNotices.includes(marker),
    `THIRD_PARTY_NOTICES.txt missing bundled runtime marker: ${marker}`,
  );
}

const sitemap = readFileSync(resolve(distDir, "sitemap.xml"), "utf8");
const sitemapUrls = new Set(
  [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]),
);
assert(
  sitemapUrls.size === pages.length,
  `Expected ${pages.length} sitemap URLs, found ${sitemapUrls.size}`,
);
for (const route of routeOutputs.keys()) {
  const expected = new URL(route, siteUrl).href.replace(
    /\/$/,
    route === "/" ? "/" : "",
  );
  assert(sitemapUrls.has(expected), `Sitemap missing ${expected}`);
}

const robots = readFileSync(resolve(distDir, "robots.txt"), "utf8");
assert(
  robots.includes("User-agent: *\nAllow: /"),
  "robots.txt must allow the Wiki",
);
assert(robots.includes(`${siteUrl}/sitemap.xml`), "robots.txt missing sitemap URL");

const expectedLlms = createLlmsText(
  { title: siteMeta.title, description: siteMeta.description, siteUrl },
  summary,
);
assert(
  readFileSync(resolve(distDir, "llms.txt"), "utf8") === expectedLlms,
  "llms.txt is not derived from the current SUMMARY.md",
);

const headers = readFileSync(resolve(distDir, "_headers"), "utf8");
for (const required of [
  "Content-Security-Policy:",
  "frame-ancestors 'none'",
  "Permissions-Policy:",
  "Referrer-Policy: strict-origin-when-cross-origin",
  "Strict-Transport-Security: max-age=63072000; includeSubDomains",
  "X-Content-Type-Options: nosniff",
  "X-Frame-Options: DENY",
  "/assets/*",
  "immutable",
]) {
  assert(headers.includes(required), `_headers missing: ${required}`);
}
for (const line of headers.split(/\r?\n/)) {
  assert(
    line.length <= 2_000,
    `_headers line exceeds Cloudflare's 2,000 character limit`,
  );
}

const assets = walk(resolve(distDir, "assets"));
assert(
  !walk(distDir).some((path) => extname(path) === ".map"),
  "Static Wiki output must not publish source maps",
);
const css = assets
  .filter((path) => extname(path) === ".css")
  .map((path) => readFileSync(path, "utf8"))
  .join("\n");
const fonts = assets.filter((path) => extname(path) === ".woff2");
assert(
  fonts.length === 2,
  `Expected two self-hosted Inter subsets, found ${fonts.length}`,
);
assert(css.includes("@font-face"), "Built CSS is missing self-hosted fonts");
assert(!/url\(["']?https?:/i.test(css), "Built CSS references an external asset");

const themeCss = readFileSync(
  resolve(wikiRoot, ".vitepress/theme/styles.css"),
  "utf8",
);
assert(!/gradient\s*\(/i.test(themeCss), "Wiki theme must not define gradients");
assert(
  themeCss.includes(".aside-curtain") &&
    themeCss.includes(".excerpt-gradient-top"),
  "Wiki theme must neutralize VitePress's default fade layers",
);

console.log(`Validated ${pages.length} clean Wiki routes and ${assets.length} built assets.`);
