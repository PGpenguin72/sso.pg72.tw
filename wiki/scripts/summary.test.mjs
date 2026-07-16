import assert from "node:assert/strict";
import test from "node:test";
import {
  createLlmsText,
  createNavigation,
  parseSummary,
  sourcePathToRoute,
} from "../.vitepress/summary.mjs";

const fixture = `# 目錄

* [認識 PGID](README.md)

## 給一般使用者

* [開始使用](users/getting-started.md)
`;

test("parses GitBook sections and derives clean navigation", () => {
  const sections = parseSummary(fixture);

  assert.deepEqual(sections, [
    {
      text: null,
      items: [{ text: "認識 PGID", sourcePath: "README.md" }],
    },
    {
      text: "給一般使用者",
      items: [
        { text: "開始使用", sourcePath: "users/getting-started.md" },
      ],
    },
  ]);
  assert.deepEqual(createNavigation(sections), {
    nav: [
      { text: "認識 PGID", link: "/" },
      {
        text: "給一般使用者",
        items: [{ text: "開始使用", link: "/users/getting-started" }],
      },
    ],
    sidebar: [
      { text: "認識 PGID", link: "/" },
      {
        text: "給一般使用者",
        items: [{ text: "開始使用", link: "/users/getting-started" }],
      },
    ],
  });
});

test("derives llms.txt from the same sections", () => {
  const text = createLlmsText(
    {
      title: "PGID Wiki",
      description: "PGID docs",
      siteUrl: "https://wiki.sso.pg72.tw",
    },
    parseSummary(fixture),
  );

  assert.match(text, /^# PGID Wiki\n\n> PGID docs/);
  assert.match(text, /\[認識 PGID]\(https:\/\/wiki\.sso\.pg72\.tw\/\)/);
  assert.match(
    text,
    /\[開始使用]\(https:\/\/wiki\.sso\.pg72\.tw\/users\/getting-started\)/,
  );
});

test("maps only the GitBook README to the site root", () => {
  assert.equal(sourcePathToRoute("README.md"), "/");
  assert.equal(sourcePathToRoute("users/passkey.md"), "/users/passkey");
});

test("rejects duplicate and unsafe targets", () => {
  assert.throws(
    () => parseSummary("* [One](README.md)\n* [Two](README.md)"),
    /Duplicate SUMMARY\.md target/,
  );
  assert.throws(
    () => parseSummary("* [Escape](../private.md)"),
    /Unsafe SUMMARY\.md target/,
  );
  assert.throws(
    () => parseSummary("* [Absolute](/private.md)"),
    /Unsafe SUMMARY\.md target/,
  );
});
