/// <reference types="vite/client" />

import type { Passkey } from "@better-auth/passkey";
import { createElement, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import indexHtml from "../index.html?raw";
import llmsText from "../public/llms.txt?raw";

interface PublicViews {
  AboutPage: ComponentType;
  DeletePasskeyDialog: ComponentType<{
    busy: boolean;
    error: string | null;
    onCancel: () => void;
    onConfirm: () => void;
    passkey: Passkey;
  }>;
  LegalPage: ComponentType<{ kind: "pp" | "tos" }>;
  RegistrationPrerequisites: ComponentType<{
    onPrivacyAccepted: (accepted: boolean) => void;
    onTermsAccepted: (accepted: boolean) => void;
    onTurnstileError: () => void;
    onTurnstileToken: (token: string | null) => void;
    privacyAccepted: boolean;
    privacyVersion: string;
    resetKey: number;
    siteKey: string;
    termsAccepted: boolean;
    termsVersion: string;
  }>;
  SignInView: ComponentType<{ pending: boolean }>;
}

let publicViews: PublicViews;

// Parallel workerd transforms can push this full-App import past Vitest's
// default hook timeout.
beforeAll(async () => {
  vi.stubGlobal("window", {
    localStorage: {
      getItem: () => "dark",
      setItem: () => undefined,
    },
    location: {
      href: "http://localhost:5173/",
      origin: "http://localhost:5173",
      search: "",
    },
    matchMedia: () => ({
      addEventListener: () => undefined,
      matches: true,
      removeEventListener: () => undefined,
    }),
  });
  const appModule = "../src/" + "App.tsx";
  publicViews = (await import(/* @vite-ignore */ appModule)) as PublicViews;
}, 30_000);

afterAll(() => {
  vi.unstubAllGlobals();
});

async function metaContent(
  attribute: "name" | "property",
  value: string,
): Promise<string | null> {
  let content: string | null = null;
  const parsed = new HTMLRewriter()
    .on(`meta[${attribute}="${value}"]`, {
      element(element) {
        content = element.getAttribute("content");
      },
    })
    .transform(new Response(indexHtml));
  await parsed.text();
  return content;
}

describe("rendered public product copy", () => {
  it("renders the invite and Passkey boundaries on login, Terms, and About", () => {
    const signIn = renderToStaticMarkup(
      createElement(publicViews.SignInView, { pending: false }),
    );
    const terms = renderToStaticMarkup(
      createElement(publicViews.LegalPage, { kind: "tos" }),
    );
    const about = renderToStaticMarkup(createElement(publicViews.AboutPage));

    expect(signIn).toContain("首次建立帳號需先取得邀請");
    expect(signIn).toContain("Passkey 僅供既有帳號使用");
    expect(terms).toContain("不會取代邀請或自動建立帳號");
    expect(terms).toContain("不能用來建立帳號或繞過邀請");
    expect(about).toContain("尚未提供自助帳號復原流程");
    expect(`${signIn} ${terms} ${about}`).not.toContain("PG72 ID");
    expect(`${signIn} ${terms} ${about}`).not.toContain("所有服務");
  });

  it("limits About's centralized-management claim to PGID-owned data", () => {
    const about = renderToStaticMarkup(createElement(publicViews.AboutPage));

    expect(about).toContain(
      "集中管理 PGID 身分資料、登入方式、裝置 session 與應用授權",
    );
    expect(about).not.toContain("個人資料集中管理");
  });

  it("renders the no-self-service-recovery warning before Passkey deletion", () => {
    const passkey = {
      id: "test-passkey",
      name: "Test Passkey",
    } as Passkey;
    const dialog = renderToStaticMarkup(
      createElement(publicViews.DeletePasskeyDialog, {
        busy: false,
        error: null,
        onCancel: () => undefined,
        onConfirm: () => undefined,
        passkey,
      }),
    );

    expect(dialog).toContain("刪除後無法再用這把 Passkey 登入");
    expect(dialog).toContain("尚未提供自助帳號復原流程");
    expect(dialog).toContain("請保留至少一種可用的登入方式");
  });

  it("renders explicit legal acceptance and a stable Turnstile slot", () => {
    const prerequisites = renderToStaticMarkup(
      createElement(publicViews.RegistrationPrerequisites, {
        onPrivacyAccepted: () => undefined,
        onTermsAccepted: () => undefined,
        onTurnstileError: () => undefined,
        onTurnstileToken: () => undefined,
        privacyAccepted: false,
        privacyVersion: "2026-07-17.privacy",
        resetKey: 0,
        siteKey: "test-site-key",
        termsAccepted: false,
        termsVersion: "2026-07-17.terms",
      }),
    );

    expect(prerequisites.match(/type="checkbox"/g)).toHaveLength(2);
    expect(prerequisites).toContain('href="/tos"');
    expect(prerequisites).toContain('href="/pp"');
    expect(prerequisites).toContain('class="turnstile-slot"');
    expect(prerequisites).toContain("2026-07-17.terms");
    expect(prerequisites).toContain("2026-07-17.privacy");
  });
});

describe("static public metadata", () => {
  it("keeps indexed descriptions within implemented product boundaries", async () => {
    const description = await metaContent("name", "description");
    const openGraph = await metaContent("property", "og:description");
    const twitter = await metaContent("name", "twitter:description");

    expect(description).toContain("邀請制單一登入 beta");
    expect(description).toContain("已接入 PGID 的服務");
    expect(openGraph).toContain("Google 登入、Passkey 無密碼登入");
    expect(openGraph).toContain("集中管理 PGID session 與應用授權");
    expect(openGraph).not.toContain("集中撤銷");
    expect(twitter).toContain("Google 登入、Passkey 無密碼登入");
    expect(`${openGraph} ${twitter}`).not.toContain("Google、Passkey 無密碼登入");
  });

  it("states the same production gates in llms.txt", () => {
    expect(llmsText).toContain("Google 登入與 Passkey 無密碼登入");
    expect(llmsText).toContain("Production 目前仍是邀請制 beta");
    expect(llmsText).toContain("verified Google Email 不取代邀請");
    expect(llmsText).toContain("Passkey 只供既有帳號使用");
    expect(llmsText).toContain("接入 PGID 的服務");
    expect(llmsText).not.toContain("所有服務");
  });
});
