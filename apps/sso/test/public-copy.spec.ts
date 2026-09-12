/// <reference types="vite/client" />

import type { Passkey } from "@better-auth/passkey";
import { createElement, type ComponentType } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import indexHtml from "../index.html?raw";
import llmsText from "../public/llms.txt?raw";

interface PublicViews {
  AboutPage: ComponentType;
  accountChooserClientActions: {
    continueCurrent: () => Promise<unknown>;
    selectRemembered: (choiceId: string) => Promise<unknown>;
  };
  createAccountChooserClientActions: (
    customFetchImpl: typeof fetch,
  ) => {
    continueCurrent: () => Promise<unknown>;
    selectRemembered: (choiceId: string) => Promise<unknown>;
  };
  accountChoiceContinuationError: (payload: unknown) => string | null;
  adminUserErrorMessage: (code: unknown, fallback: string) => string;
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
  runSocialAuthenticationStart: (
    start: () => Promise<{ error?: unknown } | null | undefined>,
    fallback: string,
    onFailure: (message: string) => void,
  ) => Promise<boolean>;
  requestAccountChoiceContinuation: <T>(
    account: { active: boolean; choiceId: string },
    actions: {
      continueCurrent: () => Promise<T>;
      selectRemembered: (choiceId: string) => Promise<T>;
    },
  ) => Promise<T>;
  isOAuthContinuation: (payload: unknown) => boolean;
  isFreshSessionRequired: (error: unknown) => boolean;
  signInIntentCapabilities: (
    intent: "add-account" | "default" | "reauth",
  ) => {
    accountChooserBack: boolean;
    passkey: boolean;
    telegram: boolean;
  };
  telegramLoginSuccessAction: (
    payload: unknown,
  ) => "redirect" | "reload" | "invalid";
  SignInView: ComponentType<{
    intent?: "add-account" | "default" | "reauth";
    onBack?: () => void;
    pending: boolean;
  }>;
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
  it("gives invitation lifecycle conflicts refresh and retry guidance", () => {
    const message = publicViews.adminUserErrorMessage(
      "management_state_changed",
      "fallback",
    );

    expect(message).not.toBe("fallback");
    expect(message).toContain("重新整理");
    expect(message).toContain("再試");
  });

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
    expect(about).toContain("若帳號中心顯示復原碼");
    expect(`${signIn} ${terms} ${about}`).not.toContain("PG72 ID");
    expect(`${signIn} ${terms} ${about}`).not.toContain("所有服務");
  });

  it("renders bounded account-addition and reauthentication methods", () => {
    const addAccount = renderToStaticMarkup(
      createElement(publicViews.SignInView, {
        intent: "add-account",
        onBack: () => undefined,
        pending: false,
      }),
    );
    const reauthenticate = renderToStaticMarkup(
      createElement(publicViews.SignInView, {
        intent: "reauth",
        pending: false,
      }),
    );

    expect(addAccount).toContain("使用 Google 繼續");
    expect(addAccount).toContain("返回帳戶選擇");
    expect(addAccount).not.toContain("使用 Passkey");
    expect(addAccount).not.toContain("Telegram");
    expect(reauthenticate).toContain("使用 Google 繼續");
    expect(reauthenticate).toContain("使用 Passkey");
    expect(reauthenticate).not.toContain("Telegram");
    expect(reauthenticate).not.toContain("返回帳戶選擇");
  });

  it("applies the complete sign-in intent capability matrix", () => {
    expect(publicViews.signInIntentCapabilities("default")).toEqual({
      accountChooserBack: false,
      passkey: true,
      telegram: true,
    });
    expect(publicViews.signInIntentCapabilities("add-account")).toEqual({
      accountChooserBack: true,
      passkey: false,
      telegram: false,
    });
    expect(publicViews.signInIntentCapabilities("reauth")).toEqual({
      accountChooserBack: false,
      passkey: true,
      telegram: false,
    });
  });

  it("recognizes both fresh-session error response shapes", () => {
    expect(
      publicViews.isFreshSessionRequired({ code: "SESSION_NOT_FRESH" }),
    ).toBe(true);
    expect(
      publicViews.isFreshSessionRequired({ error: "fresh_session_required" }),
    ).toBe(true);
    expect(publicViews.isFreshSessionRequired({ error: "invalid_origin" })).toBe(
      false,
    );
    expect(publicViews.isFreshSessionRequired(null)).toBe(false);
  });

  it("uses exactly one browser operation for each account choice", async () => {
    const continueCurrent = vi.fn(async () => "continued");
    const selectRemembered = vi.fn(async () => "selected");

    await expect(
      publicViews.requestAccountChoiceContinuation(
        { active: true, choiceId: "current" },
        { continueCurrent, selectRemembered },
      ),
    ).resolves.toBe("continued");
    expect(continueCurrent).toHaveBeenCalledOnce();
    expect(selectRemembered).not.toHaveBeenCalled();

    continueCurrent.mockClear();
    await expect(
      publicViews.requestAccountChoiceContinuation(
        { active: false, choiceId: "remembered" },
        { continueCurrent, selectRemembered },
      ),
    ).resolves.toBe("selected");
    expect(continueCurrent).not.toHaveBeenCalled();
    expect(selectRemembered).toHaveBeenCalledOnce();
    expect(selectRemembered).toHaveBeenCalledWith("remembered");
  });

  it("classifies chooser and Telegram success payloads without owning navigation", () => {
    const continuation = {
      redirect: true,
      url: "https://rp.example/callback",
    };
    expect(publicViews.isOAuthContinuation(continuation)).toBe(true);
    expect(publicViews.isOAuthContinuation({ url: continuation.url })).toBe(false);
    expect(publicViews.isOAuthContinuation({
      redirect: false,
      url: continuation.url,
    })).toBe(false);
    expect(publicViews.isOAuthContinuation({
      redirect: true,
      url: "mailto:user@example.com",
    })).toBe(false);
    expect(publicViews.accountChoiceContinuationError(continuation)).toBeNull();
    expect(publicViews.accountChoiceContinuationError({ signedIn: true })).toBe(
      "無法繼續登入，請重新選擇帳戶。",
    );
    expect(publicViews.telegramLoginSuccessAction(continuation)).toBe(
      "redirect",
    );
    expect(publicViews.telegramLoginSuccessAction({ signedIn: true })).toBe(
      "reload",
    );
    expect(publicViews.telegramLoginSuccessAction({
      signedIn: true,
      unexpected: true,
    })).toBe("invalid");
    expect(publicViews.telegramLoginSuccessAction({
      redirect: true,
      url: "not-a-url",
    })).toBe("invalid");
  });

  it("uses the shared client for one redirect and signed-query injection", async () => {
    const runtimeWindow = globalThis as unknown as {
      window: {
        location: {
          href: string;
          origin: string;
          search: string;
        };
      };
    };
    const location = runtimeWindow.window.location;
    const originalHref = location.href;
    const originalSearch = location.search;
    let href = originalHref;
    const hrefAssignments = vi.fn((value: string) => {
      href = value;
    });
    Object.defineProperty(location, "href", {
      configurable: true,
      get: () => href,
      set: hrefAssignments,
    });
    const signedQuery = new URLSearchParams({
      ba_iat: String(Date.now()),
      client_id: "client",
      exp: String(Math.floor(Date.now() / 1_000) + 60),
      noise: "not-signed",
      sig: "signed-value",
    });
    for (const name of ["ba_iat", "ba_param", "client_id", "exp"]) {
      signedQuery.append("ba_param", name);
    }
    location.search = `?${signedQuery}`;
    const requestBodies: Record<string, unknown>[] = [];
    const isolatedFetch = vi.fn<typeof fetch>().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const text = input instanceof Request
          ? await input.clone().text()
          : typeof init?.body === "string"
            ? init.body
            : "{}";
        requestBodies.push(JSON.parse(text || "{}") as Record<string, unknown>);
        return Response.json({
          redirect: true,
          url: "https://rp.example/callback",
        });
      },
    );
    const isolatedActions = publicViews.createAccountChooserClientActions(
      isolatedFetch,
    );

    try {
      await isolatedActions.selectRemembered("opaque-choice");
      expect(hrefAssignments).toHaveBeenCalledOnce();
      expect(hrefAssignments).toHaveBeenLastCalledWith(
        "https://rp.example/callback",
      );
      const projected = new URLSearchParams(
        String(requestBodies[0]?.oauth_query ?? ""),
      );
      expect(requestBodies[0]?.choiceId).toBe("opaque-choice");
      expect(projected.get("client_id")).toBe("client");
      expect(projected.get("noise")).toBeNull();
      expect(projected.get("sig")).toBe("signed-value");

      hrefAssignments.mockClear();
      await isolatedActions.continueCurrent();
      expect(hrefAssignments).toHaveBeenCalledOnce();
      expect(requestBodies[1]?.selected).toBe(true);
      expect(requestBodies[1]?.oauth_query).toBe(requestBodies[0]?.oauth_query);
    } finally {
      location.search = originalSearch;
      Object.defineProperty(location, "href", {
        configurable: true,
        value: originalHref,
        writable: true,
      });
    }
  });

  it("limits About's centralized-management claim to PGID-owned data", () => {
    const about = renderToStaticMarkup(createElement(publicViews.AboutPage));

    expect(about).toContain(
      "集中管理 PGID 身分資料、登入方式、裝置 session 與應用授權",
    );
    expect(about).not.toContain("個人資料集中管理");
  });

  it("renders the recovery and sign-in-method warning before Passkey deletion", () => {
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
    expect(dialog).toContain("若帳號中心顯示復原碼");
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

  it("resets registration state for returned and thrown social-start errors only", async () => {
    const returnedFailure = vi.fn();
    await expect(
      publicViews.runSocialAuthenticationStart(
        async () => ({ error: { message: "provider rejected" } }),
        "fallback",
        returnedFailure,
      ),
    ).resolves.toBe(false);
    expect(returnedFailure).toHaveBeenCalledOnce();
    expect(returnedFailure).toHaveBeenCalledWith("provider rejected");

    const thrownFailure = vi.fn();
    await expect(
      publicViews.runSocialAuthenticationStart(
        async () => {
          throw new Error("network failed");
        },
        "fallback",
        thrownFailure,
      ),
    ).resolves.toBe(false);
    expect(thrownFailure).toHaveBeenCalledOnce();
    expect(thrownFailure).toHaveBeenCalledWith("network failed");

    const successfulFailure = vi.fn();
    await expect(
      publicViews.runSocialAuthenticationStart(
        async () => ({ error: undefined }),
        "fallback",
        successfulFailure,
      ),
    ).resolves.toBe(true);
    expect(successfulFailure).not.toHaveBeenCalled();
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
