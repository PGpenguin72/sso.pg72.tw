/// <reference types="vite/client" />

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

interface AdminOAuthClient {
  backchannelLogoutUri: string | null;
  clientId: string;
  createdAt: string | null;
  developerName: string | null;
  disabled: boolean;
  enableEndSession: boolean;
  grantTypes: string[];
  hasSecret: boolean;
  name: string;
  ownerUserId: string | null;
  postLogoutRedirectUris: string[];
  privacyPolicyUrl: string | null;
  public: boolean;
  redirectUris: string[];
  scopes: string[];
  termsOfServiceUrl: string | null;
  tokenEndpointAuthMethod: string | null;
  trusted: boolean;
  updatedAt: string | null;
  uri: string | null;
}

interface ClientViews {
  buildAdminClientUpdate: (
    client: AdminOAuthClient,
    draft: {
      backchannelLogoutUri: string;
      developerName: string;
      emailScope: boolean;
      enableEndSession: boolean;
      expectedUpdatedAt: string | null;
      name: string;
      offlineAccess: boolean;
      postLogoutRedirectUris: string;
      privacyPolicyUrl: string;
      profileScope: boolean;
      redirectUris: string;
      termsOfServiceUrl: string;
      uri: string;
    },
  ) => Record<string, unknown>;
}

let clientViews: ClientViews;

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
  clientViews = (await import(/* @vite-ignore */ appModule)) as ClientViews;
}, 30_000);

afterAll(() => {
  vi.unstubAllGlobals();
});

function client(overrides: Partial<AdminOAuthClient> = {}): AdminOAuthClient {
  return {
    backchannelLogoutUri: null,
    clientId: "test-client",
    createdAt: "2026-07-17T00:00:00.000Z",
    developerName: "PG72",
    disabled: false,
    enableEndSession: false,
    grantTypes: ["authorization_code"],
    hasSecret: true,
    name: "Test Client",
    ownerUserId: "owner",
    postLogoutRedirectUris: [],
    privacyPolicyUrl: null,
    public: false,
    redirectUris: ["https://app.example/callback"],
    scopes: ["openid"],
    termsOfServiceUrl: null,
    tokenEndpointAuthMethod: "client_secret_post",
    trusted: false,
    updatedAt: "2026-07-17T00:00:00.000Z",
    uri: null,
    ...overrides,
  };
}

const baseDraft = {
  backchannelLogoutUri: "",
  developerName: "  PG72 Team  ",
  emailScope: false,
  enableEndSession: true,
  expectedUpdatedAt: "2026-07-17T00:00:00.000Z",
  name: "  Updated Client  ",
  offlineAccess: false,
  postLogoutRedirectUris: " https://app.example/signed-out \n\n",
  privacyPolicyUrl: "",
  profileScope: false,
  redirectUris:
    " https://app.example/callback-v2 \n\nhttps://app.example/callback-v3 ",
  termsOfServiceUrl: "",
  uri: " https://app.example/ ",
};

describe("OAuth client edit payload", () => {
  it("parses editable settings without adding unrequested profile or email scopes", () => {
    expect(clientViews.buildAdminClientUpdate(client(), baseDraft)).toEqual({
      backchannelLogoutUri: null,
      developerName: "PG72 Team",
      enableEndSession: true,
      expectedUpdatedAt: "2026-07-17T00:00:00.000Z",
      grantTypes: ["authorization_code"],
      name: "Updated Client",
      postLogoutRedirectUris: ["https://app.example/signed-out"],
      privacyPolicyUrl: null,
      redirectUris: [
        "https://app.example/callback-v2",
        "https://app.example/callback-v3",
      ],
      scopes: ["openid"],
      termsOfServiceUrl: null,
      uri: "https://app.example/",
    });
  });

  it("adds offline access and refresh exactly once", () => {
    const payload = clientViews.buildAdminClientUpdate(
      client({
        grantTypes: ["authorization_code", "refresh_token"],
        scopes: ["openid", "email", "offline_access"],
      }),
      { ...baseDraft, emailScope: true, offlineAccess: true },
    );

    expect(payload.scopes).toEqual(["openid", "email", "offline_access"]);
    expect(payload.grantTypes).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
  });

  it("does not send authorization settings for a service client", () => {
    const payload = clientViews.buildAdminClientUpdate(
      client({
        grantTypes: ["urn:pg72:grant-type:introspection-only"],
        redirectUris: [],
        scopes: [],
      }),
      { ...baseDraft, offlineAccess: true },
    );

    expect(payload).toEqual({
      backchannelLogoutUri: null,
      developerName: "PG72 Team",
      expectedUpdatedAt: "2026-07-17T00:00:00.000Z",
      name: "Updated Client",
      privacyPolicyUrl: null,
      termsOfServiceUrl: null,
      uri: "https://app.example/",
    });
  });

  it("uses the version captured when editing began after the list reloads", () => {
    const payload = clientViews.buildAdminClientUpdate(
      client({ updatedAt: "2026-07-17T00:05:00.000Z" }),
      baseDraft,
    );

    expect(payload.expectedUpdatedAt).toBe("2026-07-17T00:00:00.000Z");
  });
});
