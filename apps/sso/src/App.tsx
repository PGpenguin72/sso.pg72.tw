import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BookOpen,
  Check,
  Code2,
  ExternalLink,
  FileText,
  Flag,
  Globe,
  Image as ImageIcon,
  ImagePlus,
  KeyRound,
  Laptop,
  LogIn,
  LogOut,
  Mail,
  Menu,
  MonitorSmartphone,
  Moon,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Sparkles,
  Sun,
  Trash2,
  Upload,
  UserRound,
  Users,
  X,
} from "lucide-react";
import type { Passkey } from "@better-auth/passkey";
import {
  startAuthentication,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import type { ReactNode } from "react";
import { useCallback, useEffect, useRef, useState } from "react";

import { authClient } from "./auth-client";
import { PUBLIC_PRODUCT_COPY } from "./public-copy";

interface DeviceSession {
  id: string;
  token: string;
  updatedAt: string | Date;
  userAgent?: string | null;
}

interface ConsentClientInfo {
  clientId: string;
  name: string;
  developerName: string | null;
  privacyPolicyUrl: string | null;
  termsOfServiceUrl: string | null;
  redirectHosts: string[];
  scopes: string[];
}

interface ConsentClientResponse {
  client?: ConsentClientInfo;
}

interface AuthorizedApplication {
  id: string;
  clientId: string;
  name: string;
  uri: string | null;
  scopes: string[];
  createdAt: string;
  updatedAt: string;
}

interface AuthorizationsResponse {
  authorizations: AuthorizedApplication[];
  canDeleteAccount: boolean;
}

interface AdminOAuthClient {
  clientId: string;
  name: string;
  developerName: string | null;
  privacyPolicyUrl: string | null;
  termsOfServiceUrl: string | null;
  uri: string | null;
  disabled: boolean;
  public: boolean;
  scopes: string[];
  redirectUris: string[];
  grantTypes: string[];
  tokenEndpointAuthMethod: string | null;
  hasSecret: boolean;
  trusted: boolean;
  ownerUserId: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

type PlatformRole = "bootadmin" | "admin" | "developer" | "user";

interface AdminUserView {
  id: string;
  name: string;
  email: string;
  role: PlatformRole;
  status: "active" | "suspended" | "pending_telegram";
  createdAt: string;
  lastSessionAt: string | null;
  passkeyCount: number;
  authorizedAppCount: number;
}

interface AdminUsersResponse {
  page: number;
  perPage: number;
  total: number;
  viewerRole: PlatformRole;
  users: AdminUserView[];
}

const ROLE_LABELS: Record<PlatformRole, string> = {
  bootadmin: "Bootadmin",
  admin: "Admin",
  developer: "Developer",
  user: "User",
};

/** Mirrors the worker-side ASSIGNABLE_ROLES matrix for UI affordances. */
const UI_ASSIGNABLE_ROLES: Record<PlatformRole, readonly PlatformRole[]> = {
  bootadmin: ["admin", "developer", "user"],
  admin: ["developer", "user"],
  developer: [],
  user: [],
};

const ADMIN_USER_ERROR_MESSAGES: Record<string, string> = {
  bootadmin_protected: "Bootstrap administrator 受系統保護，無法變更。",
  cannot_modify_self: "不能對自己的帳號執行這個操作。",
  cannot_suspend_self: "不能停權自己的帳號。",
  invalid_role: "角色無效。",
  rate_limited: "操作太頻繁，請稍後再試。",
  role_not_assignable: "你的角色無法執行這個角色變更。",
  user_not_found: "找不到這個使用者，請重新整理列表。",
};

function adminUserErrorMessage(code: unknown, fallback: string): string {
  return typeof code === "string"
    ? (ADMIN_USER_ERROR_MESSAGES[code] ?? fallback)
    : fallback;
}

interface AdminClientsResponse {
  clients: AdminOAuthClient[];
}

type AvatarSource = "generated" | "google" | "upload";

interface AccountProfileResponse {
  name: string;
  image: string | null;
  avatarSource: AvatarSource;
  generatedAvatarUrl: string;
  googleAvatarUrl: string | null;
  /** URL of a self-hosted uploaded avatar, when one exists. */
  uploadedAvatarUrl?: string | null;
}

interface SecurityActivityEvent {
  id: string;
  type: string;
  at: string;
  summary: string;
  provider?: string | null;
}

interface SecurityActivityResponse {
  events: SecurityActivityEvent[];
  nextCursor?: string | null;
}

// Ids must match the Worker's accepted enum in worker/oauth-reports.ts.
type ReportReason = "scope_abuse" | "impersonation" | "other" | "phishing";

const REPORT_REASONS: { id: ReportReason; label: string }[] = [
  { id: "impersonation", label: "冒名或假冒官方" },
  { id: "phishing", label: "釣魚或竊取帳號" },
  { id: "scope_abuse", label: "濫用權限或過度索取資料" },
  { id: "other", label: "其他問題" },
];

/**
 * Human labels for security-activity event types. Unknown types fall back to
 * the raw string so a new Worker-side event never renders blank.
 */
const SECURITY_ACTIVITY_LABELS: Record<string, string> = {
  "account.deleted": "帳號刪除",
  "login.passkey": "以 Passkey 登入",
  "login.social": "社群帳號登入",
  "login.success": "登入成功",
  "oauth.authorized": "授權應用程式",
  "oauth.consent": "同意應用程式存取",
  "oauth.revoked": "撤銷應用程式授權",
  "passkey.added": "新增 Passkey",
  "passkey.removed": "刪除 Passkey",
  "passkey.renamed": "重新命名 Passkey",
  "passkey.step_up_failed": "Passkey 驗證失敗",
  "passkey.step_up_succeeded": "Passkey 驗證成功",
  "profile.updated": "更新個人資料",
  "session.revoked": "撤銷裝置 session",
  "session.revoked_all": "登出其他裝置",
};

function securityActivityLabel(type: string): string {
  return SECURITY_ACTIVITY_LABELS[type] ?? type;
}

interface LoginMethodProvider {
  id: string;
  provider: string;
  createdAt: string;
  canUnlink: boolean;
}

interface LoginMethodsResponse {
  providers: LoginMethodProvider[];
  passkeyCount: number;
  linkable: string[];
}

/**
 * Sign-in providers a user may explicitly link from the account center.
 * Adding a future provider only requires a new entry here plus the Worker-side
 * provider registration; listing/unlink policy is provider-agnostic.
 */
const LINKABLE_PROVIDER_DETAILS = {
  google: { label: "Google" },
  discord: { label: "Discord" },
  github: { label: "GitHub" },
  facebook: { label: "Facebook" },
  telegram: { label: "Telegram" },
} as const;

type LinkableProviderId = keyof typeof LINKABLE_PROVIDER_DETAILS;

function isLinkableProviderId(value: string): value is LinkableProviderId {
  return value in LINKABLE_PROVIDER_DETAILS;
}

function providerLabel(provider: string): string {
  return isLinkableProviderId(provider)
    ? LINKABLE_PROVIDER_DETAILS[provider].label
    : provider;
}

interface CreatedAdminClientResponse {
  client: AdminOAuthClient;
  clientSecret?: string;
}

interface PasskeyStepUpChallengeResponse {
  challengeId?: string;
  error?: string;
  options?: PublicKeyCredentialRequestOptionsJSON;
  verified?: boolean;
}

const ADMIN_CLIENT_ERROR_MESSAGES: Record<string, string> = {
  client_exists: "這個 Client ID 已存在。",
  invalid_client_id: "Client ID 格式無效（小寫英數、-、_、.，3-64 字元）。",
  invalid_client_name: "名稱不能是空白且不可超過 64 字元。",
  invalid_developer_name: "開發者名稱為必填，且不可超過 64 字元。",
  invalid_privacy_policy_url: "隱私權政策必須是完整的 HTTPS URL。",
  invalid_terms_of_service_url: "服務條款必須是完整的 HTTPS URL。",
  passkey_enrollment_required:
    "請先在「安全性」新增 Passkey，再執行這個操作。",
  passkey_step_up_required: "請先完成 Passkey 驗證。",
  fresh_session_required: "登入時間已超過 10 分鐘，請重新登入。",
  invalid_redirect_uri:
    "Redirect URI 必須是完整的 HTTPS URL，不允許 wildcard 或 fragment。",
  invalid_scopes: "Scopes 只能是 openid/profile/email/offline_access。",
  rate_limited: "操作太頻繁，請稍後再試。",
  refresh_token_requires_offline_access:
    "啟用 refresh token 時必須包含 offline_access scope。",
  skip_consent_not_allowed: "所有 client 都必須經過使用者同意。",
  trusted_client_locked: "Trusted client 只能透過 seed 或 migration 調整。",
};

function adminClientErrorMessage(code: unknown, fallback: string): string {
  return typeof code === "string"
    ? (ADMIN_CLIENT_ERROR_MESSAGES[code] ?? fallback)
    : fallback;
}

type Tab =
  | "account"
  | "security"
  | "activity"
  | "apps"
  | "developer"
  | "admin";
type Theme = "dark" | "light";
type LoadState = "error" | "loading" | "ready";

// Must not exceed the Worker's stored-avatar ceiling (256 KiB after decode) so
// the client rejects oversized files before an upload the server would refuse.
const MAX_AVATAR_BYTES = 256 * 1024;
const ACCEPTED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp"];
const ACCEPTED_AVATAR_HINT = "支援 PNG、JPG 或 WebP，檔案上限 256 KB、2048px。";

/** Developer resource links; wiki/API handbook are produced by the docs agent. */
const DEVELOPER_RESOURCES: { label: string; description: string; href: string }[] =
  [
    {
      label: "OAuth / OIDC 串接手冊",
      description: "Authorization Code + PKCE、scopes 與 token 交換說明。",
      href: "https://wiki.sso.pg72.tw/developers/oidc-flow",
    },
    {
      label: "建立 OAuth Client",
      description: "client 設定、redirect URI 規範與最佳實務。",
      href: "https://wiki.sso.pg72.tw/developers/register-client",
    },
    {
      label: "PGID 開發者 Wiki",
      description: "完整開發者文件與 FAQ。",
      href: "https://wiki.sso.pg72.tw",
    },
  ];

const THEME_STORAGE_KEY = "pg72_theme";

function preferredTheme(): Theme {
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === "dark" || stored === "light") return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "dark" ? "#050506" : "#f6f7f9");
}

function messageFrom(error: unknown, fallback: string): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "message" in error &&
    typeof error.message === "string" &&
    error.message.length > 0
  ) {
    return error.message;
  }
  return fallback;
}

function formatDate(value: string | Date): string {
  return new Intl.DateTimeFormat("zh-TW", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function passkeyMetadata(passkey: Passkey): string {
  const authenticator =
    passkey.deviceType === "multiDevice" ? "同步式 Passkey" : "裝置 Passkey";
  return `${authenticator} · ${passkey.backedUp ? "已備份" : "未備份"}`;
}

function deviceIcon(userAgent?: string | null) {
  const value = userAgent?.toLowerCase() ?? "";
  if (/iphone|android|mobile/.test(value)) {
    return <Smartphone aria-hidden="true" />;
  }
  return <Laptop aria-hidden="true" />;
}

function friendlyDevice(userAgent?: string | null): string {
  if (!userAgent) return "Unknown device";
  if (/iphone/i.test(userAgent)) return "iPhone";
  if (/ipad/i.test(userAgent)) return "iPad";
  if (/android/i.test(userAgent)) return "Android device";
  if (/macintosh|mac os/i.test(userAgent)) return "Mac";
  if (/windows/i.test(userAgent)) return "Windows device";
  if (/linux/i.test(userAgent)) return "Linux device";
  return "Web browser";
}

function Brand() {
  return (
    <a className="brand" href="/" aria-label="PGID">
      <span className="brand-mark" aria-hidden="true">🐧</span>
      <span>PGID</span>
    </a>
  );
}

function ThemeToggle({ floating = false }: { floating?: boolean }) {
  const [theme, setTheme] = useState<Theme>(preferredTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    if (window.localStorage.getItem(THEME_STORAGE_KEY)) return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const followSystem = (event: MediaQueryListEvent) => {
      setTheme(event.matches ? "dark" : "light");
    };
    media.addEventListener("change", followSystem);
    return () => media.removeEventListener("change", followSystem);
  }, []);

  const nextTheme = theme === "dark" ? "light" : "dark";
  const label = nextTheme === "dark" ? "切換為深色模式" : "切換為淺色模式";

  return (
    <button
      type="button"
      className={`icon-button theme-toggle${floating ? " theme-toggle-floating" : ""}`}
      aria-label={label}
      title={label}
      onClick={() => {
        window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
        setTheme(nextTheme);
      }}
    >
      {theme === "dark" ? (
        <Sun aria-hidden="true" />
      ) : (
        <Moon aria-hidden="true" />
      )}
    </button>
  );
}

/**
 * Provider id + label for the client's `signIn.social`. `telegram` is not one of
 * Better Auth's built-in social providers, so the id is cast at the call site;
 * whether it actually works depends on the Worker-side provider configuration.
 */
type SocialProviderId = Parameters<typeof authClient.signIn.social>[0]["provider"];

// Telegram is intentionally absent: it is not an OAuth provider and does not go
// through `signIn.social`. It uses the Telegram Login Widget (see TelegramLogin).
const SOCIAL_SIGN_IN_PROVIDERS: { id: string; label: string }[] = [
  { id: "discord", label: "Discord" },
  { id: "github", label: "GitHub" },
  { id: "facebook", label: "Facebook" },
  { id: "apple", label: "Apple" },
];

interface TelegramConfig {
  enabled: boolean;
  botUsername: string | null;
}

/**
 * Telegram Login Widget button. Telegram authenticates via its own official
 * embed, which posts a signed payload; we forward it to the Worker's
 * `/api/auth/telegram` endpoint (which verifies the HMAC server-side). Using
 * the embed directly avoids the widget script's currentScript race when the
 * script is injected after React has mounted.
 */
function TelegramLogin({
  config,
  disabled,
  endpoint = "/api/auth/telegram",
  onSuccess,
}: {
  config: TelegramConfig;
  disabled: boolean;
  endpoint?: string;
  onSuccess?: () => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!config.enabled || !config.botUsername || !containerRef.current) return;
    const container = containerRef.current;
    const iframe = document.createElement("iframe");
    const widgetOrigin = "https://oauth.telegram.org";
    const widgetUrl = `${widgetOrigin}/embed/${encodeURIComponent(config.botUsername)}?origin=${encodeURIComponent(window.location.origin)}&return_to=${encodeURIComponent(window.location.href)}&size=large&radius=8`;
    iframe.src = widgetUrl;
    iframe.title = "使用 Telegram 登入";
    iframe.setAttribute("frameborder", "0");
    iframe.setAttribute("scrolling", "no");
    iframe.style.width = "238px";
    iframe.style.height = "48px";
    iframe.style.border = "0";
    container.appendChild(iframe);

    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== widgetOrigin || event.source !== iframe.contentWindow) {
        return;
      }
      let data: { event?: string; auth_data?: Record<string, unknown> };
      try {
        data = typeof event.data === "string" ? JSON.parse(event.data) : event.data;
      } catch {
        return;
      }
      if (data?.event !== "auth_user" || !data.auth_data) return;
      setError(null);
      void fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(data.auth_data),
      })
        .then((res) => {
          if (!res.ok) throw new Error("telegram_login_failed");
          if (onSuccess) onSuccess();
          else window.location.reload();
        })
        .catch(() => setError("Telegram 登入失敗，請稍後再試。"));
    };
    window.addEventListener("message", handleMessage);
    return () => {
      window.removeEventListener("message", handleMessage);
      container.replaceChildren();
    };
  }, [config, endpoint, onSuccess]);

  // The parent only mounts this when Telegram is configured; render nothing
  // otherwise so a stray disabled button never appears.
  if (!config.enabled) return null;
  return (
    <div className="telegram-login" aria-disabled={disabled}>
      <div ref={containerRef} />
      {error ? <div className="notice notice-error">{error}</div> : null}
    </div>
  );
}

export function SignInView({ pending }: { pending: boolean }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enabledSocial, setEnabledSocial] = useState<string[] | null>(null);
  const [telegramConfig, setTelegramConfig] = useState<TelegramConfig | null>(
    null,
  );
  const query = new URLSearchParams(window.location.search);
  const oauthQuery = query.has("client_id") && query.has("sig");

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/social-config", { headers: { accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : { enabled: [] }))
      .then((c: { enabled?: string[] }) => {
        if (!cancelled) setEnabledSocial(Array.isArray(c.enabled) ? c.enabled : []);
      })
      .catch(() => {
        if (!cancelled) setEnabledSocial([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/telegram/config", { headers: { accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : { enabled: false, botUsername: null }))
      .then((c: TelegramConfig) => {
        if (!cancelled) {
          setTelegramConfig({
            enabled: c.enabled === true,
            botUsername: c.botUsername ?? null,
          });
        }
      })
      .catch(() => {
        if (!cancelled) setTelegramConfig({ enabled: false, botUsername: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Wait for both config fetches before showing any social buttons so the row
  // does not flash a full set and then collapse as unconfigured ones drop out.
  const socialConfigReady = enabledSocial !== null && telegramConfig !== null;
  const visibleSocial = enabledSocial
    ? SOCIAL_SIGN_IN_PROVIDERS.filter((p) => enabledSocial.includes(p.id))
    : [];
  const telegramEnabled = telegramConfig?.enabled === true;
  // Hide the divider + grid entirely when nothing in the section is available.
  const showSocialSection =
    socialConfigReady && (visibleSocial.length > 0 || telegramEnabled);

  const socialSignIn = async (provider: string, label: string) => {
    setBusy(provider);
    setError(null);
    const result = await authClient.signIn.social({
      provider: provider as SocialProviderId,
      callbackURL: window.location.href,
    });
    if (result?.error) {
      setError(messageFrom(result.error, `${label} 登入失敗，請稍後再試。`));
      setBusy(null);
    }
  };

  const googleSignIn = () => void socialSignIn("google", "Google");

  const passkeySignIn = async () => {
    setBusy("passkey");
    setError(null);
    const result = await authClient.signIn.passkey();
    if (result.error) {
      setError(messageFrom(result.error, "Passkey sign-in failed."));
    }
    setBusy(null);
  };

  return (
    <>
      <ThemeToggle floating />
      <main className="sign-in-shell">
        <div className="sign-in-heading">
          <Brand />
          <span className="eyebrow">Secure account</span>
          <h1>{oauthQuery ? "繼續登入" : "登入 PGID"}</h1>
          <p>{PUBLIC_PRODUCT_COPY.signIn}</p>
        </div>

        <div className="auth-actions" aria-busy={pending || busy !== null}>
          <button
            className="button button-primary button-wide"
            type="button"
            onClick={googleSignIn}
            disabled={pending || busy !== null}
          >
            <LogIn aria-hidden="true" />
            {busy === "google" ? "正在連線..." : "使用 Google 繼續"}
          </button>
          <button
            className="button button-secondary button-wide"
            type="button"
            onClick={passkeySignIn}
            disabled={pending || busy !== null}
          >
            <KeyRound aria-hidden="true" />
            {busy === "passkey" ? "等待驗證..." : "使用 Passkey"}
          </button>
        </div>

        {showSocialSection ? (
          <>
            <div className="auth-divider" role="separator">
              <span>或使用其他帳號</span>
            </div>

            <div className="social-grid" aria-busy={pending || busy !== null}>
              {visibleSocial.map((provider) => (
                <button
                  key={provider.id}
                  className="button button-secondary"
                  type="button"
                  disabled={pending || busy !== null}
                  onClick={() => void socialSignIn(provider.id, provider.label)}
                >
                  {busy === provider.id ? "正在連線..." : provider.label}
                </button>
              ))}
              {telegramEnabled && telegramConfig ? (
                <TelegramLogin
                  config={telegramConfig}
                  disabled={pending || busy !== null}
                />
              ) : null}
            </div>
          </>
        ) : null}

        {error ? <div className="notice notice-error">{error}</div> : null}
        <p className="invite-note">
          <ShieldCheck aria-hidden="true" />
          登入即表示你同意
          <a href="/tos">服務條款</a>與<a href="/pp">隱私權政策</a>
          <span aria-hidden="true"> · </span>
          <a href="/about">了解 PGID</a>
        </p>
      </main>
    </>
  );
}

function PendingTelegramView() {
  const [enabledSocial, setEnabledSocial] = useState<string[]>(["google"]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/auth/telegram/complete", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        if (response.ok) {
          window.location.reload();
          return;
        }
        if (response.status !== 409) throw new Error("complete_failed");
        const configResponse = await fetch("/api/auth/social-config", {
          headers: { accept: "application/json" },
        });
        const config = configResponse.ok
          ? ((await configResponse.json()) as { enabled?: string[] })
          : {};
        if (!cancelled) {
          setEnabledSocial(
            ["google", ...(Array.isArray(config.enabled) ? config.enabled : [])]
              .filter((provider, index, all) => all.indexOf(provider) === index),
          );
        }
      })
      .catch(() => {
        if (!cancelled) setError("無法載入綁定設定，請重新整理。");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const linkProvider = async (provider: string) => {
    setBusy(provider);
    setError(null);
    try {
      const result = await authClient.linkSocial({
        provider: provider as SocialProviderId,
        callbackURL: window.location.origin,
      });
      if (result.error) {
        setError(messageFrom(result.error, "無法完成登入方式綁定。"));
        setBusy(null);
      }
    } catch (linkError: unknown) {
      setError(messageFrom(linkError, "無法完成登入方式綁定。"));
      setBusy(null);
    }
  };

  return (
    <>
      <ThemeToggle floating />
      <main className="sign-in-shell">
        <div className="sign-in-heading">
          <Brand />
          <span className="eyebrow">Complete your account</span>
          <h1>完成 PGID 設定</h1>
          <p>你已使用 Telegram 建立 PGID，請綁定其他登入帳號才能使用。</p>
        </div>
        <div className="auth-actions" aria-busy={busy !== null}>
          {enabledSocial.map((provider) => (
            <button
              key={provider}
              className="button button-secondary button-wide"
              type="button"
              disabled={busy !== null}
              onClick={() => void linkProvider(provider)}
            >
              <LogIn aria-hidden="true" />
              {busy === provider ? "正在連線..." : `綁定 ${provider === "google" ? "Google" : provider}`}
            </button>
          ))}
        </div>
        {error ? <div className="notice notice-error">{error}</div> : null}
      </main>
    </>
  );
}

const SCOPE_DETAILS: Record<string, { label: string; description: string }> = {
  openid: {
    label: "確認你的身分",
    description: "以唯一識別碼辨識你的 PGID 帳號。",
  },
  profile: {
    label: "查看基本個人資料",
    description: "包含你的顯示名稱與帳號頭像。",
  },
  email: {
    label: "查看電子郵件地址",
    description: "包含信箱地址與信箱是否已驗證。",
  },
  offline_access: {
    label: "在你離線時保持連線",
    description: "允許應用程式在你離開後更新登入權杖。",
  },
};

const OFFLINE_ACCESS_NOTICE = "離線存取：應用在你離線時仍可存取。";
const DEVELOPER_NAME_FALLBACK = "PG72 官方";

function scopeIcon(scope: string) {
  if (scope === "email") return <Mail aria-hidden="true" />;
  if (scope === "profile") return <UserRound aria-hidden="true" />;
  if (scope === "offline_access") return <RefreshCw aria-hidden="true" />;
  return <ShieldCheck aria-hidden="true" />;
}

function safeClientHost(uri?: string): string | null {
  if (!uri) return null;
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "https:") return null;
    return parsed.host;
  } catch {
    return null;
  }
}

function safeOAuthRedirect(uri: string): string | null {
  try {
    const target = new URL(uri);
    const isLocalHttp =
      target.protocol === "http:" &&
      (target.hostname === "localhost" || target.hostname === "127.0.0.1");
    if ((target.protocol !== "https:" && !isLocalHttp) || target.username || target.password) {
      return null;
    }
    return target.toString();
  } catch {
    return null;
  }
}

function TrustLink({ label, url }: { label: string; url: string | null }) {
  return (
    <div className="trust-link-row">
      <dt>{label}</dt>
      <dd>
        {url ? (
          <a href={url} target="_blank" rel="noopener noreferrer">
            檢視
          </a>
        ) : (
          <span className="trust-missing">開發者未提供</span>
        )}
      </dd>
    </div>
  );
}

function ConsentView({
  clientId,
  userEmail,
  userName,
  userImage,
}: {
  clientId: string | null;
  userEmail: string;
  userName: string;
  userImage: string | null;
}) {
  const [busy, setBusy] = useState<"allow" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [client, setClient] = useState<ConsentClientInfo | null>(null);
  const [clientLoading, setClientLoading] = useState(true);
  const [reportOpen, setReportOpen] = useState(false);
  const scope =
    new URLSearchParams(window.location.search).get("scope") ?? "openid";
  // Only the scopes requested by this authorization request are listed. The
  // query string was signed by the Worker when it redirected here, and the
  // provider rejects any consent decision whose signed query was tampered
  // with, as well as any scope outside the client's registration.
  const scopes = scope.split(" ").filter(Boolean);
  const appName = client?.name ?? "這個應用程式";

  useEffect(() => {
    if (!clientId) {
      setError("缺少應用程式識別資料，請重新開始登入流程。");
      setClientLoading(false);
      return;
    }

    const controller = new AbortController();
    const loadClient = async () => {
      // Server-side client registration data straight from D1. Nothing shown
      // in the identity block can be influenced by authorization request
      // parameters.
      const query = new URLSearchParams({ client_id: clientId });
      const response = await fetch(`/api/consent/client?${query}`, {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error("Unable to load OAuth client metadata");
      }

      const data = (await response.json()) as ConsentClientResponse;
      if (!data.client || data.client.clientId !== clientId || !data.client.name) {
        throw new Error("OAuth client metadata did not match the request");
      }
      setClient(data.client);
      setClientLoading(false);
    };

    void loadClient().catch((loadError: unknown) => {
      if (!(loadError instanceof DOMException && loadError.name === "AbortError")) {
        setError("無法載入應用程式資料，請重新開始登入流程。");
        setClientLoading(false);
      }
    });
    return () => controller.abort();
  }, [clientId]);

  const decide = async (accept: boolean) => {
    setBusy(accept ? "allow" : "deny");
    setError(null);
    try {
      // Cancelling returns the user to the relying party with an
      // access_denied error redirect built by the provider.
      const result = await authClient.oauth2.consent({ accept });
      if (result.error) {
        setError(messageFrom(result.error, "無法處理授權，請稍後再試。"));
        return;
      }

      const redirect = result.data;
      const target =
        redirect?.redirect === true && typeof redirect.url === "string"
          ? safeOAuthRedirect(redirect.url)
          : null;
      if (!target) {
        setError("授權已處理，但無法取得安全的返回網址，請重新開始登入流程。");
        return;
      }

      // Better Auth also performs this redirect; replace is a safe fallback and
      // prevents the completed consent page from remaining in browser history.
      window.location.replace(target);
    } catch (consentError: unknown) {
      setError(messageFrom(consentError, "網路連線失敗，請稍後再試。"));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <ThemeToggle floating />
      <main className="consent-shell" aria-busy={busy !== null || clientLoading}>
        <div className="consent-brandbar">
          <Brand />
        </div>
        <section className="consent-card">
          <header className="consent-app">
            <span className="consent-app-glyph">
              <MonitorSmartphone aria-hidden="true" />
            </span>
            <div className="consent-app-meta">
              <span className="eyebrow">應用程式授權</span>
              <h1>{appName} 想要存取你的 PGID 帳號</h1>
              {client ? (
                <p className="consent-developer">
                  由 <strong>{client.developerName ?? DEVELOPER_NAME_FALLBACK}</strong> 提供
                </p>
              ) : null}
            </div>
          </header>

          {client && client.redirectHosts.length > 0 ? (
            <div className="consent-domain">
              <Globe aria-hidden="true" />
              <div className="consent-domain-copy">
                <span className="consent-domain-label">授權後將前往</span>
                <strong className="consent-domain-value">
                  {client.redirectHosts.join("、")}
                </strong>
                <span className="consent-domain-hint">
                  這是此應用註冊時綁定的網域，請確認它是你信任的網站。
                </span>
              </div>
            </div>
          ) : null}

          <div className="consent-account-card">
            {userImage ? (
              <img
                className="consent-account-avatar"
                src={userImage}
                alt=""
                referrerPolicy="no-referrer"
              />
            ) : (
              <span className="consent-account-avatar avatar-fallback">
                <UserRound aria-hidden="true" />
              </span>
            )}
            <div className="consent-account-meta">
              <span className="consent-account-label">目前登入身分</span>
              <strong>{userName}</strong>
              <span className="consent-account-email">{userEmail}</span>
            </div>
          </div>

          <h2 className="scope-heading">{appName} 將能夠存取：</h2>
          <ul className="scope-list">
            {scopes.map((item) => {
              const details = SCOPE_DETAILS[item] ?? {
                label: item,
                description: "使用這項由應用程式要求的權限。",
              };
              return (
                <li key={item}>
                  {scopeIcon(item)}
                  <span className="scope-copy">
                    <strong>{details.label}</strong>
                    <span>{details.description}</span>
                    {item === "offline_access" ? (
                      <span className="scope-offline-flag">
                        {OFFLINE_ACCESS_NOTICE}
                      </span>
                    ) : null}
                  </span>
                </li>
              );
            })}
          </ul>

          <dl className="trust-links">
            <TrustLink label="服務條款" url={client?.termsOfServiceUrl ?? null} />
            <TrustLink
              label="隱私權政策"
              url={client?.privacyPolicyUrl ?? null}
            />
          </dl>

          {error ? (
            <div className="notice notice-error" role="alert">
              {error}
            </div>
          ) : null}

          <div className="consent-actions">
            <button
              type="button"
              className="button button-secondary"
              disabled={busy !== null || clientLoading || !clientId}
              onClick={() => void decide(false)}
            >
              <X aria-hidden="true" />
              {busy === "deny" ? "返回中..." : "取消"}
            </button>
            <button
              type="button"
              className="button button-primary"
              disabled={busy !== null || clientLoading || !client}
              onClick={() => void decide(true)}
            >
              <Check aria-hidden="true" />
              {busy === "allow" ? "返回中..." : "允許"}
            </button>
          </div>

          <button
            type="button"
            className="consent-report"
            disabled={!clientId}
            onClick={() => setReportOpen(true)}
          >
            <ShieldAlert aria-hidden="true" />
            這個應用有問題？檢舉或標記不信任
          </button>
        </section>
      </main>
      {reportOpen && clientId ? (
        <ReportDialog
          clientId={clientId}
          clientName={appName}
          onClose={() => setReportOpen(false)}
        />
      ) : null}
    </>
  );
}

function DeleteAccountDialog({
  busy,
  email,
  error,
  onCancel,
  onConfirm,
}: {
  busy: boolean;
  email: string;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const [confirmation, setConfirmation] = useState("");
  const panelRef = useRef<HTMLElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const busyRef = useRef(busy);

  useEffect(() => {
    busyRef.current = busy;
  }, [busy]);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    inputRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        onCancel();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;

      const focusable = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), [href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [onCancel]);

  const confirmed =
    confirmation.trim().toLowerCase() === email.trim().toLowerCase();

  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <section
        ref={panelRef}
        className="dialog-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-account-title"
        aria-describedby="delete-account-description"
        aria-busy={busy}
      >
        <div className="dialog-icon danger-icon">
          <Trash2 aria-hidden="true" />
        </div>
        <h2 id="delete-account-title">永久刪除 PGID？</h2>
        <p id="delete-account-description">
          帳號、Passkeys、sessions、授權與 OAuth tokens 都會永久刪除，且無法復原。
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            if (confirmed && !busy) onConfirm();
          }}
        >
          <label className="confirmation-field">
            <span>輸入 {email} 以確認</span>
            <input
              ref={inputRef}
              type="email"
              value={confirmation}
              autoComplete="off"
              spellCheck={false}
              disabled={busy}
              aria-invalid={error ? "true" : undefined}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </label>
          {error ? (
            <div className="dialog-error" role="alert">
              {error}
            </div>
          ) : null}
          <div className="dialog-actions">
            <button
              type="button"
              className="button button-secondary"
              disabled={busy}
              onClick={onCancel}
            >
              取消
            </button>
            <button
              type="submit"
              className="button button-danger"
              disabled={busy || !confirmed}
            >
              <Trash2 aria-hidden="true" />
              {busy ? "刪除中..." : "永久刪除"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

export function DeletePasskeyDialog({
  busy,
  error,
  passkey,
  onCancel,
  onConfirm,
}: {
  busy: boolean;
  error: string | null;
  passkey: Passkey;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const panelRef = useRef<HTMLElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const busyRef = useRef(busy);

  useEffect(() => {
    busyRef.current = busy;
  }, [busy]);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    cancelRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        onCancel();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;

      const focusable = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), [href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [onCancel]);

  const label = passkey.name?.trim() || "未命名 Passkey";

  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <section
        ref={panelRef}
        className="dialog-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-passkey-title"
        aria-describedby="delete-passkey-description"
        aria-busy={busy}
      >
        <div className="dialog-icon danger-icon">
          <KeyRound aria-hidden="true" />
        </div>
        <h2 id="delete-passkey-title">刪除「{label}」？</h2>
        <p id="delete-passkey-description">
          刪除後無法再用這把 Passkey 登入。{PUBLIC_PRODUCT_COPY.recovery}
        </p>
        {error ? (
          <div className="dialog-error" role="alert">
            {error}
          </div>
        ) : null}
        <div className="dialog-actions">
          <button
            ref={cancelRef}
            type="button"
            className="button button-secondary"
            disabled={busy}
            onClick={onCancel}
          >
            取消
          </button>
          <button
            type="button"
            className="button button-danger"
            disabled={busy}
            onClick={onConfirm}
          >
            <Trash2 aria-hidden="true" />
            {busy ? "刪除中..." : "刪除 Passkey"}
          </button>
        </div>
      </section>
    </div>
  );
}

function ReportDialog({
  clientId,
  clientName,
  onClose,
}: {
  clientId: string;
  clientName: string;
  onClose: () => void;
}) {
  const [reason, setReason] = useState<ReportReason>("impersonation");
  const [detail, setDetail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const panelRef = useRef<HTMLElement>(null);
  const doneButtonRef = useRef<HTMLButtonElement>(null);
  const busyRef = useRef(busy);

  useEffect(() => {
    busyRef.current = busy;
  }, [busy]);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    // Move focus into the dialog on open (first radio, falling back to the
    // first control) so keyboard and screen-reader users start inside it.
    panelRef.current
      ?.querySelector<HTMLElement>("input, button, textarea")
      ?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = Array.from(
        panelRef.current.querySelectorAll<HTMLElement>(
          'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), [href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      const first = focusable[0];
      const last = focusable.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [onClose]);

  // After a successful report the form is replaced by a confirmation; move
  // focus to its primary action so the keyboard focus is not left orphaned.
  useEffect(() => {
    if (done) doneButtonRef.current?.focus();
  }, [done]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/oauth/report", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId, reason, detail: detail.trim() }),
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setError(
          payload.error === "rate_limited"
            ? "檢舉太頻繁，請稍後再試。"
            : "無法送出檢舉，請稍後再試。",
        );
        return;
      }
      setDone(true);
    } catch {
      setError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="dialog-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <section
        ref={panelRef}
        className="dialog-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-title"
        aria-busy={busy}
      >
        <div className="dialog-icon warning-icon">
          <Flag aria-hidden="true" />
        </div>
        {done ? (
          <>
            <h2 id="report-title">檢舉已受理</h2>
            <p>
              感謝你的回報。我們已記錄對 <strong>{clientName}</strong>{" "}
              的檢舉，團隊會盡快檢視。你隨時可以在「應用程式」頁撤銷它的授權。
            </p>
            <div className="dialog-actions">
              <button
                ref={doneButtonRef}
                type="button"
                className="button button-primary"
                onClick={onClose}
              >
                完成
              </button>
            </div>
          </>
        ) : (
          <>
            <h2 id="report-title">檢舉「{clientName}」</h2>
            <p>
              若你認為這個應用程式在冒名、釣魚或濫用你的資料，請告訴我們原因。
            </p>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (!busy) void submit();
              }}
            >
              <fieldset className="report-reasons" disabled={busy}>
                <legend>原因</legend>
                {REPORT_REASONS.map((item) => (
                  <label key={item.id} className="report-reason">
                    <input
                      type="radio"
                      name="report-reason"
                      value={item.id}
                      checked={reason === item.id}
                      onChange={() => setReason(item.id)}
                    />
                    <span>{item.label}</span>
                  </label>
                ))}
              </fieldset>
              <label className="report-detail">
                <span>補充說明（選填）</span>
                <textarea
                  rows={3}
                  maxLength={1000}
                  value={detail}
                  disabled={busy}
                  onChange={(event) => setDetail(event.target.value)}
                  placeholder="描述你觀察到的問題，例如假冒的網域或要求的異常權限。"
                />
              </label>
              {error ? (
                <div className="dialog-error" role="alert">
                  {error}
                </div>
              ) : null}
              <div className="dialog-actions">
                <button
                  type="button"
                  className="button button-secondary"
                  disabled={busy}
                  onClick={onClose}
                >
                  取消
                </button>
                <button
                  type="submit"
                  className="button button-danger"
                  disabled={busy}
                >
                  <Flag aria-hidden="true" />
                  {busy ? "送出中..." : "送出檢舉"}
                </button>
              </div>
            </form>
          </>
        )}
      </section>
    </div>
  );
}

function PublicPageShell({
  title,
  lead,
  icon,
  children,
}: {
  title: string;
  lead: string;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="public-shell">
      <header className="public-header">
        <Brand />
        {/* Inline (non-floating) controls so the fixed theme toggle never
            overlaps the back link on narrow screens. */}
        <div className="public-header-actions">
          <a className="public-back" href="/">
            <ArrowLeft aria-hidden="true" />
            回到 PGID
          </a>
          <ThemeToggle />
        </div>
      </header>
      <main className="public-main">
        <div className="public-hero">
          <span className="public-hero-icon">{icon}</span>
          <h1>{title}</h1>
          <p>{lead}</p>
        </div>
        <div className="public-body">{children}</div>
      </main>
      <footer className="public-footer">
        <span>© {new Date().getFullYear()} PG72</span>
        <span className="public-footer-links">
          <a href="/about">關於 PGID</a>
          <span aria-hidden="true"> · </span>
          <a href="/tos">服務條款</a>
          <span aria-hidden="true"> · </span>
          <a href="/pp">隱私權政策</a>
        </span>
        <span>
          聯繫我們：<a href="mailto:contact@pg72.tw">contact@pg72.tw</a>
        </span>
      </footer>
    </div>
  );
}

function DraftNotice() {
  return (
    <p className="public-placeholder">
      <AlertTriangle aria-hidden="true" />
      本文為草稿，尚待正式複核後生效；正式生效日期將於公開上線時填入。
    </p>
  );
}

function LegalMeta() {
  return (
    <p className="public-meta">
      生效日期：待定（公開上線時填入） · 最後更新：2026-07-16
    </p>
  );
}

function TermsContent() {
  return (
    <>
      <LegalMeta />
      <DraftNotice />
      <section className="public-section public-intro">
        <p>
          歡迎使用 PGID（以下稱「本服務」），由 PG72（以下稱「我們」）提供，網址為{" "}
          <span className="mono">https://sso.pg72.tw</span>。PGID 是 PG72
          自建的身分認證服務（Identity Provider），讓你以單一身分登入已接入 PGID
          的 PG72 服務與經核准的第三方應用程式。
        </p>
        <p>使用本服務即表示你同意本條款。若你不同意，請勿使用本服務。</p>
      </section>

      <section className="public-section">
        <h2>1. 服務內容</h2>
        <p>本服務提供：</p>
        <ul className="public-list">
          <li>
            以 Google、Passkey（無密碼）以及其他支援的社群帳號（如 Discord、GitHub、Facebook、Apple、Telegram）登入；
          </li>
          <li>
            以 OAuth 2.1 / OpenID Connect 授權第三方應用程式存取你的基本身分資訊；
          </li>
          <li>
            帳號中心：管理個人資料、登入方式、已授權應用程式、裝置工作階段（session）與安全活動記錄。
          </li>
        </ul>
        <p>
          本服務<strong>不儲存你的密碼</strong>；登入以 OAuth 提供者與 Passkey
          憑證為準。
        </p>
      </section>

      <section className="public-section">
        <h2>2. 帳號資格與註冊</h2>
        <ul className="public-list">
          <li>{PUBLIC_PRODUCT_COPY.inviteAccess}</li>
          <li>{PUBLIC_PRODUCT_COPY.passkeyAccess}</li>
          <li>你必須提供正確資訊，並就你帳號下的一切活動負責。</li>
          <li>
            你必須妥善保管你的登入方式（Passkey 裝置、社群帳號）。若懷疑帳號遭盜用，請立即透過第
            10 條的聯絡方式通知我們。
          </li>
          <li>
            我們保留於你違反本條款、或為保護服務與其他使用者安全時，
            <strong>停權或終止</strong>帳號的權利。
          </li>
        </ul>
      </section>

      <section className="public-section">
        <h2>3. 可接受使用</h2>
        <p>你同意不會：</p>
        <ul className="public-list">
          <li>未經授權存取他人帳號或資料；</li>
          <li>干擾、破壞、逆向或試圖繞過本服務的安全機制；</li>
          <li>以自動化方式濫用註冊、登入或授權端點；</li>
          <li>
            冒充他人或 PG72，或以誤導方式註冊 OAuth
            應用程式（例如以近似官方的名稱誘導使用者授權）；
          </li>
          <li>將本服務用於任何違法用途。</li>
        </ul>
        <p>
          我們提供 OAuth 應用程式的<strong>檢舉</strong>機制；若你認為某應用程式不受信任或濫用授權，可於帳號中心檢舉，我們會審查並得停用該應用。
        </p>
      </section>

      <section className="public-section">
        <h2>4. 第三方登入與應用程式</h2>
        <ul className="public-list">
          <li>你透過第三方（如 Google）登入時，亦受該第三方之條款約束。</li>
          <li>
            你可授權第三方應用程式存取你的基本身分（依你於同意畫面核可的範圍）。你可隨時於帳號中心撤銷授權。
          </li>
          <li>
            對於第三方應用程式如何使用你的資料，我們不負責；請於授權前檢視該應用的開發者、導向網域與請求權限。
          </li>
        </ul>
      </section>

      <section className="public-section">
        <h2>5. 你的內容與資料</h2>
        <p>
          你對本服務的資料處理，適用我們的<a href="/pp">隱私權政策</a>。使用本服務即表示你亦同意該政策。
        </p>
      </section>

      <section className="public-section">
        <h2>6. 服務可用性與變更</h2>
        <ul className="public-list">
          <li>本服務目前處於早期階段，可能不定時維護、變更或中斷，恕不另行個別通知。</li>
          <li>我們可能新增、修改或移除功能。重大變更會盡合理努力公告。</li>
        </ul>
      </section>

      <section className="public-section">
        <h2>7. 免責聲明</h2>
        <p>
          本服務按「現狀」與「現有」提供，不就可用性、無誤、安全性或適合特定用途作任何明示或默示保證。你理解自建身分服務仍在演進中，並自行承擔使用風險。
        </p>
      </section>

      <section className="public-section">
        <h2>8. 責任限制</h2>
        <p>
          在法律允許的最大範圍內，對於因使用或無法使用本服務所生之任何間接、附帶、衍生性損害，我們不負賠償責任。
        </p>
      </section>

      <section className="public-section">
        <h2>9. 條款修改</h2>
        <p>
          我們可能不時修訂本條款。修訂後將更新本頁「最後更新」日期；重大變更會另行公告。於變更生效後繼續使用本服務，即視為接受修訂後條款。
        </p>
      </section>

      <section className="public-section">
        <h2>10. 聯絡我們</h2>
        <p>
          有任何問題、帳號安全通報或條款疑義，請聯絡：
          <br />
          <a href="mailto:contact@pg72.tw">contact@pg72.tw</a>
        </p>
      </section>
    </>
  );
}

function PrivacyContent() {
  return (
    <>
      <LegalMeta />
      <DraftNotice />
      <section className="public-section public-intro">
        <p>
          本政策說明 PGID（<span className="mono">https://sso.pg72.tw</span>，由 PG72
          提供）如何蒐集、使用與保護你的個人資料。我們以「最小蒐集、集中控制、可撤銷」為原則設計本服務。
        </p>
      </section>

      <section className="public-section">
        <h2>1. 我們蒐集的資料</h2>
        <p>
          <strong>你登入時，依登入方式取得：</strong>
        </p>
        <ul className="public-list">
          <li>
            <strong>不可變使用者識別碼（sub）</strong>：我們以此穩定識別你，而非以 Email。
          </li>
          <li>
            <strong>Email 與是否已驗證</strong>：用於帳號識別與通知；僅接受已驗證的 Email。
          </li>
          <li>
            <strong>Telegram 登入邊界</strong>：Telegram 不提供 Email，因此不會直接建立 PGID
            帳號；只有在 authenticated PGID session 中明確連結後，才保存 Telegram provider ID
            並允許該 identity 登入既有帳號。
          </li>
          <li>
            <strong>顯示名稱與頭像</strong>：來自你的登入提供者，或你自行設定／上傳。
          </li>
          <li>
            <strong>登入提供者資訊</strong>：你連結的 Google 或其他社群帳號的提供者識別。
          </li>
          <li>
            <strong>Passkey 憑證公開資訊</strong>：Passkey 的公鑰與中繼資料（我們<strong>不持有</strong>你的私鑰或生物特徵）。
          </li>
        </ul>
        <p>
          <strong>你使用服務時，我們記錄：</strong>
        </p>
        <ul className="public-list">
          <li>
            <strong>工作階段（session）資料</strong>：host-only cookie 對應的 session
            識別、建立／到期時間。
          </li>
          <li>
            <strong>安全與稽核事件</strong>：登入、授權、撤銷授權、session
            撤銷、個人資料與登入方式變更等。為安全目的，我們可能記錄<strong>遮蔽後的 IP</strong>
            與粗略的裝置／瀏覽器類型；我們<strong>不會</strong>在稽核記錄中儲存完整 Email、存取權杖或其他機密。
          </li>
          <li>
            <strong>OAuth 授權記錄</strong>：你授權了哪些應用程式、核可的權限範圍。
          </li>
        </ul>
        <p>
          <strong>我們不蒐集也不儲存：</strong>
        </p>
        <ul className="public-list">
          <li>你的密碼（本服務無密碼登入）；</li>
          <li>你的 Passkey 私鑰或生物特徵；</li>
          <li>第三方應用程式在其自身系統內對你的資料處理。</li>
        </ul>
      </section>

      <section className="public-section">
        <h2>2. 我們如何使用資料</h2>
        <ul className="public-list">
          <li>提供登入與授權功能、維持你的工作階段；</li>
          <li>讓你管理帳號、登入方式與已授權應用程式；</li>
          <li>保障帳號與服務安全（偵測濫用、節流、稽核、撤銷）；</li>
          <li>在必要時與你聯繫（安全通知、重大服務變更）。</li>
        </ul>
        <p>
          我們<strong>不會</strong>販售你的個人資料。
        </p>
      </section>

      <section className="public-section">
        <h2>3. Cookie 與工作階段</h2>
        <ul className="public-list">
          <li>
            我們使用<strong>必要的</strong> host-only、<span className="mono">Secure</span>、
            <span className="mono">HttpOnly</span> cookie 維持登入狀態，不跨子網域共用。
          </li>
          <li>我們不使用第三方廣告追蹤 cookie。</li>
          <li>登入頁可能載入來自你所選登入提供者（如 Google）的資源以完成登入。</li>
        </ul>
      </section>

      <section className="public-section">
        <h2>4. 第三方登入與應用程式</h2>
        <ul className="public-list">
          <li>你以第三方（Google、社群帳號）登入時，該提供者會依其隱私政策處理你的資料。</li>
          <li>
            你授權的第三方應用程式，會依你核可的範圍取得你的基本身分（如 sub、名稱、Email）；這些應用對你資料的後續使用受其自身隱私政策約束。你可隨時於帳號中心撤銷授權。
          </li>
        </ul>
      </section>

      <section className="public-section">
        <h2>5. 資料分享</h2>
        <p>除下列情形外，我們不對外分享你的個人資料：</p>
        <ul className="public-list">
          <li>
            <strong>經你授權</strong>：你明確授權的第三方應用程式，取得你核可範圍內的身分資訊；
          </li>
          <li>
            <strong>法律要求</strong>：於法律要求或為保護服務、使用者與公眾安全之必要範圍內；
          </li>
          <li>
            <strong>服務營運</strong>：我們自行掌控的基礎設施（Cloudflare Workers／D1
            等）用於運行本服務；我們不將身分資料委外作行銷用途。
          </li>
        </ul>
      </section>

      <section className="public-section">
        <h2>6. 資料保留</h2>
        <ul className="public-list">
          <li>帳號資料於帳號存續期間保留。</li>
          <li>
            你可於帳號中心<strong>自助刪除帳號</strong>（需近期重新驗證）；刪除後，你的帳號記錄與其連結身分會被移除，已授權應用程式將無法再以你的身分取得資料。
          </li>
          <li>為安全與防濫用目的，部分稽核／安全事件可能在去識別化或遮蔽後保留一段合理期間。</li>
        </ul>
      </section>

      <section className="public-section">
        <h2>7. 你的權利</h2>
        <p>你可以：</p>
        <ul className="public-list">
          <li>檢視與更新你的個人資料（名稱、頭像）；</li>
          <li>檢視並撤銷已授權的應用程式與其權杖；</li>
          <li>檢視與撤銷裝置工作階段（單一或全部）；</li>
          <li>管理你的 Passkey 與登入方式；</li>
          <li>查看你的個人安全活動記錄；</li>
          <li>刪除你的帳號。</li>
        </ul>
        <p>如需行使上述以外的權利或有疑問，請透過第 9 條聯絡我們。</p>
      </section>

      <section className="public-section">
        <h2>8. 資料安全</h2>
        <ul className="public-list">
          <li>傳輸全程 HTTPS；嚴格的安全標頭與內容安全政策（CSP）。</li>
          <li>敏感的提供者權杖於儲存時加密；session 以中央可撤銷機制管理。</li>
          <li>
            Passkey 綁定於 <span className="mono">sso.pg72.tw</span>，採用 WebAuthn。
          </li>
          <li>我們持續強化安全控制；公開註冊開放前會進行額外的安全審查。</li>
        </ul>
        <p>
          沒有任何系統能保證絕對安全；我們會盡合理努力保護你的資料，並在發生重大事件時依法通知。
        </p>
      </section>

      <section className="public-section">
        <h2>9. 聯絡我們</h2>
        <p>
          有關隱私的任何問題、資料查詢或刪除請求，請聯絡：
          <br />
          <a href="mailto:contact@pg72.tw">contact@pg72.tw</a>
        </p>
      </section>

      <section className="public-section">
        <h2>10. 政策變更</h2>
        <p>
          我們可能不時更新本政策。更新後將修改本頁「最後更新」日期；重大變更會另行公告。
        </p>
      </section>
    </>
  );
}

export function LegalPage({ kind }: { kind: "pp" | "tos" }) {
  const isTerms = kind === "tos";
  return (
    <PublicPageShell
      title={isTerms ? "服務條款" : "隱私權政策"}
      lead={
        isTerms
          ? "使用 PGID 前，請閱讀以下服務條款。"
          : "PGID 如何蒐集、使用與保護你的資料。"
      }
      icon={
        isTerms ? (
          <FileText aria-hidden="true" />
        ) : (
          <ShieldCheck aria-hidden="true" />
        )
      }
    >
      {isTerms ? <TermsContent /> : <PrivacyContent />}
    </PublicPageShell>
  );
}

export function AboutPage() {
  return (
    <PublicPageShell
      title="關於 PGID"
      lead={PUBLIC_PRODUCT_COPY.aboutLead}
      icon={<Sparkles aria-hidden="true" />}
    >
      <section className="public-section">
        <h2>PGID 是什麼？</h2>
        <p>{PUBLIC_PRODUCT_COPY.aboutOverview}</p>
      </section>
      <section className="public-section">
        <h2>怎麼使用？</h2>
        <p>{PUBLIC_PRODUCT_COPY.aboutUsage}</p>
      </section>
      <section className="public-section">
        <h2>為什麼選擇 PGID？</h2>
        <ul className="public-list">
          <li>
            <strong>更安全</strong>
            ：支援 Passkey 無密碼登入，token 不進入瀏覽器儲存。
          </li>
          <li>
            <strong>你掌控授權</strong>
            ：清楚看到每個應用程式取得哪些資料，並可隨時撤銷或檢舉。
          </li>
          <li>
            <strong>一致的體驗</strong>
            ：{PUBLIC_PRODUCT_COPY.aboutConsistency}
          </li>
        </ul>
      </section>
      <section className="public-section">
        <h2>開始使用</h2>
        <ul className="public-list">
          <li>{PUBLIC_PRODUCT_COPY.inviteAccess}</li>
          <li>{PUBLIC_PRODUCT_COPY.passkeyAccess}</li>
          <li>{PUBLIC_PRODUCT_COPY.recovery}</li>
        </ul>
        <p>
          收到邀請後，可前往 <a href="/">登入頁</a> 使用 Google 完成首次登入；已有
          PGID 帳號則可使用已註冊的 Passkey。相關條款請見 <a href="/tos">服務條款</a> 與{" "}
          <a href="/pp">隱私權政策</a>。
        </p>
      </section>
    </PublicPageShell>
  );
}

/**
 * Passkey list for the security tab. `useListPasskeys` triggers a
 * `/passkey/list-user-passkeys` fetch on mount, so it lives in a component that
 * is only rendered for an authenticated session — otherwise the sign-in and
 * public pages would fire a guaranteed-401 request on every load.
 */
function PasskeyList({
  busy,
  editingPasskeyId,
  passkeyName,
  onBeginRename,
  onRenameChange,
  onRenameSubmit,
  onRenameCancel,
  onRequestDelete,
}: {
  busy: string | null;
  editingPasskeyId: string | null;
  passkeyName: string;
  onBeginRename: (passkey: Passkey) => void;
  onRenameChange: (value: string) => void;
  onRenameSubmit: (passkey: Passkey) => void;
  onRenameCancel: () => void;
  onRequestDelete: (passkey: Passkey) => void;
}) {
  const passkeysQuery = authClient.useListPasskeys();
  return (
    <div
      className="item-list passkey-list"
      aria-busy={busy?.startsWith("passkey:") === true}
    >
      {(passkeysQuery.data ?? []).map((passkey: Passkey) => {
        const editing = editingPasskeyId === passkey.id;
        const updating = busy === `passkey:update:${passkey.id}`;
        return (
          <div className="list-item" key={passkey.id}>
            <span className="item-icon key-icon">
              <KeyRound aria-hidden="true" />
            </span>
            <div className="item-copy">
              {editing ? (
                <form
                  className="passkey-rename-form"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (!updating) onRenameSubmit(passkey);
                  }}
                >
                  <input
                    autoFocus
                    type="text"
                    maxLength={64}
                    value={passkeyName}
                    aria-label="Passkey 名稱"
                    disabled={updating}
                    onChange={(event) => onRenameChange(event.target.value)}
                  />
                </form>
              ) : (
                <strong>{passkey.name?.trim() || "未命名 Passkey"}</strong>
              )}
              <span>{passkeyMetadata(passkey)}</span>
              <time>
                {passkey.createdAt
                  ? `建立於 ${formatDate(passkey.createdAt)}`
                  : "建立時間不明"}
              </time>
            </div>
            <div className="passkey-actions">
              {editing ? (
                <>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label="儲存 Passkey 名稱"
                    title="儲存"
                    disabled={updating || !passkeyName.trim()}
                    onClick={() => onRenameSubmit(passkey)}
                  >
                    <Check aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label="取消重新命名"
                    title="取消"
                    disabled={updating}
                    onClick={onRenameCancel}
                  >
                    <X aria-hidden="true" />
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={`重新命名 ${passkey.name?.trim() || "Passkey"}`}
                    title="重新命名"
                    disabled={busy?.startsWith("passkey:") === true}
                    onClick={() => onBeginRename(passkey)}
                  >
                    <Pencil aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    className="icon-button danger-icon"
                    aria-label={`刪除 ${passkey.name?.trim() || "Passkey"}`}
                    title="刪除"
                    disabled={busy?.startsWith("passkey:") === true}
                    onClick={() => onRequestDelete(passkey)}
                  >
                    <Trash2 aria-hidden="true" />
                  </button>
                </>
              )}
            </div>
          </div>
        );
      })}
      {passkeysQuery.isPending ? (
        <div className="empty-state">
          <RefreshCw aria-hidden="true" className="is-spinning" />
          <span>載入 Passkeys...</span>
        </div>
      ) : null}
      {!passkeysQuery.isPending &&
      (passkeysQuery.data?.length ?? 0) === 0 ? (
        <div className="empty-state">
          <KeyRound aria-hidden="true" />
          <span>尚未註冊 Passkey</span>
        </div>
      ) : null}
    </div>
  );
}

export function App() {
  const sessionQuery = authClient.useSession();
  const [tab, setTab] = useState<Tab>("account");
  const [navOpen, setNavOpen] = useState(false);
  const [sessions, setSessions] = useState<DeviceSession[]>([]);
  const [sessionsState, setSessionsState] = useState<LoadState>("loading");
  const [activityEvents, setActivityEvents] = useState<SecurityActivityEvent[]>(
    [],
  );
  const [activityState, setActivityState] = useState<LoadState>("loading");
  const [activityCursor, setActivityCursor] = useState<string | null>(null);
  const [activityLoadingMore, setActivityLoadingMore] = useState(false);
  const [activityMoreError, setActivityMoreError] = useState<string | null>(
    null,
  );
  const [reportTarget, setReportTarget] = useState<{
    clientId: string;
    name: string;
  } | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarFileName, setAvatarFileName] = useState<string | null>(null);
  const [avatarError, setAvatarError] = useState<string | null>(null);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const [authorizations, setAuthorizations] = useState<AuthorizedApplication[]>([]);
  const [authorizationsState, setAuthorizationsState] =
    useState<LoadState>("loading");
  const [authorizationsError, setAuthorizationsError] = useState<string | null>(null);
  const [canDeleteAccount, setCanDeleteAccount] = useState<boolean | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [editingPasskeyId, setEditingPasskeyId] = useState<string | null>(null);
  const [passkeyName, setPasskeyName] = useState("");
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [passkeyToDelete, setPasskeyToDelete] = useState<Passkey | null>(null);
  const [passkeyDeleteError, setPasskeyDeleteError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [profileInfo, setProfileInfo] = useState<AccountProfileResponse | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState("");
  const [loginMethods, setLoginMethods] = useState<LoginMethodsResponse | null>(null);
  const [loginMethodsState, setLoginMethodsState] = useState<LoadState>("loading");
  const [loginMethodsError, setLoginMethodsError] = useState<string | null>(null);
  const [telegramConfig, setTelegramConfig] = useState<TelegramConfig | null>(
    null,
  );
  const [unlinkPendingId, setUnlinkPendingId] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<PlatformRole>("user");
  const [adminUsers, setAdminUsers] = useState<AdminUserView[]>([]);
  const [adminUsersState, setAdminUsersState] = useState<LoadState>("loading");
  const [adminUsersError, setAdminUsersError] = useState<string | null>(null);
  const [adminUsersPage, setAdminUsersPage] = useState(1);
  const [adminUsersTotal, setAdminUsersTotal] = useState(0);
  const [adminUsersQuery, setAdminUsersQuery] = useState("");
  const [userSearchDraft, setUserSearchDraft] = useState("");
  const [viewerRole, setViewerRole] = useState<PlatformRole | null>(null);
  const [userPendingDelete, setUserPendingDelete] = useState<string | null>(
    null,
  );
  const [adminClients, setAdminClients] = useState<AdminOAuthClient[]>([]);
  const [adminClientsState, setAdminClientsState] =
    useState<LoadState>("loading");
  const [adminClientsError, setAdminClientsError] = useState<string | null>(null);
  const [clientName, setClientName] = useState("");
  const [clientIdDraft, setClientIdDraft] = useState("");
  const [clientDeveloperDraft, setClientDeveloperDraft] = useState("");
  const [clientPrivacyUrlDraft, setClientPrivacyUrlDraft] = useState("");
  const [clientTermsUrlDraft, setClientTermsUrlDraft] = useState("");
  const [clientRedirectUrisDraft, setClientRedirectUrisDraft] = useState("");
  const [editingClientId, setEditingClientId] = useState<string | null>(null);
  const [editDeveloperDraft, setEditDeveloperDraft] = useState("");
  const [editPrivacyUrlDraft, setEditPrivacyUrlDraft] = useState("");
  const [editTermsUrlDraft, setEditTermsUrlDraft] = useState("");
  const [clientTypeDraft, setClientTypeDraft] = useState<
    "confidential" | "public"
  >("confidential");
  const [clientOfflineDraft, setClientOfflineDraft] = useState(false);
  const [issuedClientSecret, setIssuedClientSecret] = useState<{
    clientId: string;
    secret: string;
  } | null>(null);
  const [clientPendingDelete, setClientPendingDelete] = useState<string | null>(
    null,
  );

  const closeDeleteDialog = useCallback(() => {
    setDeleteError(null);
    setDeleteDialogOpen(false);
  }, []);

  const session = sessionQuery.data;

  useEffect(() => {
    if (!session) {
      setTelegramConfig(null);
      return;
    }
    let cancelled = false;
    fetch("/api/auth/telegram/config", {
      headers: { accept: "application/json" },
    })
      .then((response) =>
        response.ok
          ? response.json()
          : { enabled: false, botUsername: null },
      )
      .then((config: TelegramConfig) => {
        if (!cancelled) {
          setTelegramConfig({
            enabled: config.enabled === true,
            botUsername: config.botUsername ?? null,
          });
        }
      })
      .catch(() => {
        if (!cancelled) setTelegramConfig({ enabled: false, botUsername: null });
      });
    return () => {
      cancelled = true;
    };
  }, [session?.user.id]);

  const loadSessions = useCallback(async () => {
    setSessionsState("loading");
    const result = await authClient.listSessions();
    if (result.error) {
      setSessionsState("error");
      return;
    }
    setSessions(result.data ?? []);
    setSessionsState("ready");
  }, []);

  const loadSecurityActivity = useCallback(async () => {
    setActivityState("loading");
    setActivityMoreError(null);
    try {
      const response = await fetch("/api/account/security-activity", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Unable to load activity (${response.status})`);
      }
      const data = (await response.json()) as SecurityActivityResponse;
      if (!Array.isArray(data.events)) {
        throw new Error("Invalid activity response");
      }
      setActivityEvents(data.events);
      setActivityCursor(data.nextCursor ?? null);
      setActivityState("ready");
    } catch {
      setActivityState("error");
    }
  }, []);

  const loadMoreSecurityActivity = useCallback(async () => {
    if (!activityCursor) return;
    setActivityLoadingMore(true);
    setActivityMoreError(null);
    try {
      const params = new URLSearchParams({ cursor: activityCursor });
      const response = await fetch(`/api/account/security-activity?${params}`, {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Unable to load activity (${response.status})`);
      }
      const data = (await response.json()) as SecurityActivityResponse;
      if (!Array.isArray(data.events)) {
        throw new Error("Invalid activity response");
      }
      setActivityEvents((current) => [...current, ...data.events]);
      setActivityCursor(data.nextCursor ?? null);
    } catch {
      // Keep the events already shown and the cursor intact so the user can
      // retry; surfacing an error avoids the false impression of reaching the
      // end of the timeline.
      setActivityMoreError("無法載入更多活動，請重試。");
    } finally {
      setActivityLoadingMore(false);
    }
  }, [activityCursor]);

  const loadAuthorizations = useCallback(async () => {
    setAuthorizationsState("loading");
    setAuthorizationsError(null);
    try {
      const response = await fetch("/api/account/authorizations", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Unable to load authorizations (${response.status})`);
      }

      const data = (await response.json()) as AuthorizationsResponse;
      if (!Array.isArray(data.authorizations)) {
        throw new Error("Invalid authorizations response");
      }
      setAuthorizations(data.authorizations);
      setCanDeleteAccount(data.canDeleteAccount === true);
      setAuthorizationsState("ready");
    } catch {
      setAuthorizationsError("無法載入已授權的應用程式，請稍後重試。");
      setAuthorizationsState("error");
    }
  }, []);

  const loadProfile = useCallback(async () => {
    try {
      const response = await fetch("/api/account/profile", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error(`Unable to load profile (${response.status})`);
      setProfileInfo((await response.json()) as AccountProfileResponse);
    } catch {
      setProfileInfo(null);
    }
  }, []);

  const loadLoginMethods = useCallback(async () => {
    setLoginMethodsState("loading");
    setLoginMethodsError(null);
    try {
      const response = await fetch("/api/account/login-methods", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Unable to load login methods (${response.status})`);
      }
      const data = (await response.json()) as LoginMethodsResponse;
      if (!Array.isArray(data.providers)) {
        throw new Error("Invalid login methods response");
      }
      setLoginMethods(data);
      setLoginMethodsState("ready");
    } catch {
      setLoginMethodsError("無法載入登入方式,請稍後重試。");
      setLoginMethodsState("error");
    }
  }, []);

  const loadAdminClients = useCallback(async () => {
    setAdminClientsState("loading");
    try {
      const response = await fetch("/api/admin/clients", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Unable to load clients (${response.status})`);
      }
      const data = (await response.json()) as AdminClientsResponse;
      if (!Array.isArray(data.clients)) {
        throw new Error("Invalid clients response");
      }
      setAdminClients(data.clients);
      setAdminClientsState("ready");
    } catch {
      setAdminClientsState("error");
    }
  }, []);

  const loadAdminUsers = useCallback(
    async (page: number, query: string) => {
      setAdminUsersState("loading");
      setUserPendingDelete(null);
      try {
        const params = new URLSearchParams({
          page: String(page),
          perPage: "10",
        });
        if (query) params.set("q", query);
        const response = await fetch(`/api/admin/users?${params}`, {
          credentials: "include",
          cache: "no-store",
          headers: { Accept: "application/json" },
        });
        if (!response.ok) {
          throw new Error(`Unable to load users (${response.status})`);
        }
        const data = (await response.json()) as AdminUsersResponse;
        if (!Array.isArray(data.users)) {
          throw new Error("Invalid users response");
        }
        setAdminUsers(data.users);
        setAdminUsersPage(data.page);
        setAdminUsersTotal(data.total);
        setViewerRole(data.viewerRole);
        setAdminUsersState("ready");
      } catch {
        setAdminUsersState("error");
      }
    },
    [],
  );

  const sessionRole = (session?.user.role ?? "user") as PlatformRole;
  const canManageUsers =
    sessionRole === "admin" || sessionRole === "bootadmin";
  const canManageClients = canManageUsers || sessionRole === "developer";

  useEffect(() => {
    if (session) {
      void loadSessions();
      void loadSecurityActivity();
      void loadAuthorizations();
      void loadProfile();
      void loadLoginMethods();
      if (canManageClients) {
        void loadAdminClients();
      }
      if (canManageUsers) {
        void loadAdminUsers(1, "");
      }
    }
  }, [
    canManageClients,
    canManageUsers,
    loadAdminClients,
    loadAdminUsers,
    loadSecurityActivity,
    loadAuthorizations,
    loadLoginMethods,
    loadProfile,
    loadSessions,
    session,
  ]);

  const pathname = window.location.pathname;
  const isConsent = pathname === "/consent";
  const clientId = new URLSearchParams(window.location.search).get("client_id");

  // Per-route document title. Public/consent routes are keyed off the path;
  // the root route depends on whether a session resolved (account center vs.
  // sign-in). Runs on every render before the route-specific early returns.
  useEffect(() => {
    let title: string;
    if (pathname === "/about") title = "關於 PGID";
    else if (pathname === "/tos") title = "服務條款 — PGID";
    else if (pathname === "/pp") title = "隱私權政策 — PGID";
    else if (pathname === "/consent") title = "授權 — PGID";
    else if (session) title = "PGID 帳號中心";
    else title = "PGID — PG72 單一登入";
    document.title = title;
  }, [pathname, session]);

  // Public informational pages render without a session so they are linkable
  // from consent, sign-in and third-party sites.
  if (pathname === "/tos") return <LegalPage kind="tos" />;
  if (pathname === "/pp") return <LegalPage kind="pp" />;
  if (pathname === "/about") return <AboutPage />;

  if (sessionQuery.isPending) {
    return (
      <>
        <ThemeToggle floating />
        <div className="loading-screen">
          <Brand />
          <span className="loading-line" />
        </div>
      </>
    );
  }

  if (!session) {
    return <SignInView pending={sessionQuery.isPending} />;
  }

  if (session.user.status === "pending_telegram") {
    return <PendingTelegramView />;
  }

  if (isConsent) {
    return (
      <ConsentView
        clientId={clientId}
        userEmail={session.user.email}
        userName={session.user.name}
        userImage={session.user.image ?? null}
      />
    );
  }

  const addPasskey = async () => {
    setBusy("passkey:add");
    setNotice(null);
    setPasskeyError(null);
    try {
      const result = await authClient.passkey.addPasskey({
        name: `Passkey ${new Date().toLocaleDateString("zh-TW")}`,
      });
      if (result.error) {
        setPasskeyError(messageFrom(result.error, "無法新增 Passkey。"));
        return;
      }
      setNotice("Passkey 已新增。");
      await loadLoginMethods();
    } catch (addError: unknown) {
      setPasskeyError(messageFrom(addError, "無法新增 Passkey。"));
    } finally {
      setBusy(null);
    }
  };

  const beginPasskeyRename = (passkey: Passkey) => {
    setPasskeyError(null);
    setEditingPasskeyId(passkey.id);
    setPasskeyName(passkey.name?.trim() || "Passkey");
  };

  const updatePasskeyName = async (passkey: Passkey) => {
    const name = passkeyName.trim();
    if (!name) {
      setPasskeyError("Passkey 名稱不能是空白。");
      return;
    }

    setBusy(`passkey:update:${passkey.id}`);
    setNotice(null);
    setPasskeyError(null);
    try {
      const result = await authClient.passkey.updatePasskey({
        id: passkey.id,
        name,
      });
      if (result.error) {
        setPasskeyError(messageFrom(result.error, "無法更新 Passkey 名稱。"));
        return;
      }
      setEditingPasskeyId(null);
      setPasskeyName("");
      setNotice("Passkey 名稱已更新。");
    } catch (updateError: unknown) {
      setPasskeyError(messageFrom(updateError, "無法更新 Passkey 名稱。"));
    } finally {
      setBusy(null);
    }
  };

  const deletePasskey = async () => {
    if (!passkeyToDelete) return;

    const passkey = passkeyToDelete;
    setBusy(`passkey:delete:${passkey.id}`);
    setNotice(null);
    setPasskeyDeleteError(null);
    try {
      const result = await authClient.passkey.deletePasskey({ id: passkey.id });
      if (result.error) {
        const message = messageFrom(result.error, "無法刪除 Passkey。");
        const normalizedMessage = message.toLowerCase();
        setPasskeyDeleteError(
          normalizedMessage.includes("last_login_method") ||
            normalizedMessage.includes("sign-in method")
            ? "帳號至少要保留一種登入方式,請先連結其他登入方式。"
            : normalizedMessage.includes("fresh") ||
                normalizedMessage.includes("session_not_fresh")
              ? "刪除最後一把 Passkey 前，請登出並重新登入。"
              : message,
        );
        return;
      }
      setPasskeyToDelete(null);
      setNotice("Passkey 已刪除。");
      await loadLoginMethods();
    } catch (deleteError: unknown) {
      setPasskeyDeleteError(messageFrom(deleteError, "無法刪除 Passkey。"));
    } finally {
      setBusy(null);
    }
  };

  const revokeSession = async (token: string) => {
    setBusy(token);
    const result = await authClient.revokeSession({ token });
    if (!result.error) await loadSessions();
    setBusy(null);
  };

  const revokeOtherSessions = async () => {
    setBusy("revoke-others");
    const result = await authClient.revokeOtherSessions();
    setNotice(
      result.error
        ? messageFrom(result.error, "Session revocation failed.")
        : "其他裝置已登出。",
    );
    if (!result.error) await loadSessions();
    setBusy(null);
  };

  const revokeAuthorization = async (authorization: AuthorizedApplication) => {
    setBusy(`authorization:${authorization.id}`);
    setNotice(null);
    setAuthorizationsError(null);
    try {
      const response = await fetch(
        `/api/account/authorizations/${encodeURIComponent(authorization.id)}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      if (!response.ok) throw new Error(`Unable to revoke (${response.status})`);

      setAuthorizations((current) =>
        current.filter((item) => item.id !== authorization.id),
      );
      setNotice(`已撤銷 ${authorization.name} 的授權與 tokens。`);
    } catch {
      setAuthorizationsError("無法撤銷授權，請重新整理後再試。");
    } finally {
      setBusy(null);
    }
  };

  const deleteAccount = async () => {
    setBusy("delete-account");
    setNotice(null);
    setDeleteError(null);
    try {
      const result = await authClient.deleteUser();
      if (result.error) {
        const message = messageFrom(result.error, "無法刪除帳號。");
        const normalizedMessage = message.toLowerCase();
        setDeleteError(
          normalizedMessage.includes("session")
            ? "登入狀態已超過 10 分鐘。請登出並重新登入後再刪除帳號。"
            : normalizedMessage.includes("bootstrap") ||
                normalizedMessage.includes("protected")
              ? "Bootstrap administrator 是系統復原帳號，不能刪除。"
              : message,
        );
        return;
      }
      window.location.replace("/");
    } catch (deleteAccountError: unknown) {
      setDeleteError(messageFrom(deleteAccountError, "網路連線失敗，請稍後再試。"));
    } finally {
      setBusy(null);
    }
  };

  const saveDisplayName = async () => {
    const name = nameDraft.trim();
    if (!name) {
      setProfileError("顯示名稱不能是空白。");
      return;
    }

    setBusy("profile:name");
    setNotice(null);
    setProfileError(null);
    try {
      const response = await fetch("/api/account/profile", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setProfileError(
          payload.error === "invalid_name"
            ? "名稱無效:去除控制字元與前後空白後必須是 1-64 個字元。"
            : payload.error === "rate_limited"
              ? "操作太頻繁,請稍後再試。"
              : "無法更新顯示名稱,請稍後再試。",
        );
        return;
      }
      setEditingName(false);
      setNameDraft("");
      setNotice("顯示名稱已更新。");
      await loadProfile();
      await sessionQuery.refetch();
    } catch (saveError: unknown) {
      setProfileError(messageFrom(saveError, "網路連線失敗,請稍後再試。"));
    } finally {
      setBusy(null);
    }
  };

  const AVATAR_MODE_LABEL: Record<AvatarSource, string> = {
    generated: "已改用生成頭貼。",
    google: "已改用 Google 頭貼。",
    upload: "已改用上傳的頭貼。",
  };

  const chooseAvatar = async (avatar: AvatarSource) => {
    setBusy("profile:avatar");
    setNotice(null);
    setProfileError(null);
    setAvatarError(null);
    try {
      // Preferred contract: dedicated avatar-mode endpoint understands all three
      // sources (identicon/google/upload).
      const mode = avatar === "generated" ? "identicon" : avatar;
      let response = await fetch("/api/account/avatar/mode", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode }),
      });
      // Fallback to the legacy profile endpoint while the mode endpoint is not
      // yet deployed (only generated/google are representable there).
      if (
        (response.status === 404 || response.status === 405) &&
        avatar !== "upload"
      ) {
        response = await fetch("/api/account/profile", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ avatar }),
        });
      }
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setProfileError(
          payload.error === "rate_limited"
            ? "操作太頻繁,請稍後再試。"
            : payload.error === "no_avatar"
              ? "尚未上傳頭貼，請先上傳圖片。"
              : "無法更新頭貼,請稍後再試。",
        );
        return;
      }
      setNotice(AVATAR_MODE_LABEL[avatar]);
      await loadProfile();
      await sessionQuery.refetch();
    } catch (avatarError: unknown) {
      setProfileError(messageFrom(avatarError, "網路連線失敗,請稍後再試。"));
    } finally {
      setBusy(null);
    }
  };

  const clearAvatarSelection = () => {
    setAvatarPreview(null);
    setAvatarFileName(null);
    setAvatarError(null);
    if (avatarInputRef.current) avatarInputRef.current.value = "";
  };

  const onAvatarFileSelected = (file: File | null) => {
    setAvatarError(null);
    if (!file) {
      clearAvatarSelection();
      return;
    }
    if (!ACCEPTED_AVATAR_TYPES.includes(file.type)) {
      setAvatarError("格式不支援，請選擇 PNG、JPG 或 WebP 圖片。");
      return;
    }
    if (file.size > MAX_AVATAR_BYTES) {
      setAvatarError("檔案太大，請選擇 256 KB 以內的圖片。");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setAvatarPreview(typeof reader.result === "string" ? reader.result : null);
      setAvatarFileName(file.name);
    };
    reader.onerror = () => setAvatarError("無法讀取檔案，請重新選擇。");
    reader.readAsDataURL(file);
  };

  const uploadAvatar = async () => {
    if (!avatarPreview) return;
    setBusy("profile:avatar");
    setNotice(null);
    setProfileError(null);
    setAvatarError(null);
    try {
      const response = await fetch("/api/account/avatar", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dataUrl: avatarPreview }),
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAvatarError(
          payload.error === "rate_limited"
            ? "操作太頻繁，請稍後再試。"
            : payload.error === "unsupported_avatar_type" ||
                payload.error === "empty_avatar" ||
                payload.error === "invalid_request"
              ? "圖片無效，請改用其他 PNG、JPG 或 WebP 圖片。"
              : payload.error === "avatar_too_large" ||
                  payload.error === "avatar_dimensions_too_large"
                ? "圖片太大，請選擇 256 KB、2048px 以內的 PNG、JPG 或 WebP。"
                : "無法上傳頭貼，請稍後再試。",
        );
        return;
      }
      clearAvatarSelection();
      setNotice("頭貼已更新。");
      await loadProfile();
      await sessionQuery.refetch();
    } catch (uploadError: unknown) {
      setAvatarError(messageFrom(uploadError, "網路連線失敗，請稍後再試。"));
    } finally {
      setBusy(null);
    }
  };

  const unlinkLoginMethod = async (method: LoginMethodProvider) => {
    setBusy(`login-method:${method.id}`);
    setNotice(null);
    setLoginMethodsError(null);
    try {
      const response = await fetch(
        `/api/account/login-methods/${encodeURIComponent(method.id)}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setLoginMethodsError(
          payload.error === "last_login_method"
            ? "這是帳號僅存的登入方式,無法解除連結。"
            : payload.error === "rate_limited"
              ? "操作太頻繁,請稍後再試。"
              : "無法解除連結,請稍後再試。",
        );
        return;
      }
      setNotice(`${providerLabel(method.provider)} 已解除連結。`);
      await loadLoginMethods();
    } catch {
      setLoginMethodsError("網路連線失敗,請稍後再試。");
    } finally {
      setUnlinkPendingId(null);
      setBusy(null);
    }
  };

  const linkLoginMethod = async (provider: LinkableProviderId) => {
    setBusy(`link:${provider}`);
    setNotice(null);
    setLoginMethodsError(null);
    try {
      const result = await authClient.linkSocial({
        provider,
        callbackURL: window.location.href,
      });
      if (result.error) {
        setLoginMethodsError(messageFrom(result.error, "無法開始連結流程。"));
        setBusy(null);
        return;
      }
      // The client follows the provider redirect; assign as a fallback.
      if (result.data?.url) {
        window.location.assign(result.data.url);
      }
    } catch (linkError: unknown) {
      setLoginMethodsError(messageFrom(linkError, "無法開始連結流程。"));
      setBusy(null);
    }
  };

  const createInvitation = async () => {
    setBusy("invite");
    setNotice(null);
    try {
      const response = await fetch("/api/admin/invitations", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      const payload = (await response.json()) as {
        applied?: boolean;
        role?: string;
        error?: string;
      };
      if (!response.ok) {
        setNotice(
          adminUserErrorMessage(payload.error, "無法建立邀請資格。"),
        );
        return;
      }
      setInviteEmail("");
      if (payload.applied) {
        setNotice(
          `這個 Email 已有帳號，已直接套用角色 ${ROLE_LABELS[inviteRole]}。`,
        );
        await loadAdminUsers(adminUsersPage, adminUsersQuery);
      } else {
        setNotice("邀請資格已建立，有效期限 7 天。");
      }
    } catch {
      setNotice("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const changeUserRole = async (user: AdminUserView, role: PlatformRole) => {
    setBusy(`user:${user.id}`);
    setAdminUsersError(null);
    try {
      const response = await fetch(
        `/api/admin/users/${encodeURIComponent(user.id)}/role`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role }),
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminUsersError(
          adminUserErrorMessage(payload.error, "無法變更角色。"),
        );
        return;
      }
      setNotice(`已將 ${user.email} 的角色變更為 ${ROLE_LABELS[role]}。`);
      await loadAdminUsers(adminUsersPage, adminUsersQuery);
    } catch {
      setAdminUsersError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const toggleUserStatus = async (user: AdminUserView) => {
    const suspend = user.status === "active";
    setBusy(`user:${user.id}`);
    setAdminUsersError(null);
    try {
      const response = await fetch(
        `/api/admin/users/${encodeURIComponent(user.id)}/status`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ suspended: suspend }),
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminUsersError(
          adminUserErrorMessage(payload.error, "無法更新使用者狀態。"),
        );
        return;
      }
      setNotice(
        suspend
          ? `${user.email} 已停權，sessions 與 tokens 已撤銷。`
          : `${user.email} 已復權。`,
      );
      await loadAdminUsers(adminUsersPage, adminUsersQuery);
    } catch {
      setAdminUsersError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const revokeUserSessions = async (user: AdminUserView) => {
    setBusy(`user:${user.id}`);
    setAdminUsersError(null);
    try {
      const response = await fetch(
        `/api/admin/users/${encodeURIComponent(user.id)}/revoke-sessions`,
        {
          method: "POST",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      const payload = (await response.json()) as {
        revokedSessions?: number;
        error?: string;
      };
      if (!response.ok) {
        setAdminUsersError(
          adminUserErrorMessage(payload.error, "無法撤銷 sessions。"),
        );
        return;
      }
      setNotice(
        `已撤銷 ${user.email} 的 ${payload.revokedSessions ?? 0} 個 sessions。`,
      );
      await loadAdminUsers(adminUsersPage, adminUsersQuery);
    } catch {
      setAdminUsersError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const deleteAdminUser = async (user: AdminUserView) => {
    setBusy(`user:${user.id}`);
    setAdminUsersError(null);
    try {
      const response = await fetch(
        `/api/admin/users/${encodeURIComponent(user.id)}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminUsersError(
          adminUserErrorMessage(payload.error, "無法刪除使用者。"),
        );
        return;
      }
      setNotice(`使用者 ${user.email} 已刪除。`);
      await loadAdminUsers(adminUsersPage, adminUsersQuery);
    } catch {
      setAdminUsersError("網路連線失敗，請稍後再試。");
    } finally {
      setUserPendingDelete(null);
      setBusy(null);
    }
  };

  const ensureClientPasskeyStepUp = async (): Promise<boolean> => {
    const challengeResponse = await fetch(
      "/api/account/passkey-step-up/challenge",
      {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json" },
      },
    );
    const challenge = (await challengeResponse.json().catch(() => ({}))) as
      PasskeyStepUpChallengeResponse;
    if (!challengeResponse.ok) {
      setAdminClientsError(
        adminClientErrorMessage(
          challenge.error,
          "無法開始 Passkey 驗證，請稍後再試。",
        ),
      );
      return false;
    }
    if (challenge.verified === true) return true;
    if (!challenge.challengeId || !challenge.options) {
      setAdminClientsError("無法開始 Passkey 驗證，請重新整理。");
      return false;
    }

    let assertion: AuthenticationResponseJSON;
    try {
      assertion = await startAuthentication({ optionsJSON: challenge.options });
    } catch {
      setAdminClientsError("Passkey 驗證已取消或無法完成。");
      return false;
    }

    const verificationResponse = await fetch(
      "/api/account/passkey-step-up/verify",
      {
        method: "POST",
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          response: assertion,
        }),
      },
    );
    const verification = (await verificationResponse
      .json()
      .catch(() => ({}))) as PasskeyStepUpChallengeResponse;
    if (!verificationResponse.ok || verification.verified !== true) {
      setAdminClientsError(
        verification.error === "passkey_step_up_challenge_invalid"
          ? "Passkey 驗證已過期或已使用，請再試一次。"
          : "Passkey 驗證失敗，操作尚未送出。",
      );
      return false;
    }

    setNotice("Passkey 驗證已完成。");
    return true;
  };

  const createAdminClient = async () => {
    setBusy("client:create");
    setAdminClientsError(null);
    setIssuedClientSecret(null);
    try {
      if (!(await ensureClientPasskeyStepUp())) return;
      const redirectUris = clientRedirectUrisDraft
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      const isPublic = clientTypeDraft === "public";
      const body: Record<string, unknown> = {
        name: clientName.trim(),
        developerName: clientDeveloperDraft.trim(),
        redirectUris,
        public: isPublic,
        scopes: clientOfflineDraft
          ? ["openid", "profile", "email", "offline_access"]
          : ["openid", "profile", "email"],
        grantTypes: clientOfflineDraft
          ? ["authorization_code", "refresh_token"]
          : ["authorization_code"],
      };
      const clientId = clientIdDraft.trim();
      if (clientId) body.clientId = clientId;
      const privacyPolicyUrl = clientPrivacyUrlDraft.trim();
      if (privacyPolicyUrl) body.privacyPolicyUrl = privacyPolicyUrl;
      const termsOfServiceUrl = clientTermsUrlDraft.trim();
      if (termsOfServiceUrl) body.termsOfServiceUrl = termsOfServiceUrl;

      const response = await fetch("/api/admin/clients", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = (await response.json()) as CreatedAdminClientResponse & {
        error?: string;
      };
      if (!response.ok) {
        setAdminClientsError(
          adminClientErrorMessage(payload.error, "無法建立 client。"),
        );
        return;
      }
      if (payload.clientSecret) {
        setIssuedClientSecret({
          clientId: payload.client.clientId,
          secret: payload.clientSecret,
        });
      }
      setClientName("");
      setClientIdDraft("");
      setClientDeveloperDraft("");
      setClientPrivacyUrlDraft("");
      setClientTermsUrlDraft("");
      setClientRedirectUrisDraft("");
      setClientOfflineDraft(false);
      setClientTypeDraft("confidential");
      setNotice(`Client ${payload.client.clientId} 已建立。`);
      await loadAdminClients();
    } catch {
      setAdminClientsError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const beginClientTrustEdit = (client: AdminOAuthClient) => {
    setAdminClientsError(null);
    setEditingClientId(client.clientId);
    setEditDeveloperDraft(client.developerName ?? "");
    setEditPrivacyUrlDraft(client.privacyPolicyUrl ?? "");
    setEditTermsUrlDraft(client.termsOfServiceUrl ?? "");
  };

  const updateAdminClientTrust = async (client: AdminOAuthClient) => {
    setBusy(`client:${client.clientId}`);
    setAdminClientsError(null);
    try {
      if (!(await ensureClientPasskeyStepUp())) return;
      const response = await fetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}`,
        {
          method: "PATCH",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            developerName: editDeveloperDraft.trim(),
            privacyPolicyUrl: editPrivacyUrlDraft.trim() || null,
            termsOfServiceUrl: editTermsUrlDraft.trim() || null,
          }),
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminClientsError(
          adminClientErrorMessage(payload.error, "無法更新 client 資訊。"),
        );
        return;
      }
      setEditingClientId(null);
      setNotice(`Client ${client.clientId} 的信任資訊已更新。`);
      await loadAdminClients();
    } catch {
      setAdminClientsError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const rotateAdminClientSecret = async (client: AdminOAuthClient) => {
    setBusy(`client:${client.clientId}`);
    setAdminClientsError(null);
    setIssuedClientSecret(null);
    try {
      if (!(await ensureClientPasskeyStepUp())) return;
      const response = await fetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}/rotate-secret`,
        {
          method: "POST",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      const payload = (await response.json()) as {
        clientSecret?: string;
        error?: string;
      };
      if (!response.ok || !payload.clientSecret) {
        setAdminClientsError(
          adminClientErrorMessage(payload.error, "無法重設 client secret。"),
        );
        return;
      }
      setIssuedClientSecret({
        clientId: client.clientId,
        secret: payload.clientSecret,
      });
      setNotice(`已重設 ${client.clientId} 的 secret，舊 secret 立即失效。`);
      await loadAdminClients();
    } catch {
      setAdminClientsError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const toggleAdminClientStatus = async (client: AdminOAuthClient) => {
    setBusy(`client:${client.clientId}`);
    setAdminClientsError(null);
    try {
      if (!(await ensureClientPasskeyStepUp())) return;
      const response = await fetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}/status`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ disabled: !client.disabled }),
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminClientsError(
          adminClientErrorMessage(payload.error, "無法更新 client 狀態。"),
        );
        return;
      }
      setNotice(
        client.disabled
          ? `Client ${client.clientId} 已重新啟用。`
          : `Client ${client.clientId} 已停用，tokens 已撤銷。`,
      );
      await loadAdminClients();
    } catch {
      setAdminClientsError("網路連線失敗，請稍後再試。");
    } finally {
      setBusy(null);
    }
  };

  const deleteAdminClient = async (client: AdminOAuthClient) => {
    setBusy(`client:${client.clientId}`);
    setAdminClientsError(null);
    try {
      if (!(await ensureClientPasskeyStepUp())) return;
      const response = await fetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        setAdminClientsError(
          adminClientErrorMessage(payload.error, "無法刪除 client。"),
        );
        return;
      }
      setNotice(`Client ${client.clientId} 已刪除，tokens 與 consents 已移除。`);
      await loadAdminClients();
    } catch {
      setAdminClientsError("網路連線失敗，請稍後再試。");
    } finally {
      setClientPendingDelete(null);
      setBusy(null);
    }
  };

  const navGroups: {
    heading: string;
    items: { id: Tab; label: string; icon: ReactNode }[];
  }[] = [
    {
      heading: "帳號中心",
      items: [
        { id: "account", label: "帳號", icon: <UserRound aria-hidden="true" /> },
        {
          id: "security",
          label: "安全性",
          icon: <ShieldCheck aria-hidden="true" />,
        },
        {
          id: "activity",
          label: "安全活動",
          icon: <Activity aria-hidden="true" />,
        },
        {
          id: "apps",
          label: "應用程式",
          icon: <MonitorSmartphone aria-hidden="true" />,
        },
      ],
    },
  ];
  const advancedItems: { id: Tab; label: string; icon: ReactNode }[] = [];
  if (canManageClients) {
    advancedItems.push({
      id: "developer",
      label: "開發者",
      icon: <Code2 aria-hidden="true" />,
    });
  }
  if (canManageUsers) {
    advancedItems.push({
      id: "admin",
      label: "管理",
      icon: <Users aria-hidden="true" />,
    });
  }
  if (advancedItems.length > 0) {
    navGroups.push({ heading: "進階", items: advancedItems });
  }

  const selectTab = (next: Tab) => {
    setTab(next);
    setNavOpen(false);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <Brand />
        <div className="user-menu">
          <ThemeToggle />
          {session.user.image ? (
            <img src={session.user.image} alt="" referrerPolicy="no-referrer" />
          ) : (
            <span className="avatar-fallback">
              <UserRound aria-hidden="true" />
            </span>
          )}
          <span className="user-name">{session.user.name}</span>
          <button
            type="button"
            className="icon-button"
            aria-label="登出"
            title="登出"
            onClick={() => authClient.signOut()}
          >
            <LogOut aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="workspace">
        <aside
          className={`sidebar${navOpen ? " sidebar-open" : ""}`}
          aria-label="帳號中心導覽"
        >
          <div className="sidebar-head">
            <h1>帳號中心</h1>
            <button
              type="button"
              className="icon-button sidebar-toggle"
              aria-label={navOpen ? "收合選單" : "展開選單"}
              aria-expanded={navOpen}
              title="選單"
              onClick={() => setNavOpen((open) => !open)}
            >
              {navOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
            </button>
          </div>
          <nav className="nav-groups">
            {navGroups.map((group) => (
              <div className="nav-group" key={group.heading}>
                <span className="nav-group-heading">{group.heading}</span>
                <div className="nav-tabs">
                  {group.items.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={tab === item.id ? "active" : ""}
                      aria-current={tab === item.id ? "page" : undefined}
                      onClick={() => selectTab(item.id)}
                    >
                      {item.icon}
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>
        </aside>

        <main className="content">
          {notice ? (
            <div className="notice" role="status">
              {notice}
              <button
                type="button"
                className="notice-close"
                aria-label="關閉"
                title="關閉"
                onClick={() => setNotice(null)}
              >
                <X aria-hidden="true" />
              </button>
            </div>
          ) : null}

          {tab === "account" ? (
            <section className="page-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Profile</span>
                  <h2>帳號</h2>
                </div>
                <span className="status-badge">
                  <span /> Active
                </span>
              </div>

              {profileError ? (
                <div className="authorization-inline-error" role="alert">
                  <ShieldOff aria-hidden="true" />
                  <span>{profileError}</span>
                </div>
              ) : null}
              <div className="profile-field">
                <span className="profile-field-label">顯示名稱</span>
                {editingName ? (
                  <form
                    className="profile-edit"
                    onSubmit={(event) => {
                      event.preventDefault();
                      if (busy !== "profile:name") void saveDisplayName();
                    }}
                  >
                    <input
                      autoFocus
                      type="text"
                      className="profile-edit-input"
                      maxLength={64}
                      value={nameDraft}
                      aria-label="顯示名稱"
                      disabled={busy === "profile:name"}
                      onChange={(event) => setNameDraft(event.target.value)}
                    />
                    <div className="profile-edit-actions">
                      <button
                        type="button"
                        className="button button-secondary button-compact"
                        disabled={busy === "profile:name"}
                        onClick={() => {
                          setEditingName(false);
                          setNameDraft("");
                          setProfileError(null);
                        }}
                      >
                        取消
                      </button>
                      <button
                        type="submit"
                        className="button button-primary button-compact"
                        disabled={busy === "profile:name" || !nameDraft.trim()}
                      >
                        <Check aria-hidden="true" />
                        {busy === "profile:name" ? "儲存中..." : "儲存"}
                      </button>
                    </div>
                  </form>
                ) : (
                  <div className="profile-field-value">
                    <span>{session.user.name}</span>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label="編輯顯示名稱"
                      title="編輯顯示名稱"
                      disabled={busy?.startsWith("profile:") === true}
                      onClick={() => {
                        setProfileError(null);
                        setNameDraft(session.user.name);
                        setEditingName(true);
                      }}
                    >
                      <Pencil aria-hidden="true" />
                    </button>
                  </div>
                )}
              </div>

              <dl className="profile-grid">
                <div>
                  <dt>Email</dt>
                  <dd>{session.user.email}</dd>
                </div>
                <div>
                  <dt>PGID</dt>
                  <dd className="mono">{session.user.id}</dd>
                </div>
                <div>
                  <dt>角色</dt>
                  <dd>{ROLE_LABELS[sessionRole]}</dd>
                </div>
              </dl>

              <div className="section-heading authorization-heading">
                <div>
                  <span className="eyebrow">Avatar</span>
                  <h2>頭貼</h2>
                  <p className="section-description">
                    你的選擇也會提供給已授權的應用程式。生成頭貼由 PGID
                    產生,不載入任何外部資源。
                  </p>
                </div>
              </div>
              {profileInfo ? (
                <>
                  <div className="avatar-current">
                    <img
                      className="avatar-current-img"
                      src={profileInfo.image ?? profileInfo.generatedAvatarUrl}
                      alt="目前的頭貼"
                      referrerPolicy="no-referrer"
                    />
                    <div className="avatar-current-meta">
                      <strong>目前頭貼</strong>
                      <span>
                        {profileInfo.avatarSource === "google"
                          ? "使用 Google 頭貼"
                          : profileInfo.avatarSource === "upload"
                            ? "使用你上傳的頭貼"
                            : "使用生成頭貼"}
                      </span>
                    </div>
                  </div>
                  <div className="item-list">
                    <div className="list-item">
                      <img
                        className="avatar-choice"
                        src={profileInfo.generatedAvatarUrl}
                        alt=""
                      />
                      <div className="item-copy">
                        <strong>生成頭貼（identicon）</strong>
                        <span>依帳號識別碼產生的固定圖案。</span>
                      </div>
                      {profileInfo.avatarSource === "generated" ? (
                        <span className="status-badge">
                          <span /> 使用中
                        </span>
                      ) : (
                        <button
                          type="button"
                          className="button button-secondary button-compact"
                          disabled={busy?.startsWith("profile:") === true}
                          onClick={() => void chooseAvatar("generated")}
                        >
                          使用
                        </button>
                      )}
                    </div>
                    {profileInfo.googleAvatarUrl ? (
                      <div className="list-item">
                        <img
                          className="avatar-choice"
                          src={profileInfo.googleAvatarUrl}
                          alt=""
                          referrerPolicy="no-referrer"
                        />
                        <div className="item-copy">
                          <strong>Google 頭貼</strong>
                          <span>來自你的 Google 帳號個人資料。</span>
                        </div>
                        {profileInfo.avatarSource === "google" ? (
                          <span className="status-badge">
                            <span /> 使用中
                          </span>
                        ) : (
                          <button
                            type="button"
                            className="button button-secondary button-compact"
                            disabled={busy?.startsWith("profile:") === true}
                            onClick={() => void chooseAvatar("google")}
                          >
                            使用
                          </button>
                        )}
                      </div>
                    ) : null}
                    {profileInfo.uploadedAvatarUrl ? (
                      <div className="list-item">
                        <img
                          className="avatar-choice"
                          src={profileInfo.uploadedAvatarUrl}
                          alt=""
                        />
                        <div className="item-copy">
                          <strong>上傳的頭貼</strong>
                          <span>你自行上傳的圖片。</span>
                        </div>
                        {profileInfo.avatarSource === "upload" ? (
                          <span className="status-badge">
                            <span /> 使用中
                          </span>
                        ) : (
                          <button
                            type="button"
                            className="button button-secondary button-compact"
                            disabled={busy?.startsWith("profile:") === true}
                            onClick={() => void chooseAvatar("upload")}
                          >
                            使用
                          </button>
                        )}
                      </div>
                    ) : null}
                  </div>

                  <div className="avatar-upload">
                    <div className="avatar-upload-preview">
                      {avatarPreview ? (
                        <img src={avatarPreview} alt="待上傳頭貼預覽" />
                      ) : (
                        <span className="avatar-upload-placeholder">
                          <ImagePlus aria-hidden="true" />
                        </span>
                      )}
                    </div>
                    <div className="avatar-upload-body">
                      <strong>上傳新頭貼</strong>
                      <span className="section-description">
                        {ACCEPTED_AVATAR_HINT} 圖片會以正方形裁切顯示。
                      </span>
                      {avatarFileName ? (
                        <span className="avatar-upload-filename">
                          已選擇：{avatarFileName}
                        </span>
                      ) : null}
                      <input
                        ref={avatarInputRef}
                        type="file"
                        className="visually-hidden"
                        accept="image/png,image/jpeg,image/webp"
                        onChange={(event) =>
                          onAvatarFileSelected(event.target.files?.[0] ?? null)
                        }
                      />
                      {avatarError ? (
                        <div className="passkey-inline-error" role="alert">
                          <ShieldOff aria-hidden="true" />
                          <span>{avatarError}</span>
                        </div>
                      ) : null}
                      <div className="avatar-upload-actions">
                        <button
                          type="button"
                          className="button button-secondary button-compact"
                          disabled={busy === "profile:avatar"}
                          onClick={() => avatarInputRef.current?.click()}
                        >
                          <Upload aria-hidden="true" />
                          選擇圖片
                        </button>
                        {avatarPreview ? (
                          <>
                            <button
                              type="button"
                              className="button button-primary button-compact"
                              disabled={busy === "profile:avatar"}
                              onClick={() => void uploadAvatar()}
                            >
                              <ImageIcon aria-hidden="true" />
                              {busy === "profile:avatar" ? "上傳中..." : "上傳並套用"}
                            </button>
                            <button
                              type="button"
                              className="button button-secondary button-compact"
                              disabled={busy === "profile:avatar"}
                              onClick={clearAvatarSelection}
                            >
                              清除
                            </button>
                          </>
                        ) : null}
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="item-list">
                  <div className="empty-state">
                    <RefreshCw aria-hidden="true" className="is-spinning" />
                    <span>正在載入頭貼設定...</span>
                  </div>
                </div>
              )}

              <div className="danger-row account-delete-row">
                <div>
                  <strong>刪除帳號</strong>
                  <span>
                    {canDeleteAccount === false
                      ? "Bootstrap administrator 是系統復原帳號，不能刪除。"
                      : "永久刪除帳號及所有 PGID 驗證資料。"}
                  </span>
                </div>
                <button
                  type="button"
                  className="button button-danger"
                  disabled={canDeleteAccount !== true}
                  onClick={() => {
                    setDeleteError(null);
                    setDeleteDialogOpen(true);
                  }}
                >
                  <Trash2 aria-hidden="true" />
                  {canDeleteAccount === null ? "確認中..." : "刪除帳號"}
                </button>
              </div>
            </section>
          ) : null}

          {tab === "apps" ? (
            <section className="page-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Connected apps</span>
                  <h2>已授權的應用程式</h2>
                  <p className="section-description">
                    撤銷後，應用程式必須再次取得你的允許才能存取帳號。
                  </p>
                </div>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="重新整理授權"
                  title="重新整理"
                  disabled={authorizationsState === "loading"}
                  onClick={() => void loadAuthorizations()}
                >
                  <RefreshCw
                    aria-hidden="true"
                    className={
                      authorizationsState === "loading" ? "is-spinning" : undefined
                    }
                  />
                </button>
              </div>
              {authorizationsState === "ready" && authorizationsError ? (
                <div className="authorization-inline-error" role="alert">
                  <ShieldOff aria-hidden="true" />
                  <span>{authorizationsError}</span>
                </div>
              ) : null}
              <div
                className="item-list authorization-list"
                aria-busy={authorizationsState === "loading"}
                aria-live="polite"
              >
                {authorizationsState === "ready"
                  ? authorizations.map((authorization) => {
                      const host = safeClientHost(
                        authorization.uri ?? undefined,
                      );
                      const scopeLabels = authorization.scopes.map(
                        (scope) => SCOPE_DETAILS[scope]?.label ?? scope,
                      );
                      const authorizationBusy =
                        busy === `authorization:${authorization.id}`;
                      return (
                        <div
                          className="list-item"
                          key={authorization.id}
                          aria-busy={authorizationBusy}
                        >
                          <span className="item-icon authorization-icon">
                            <MonitorSmartphone aria-hidden="true" />
                          </span>
                          <div className="item-copy">
                            <strong>{authorization.name}</strong>
                            <span>{host ?? authorization.clientId}</span>
                            <span>
                              {scopeLabels.length > 0
                                ? scopeLabels.join("、")
                                : "基本登入權限"}
                            </span>
                            <time dateTime={authorization.createdAt}>
                              授權於 {formatDate(authorization.createdAt)}
                            </time>
                          </div>
                          <div className="authorization-actions">
                            <button
                              type="button"
                              className="button button-secondary button-compact"
                              disabled={authorizationBusy}
                              onClick={() =>
                                setReportTarget({
                                  clientId: authorization.clientId,
                                  name: authorization.name,
                                })
                              }
                            >
                              <Flag aria-hidden="true" />
                              檢舉
                            </button>
                            <button
                              type="button"
                              className="button button-secondary button-compact"
                              disabled={authorizationBusy}
                              onClick={() =>
                                void revokeAuthorization(authorization)
                              }
                            >
                              <ShieldOff aria-hidden="true" />
                              {authorizationBusy ? "撤銷中..." : "撤銷"}
                            </button>
                          </div>
                        </div>
                      );
                    })
                  : null}
                {authorizationsState === "loading" ? (
                  <div className="empty-state">
                    <RefreshCw aria-hidden="true" className="is-spinning" />
                    <span>正在載入授權資料...</span>
                  </div>
                ) : null}
                {authorizationsState === "error" ? (
                  <div className="empty-state empty-state-error" role="alert">
                    <ShieldOff aria-hidden="true" />
                    <span>{authorizationsError}</span>
                    <button
                      type="button"
                      className="button button-secondary button-compact"
                      onClick={() => void loadAuthorizations()}
                    >
                      <RefreshCw aria-hidden="true" />
                      重試
                    </button>
                  </div>
                ) : null}
                {authorizationsState === "ready" &&
                authorizations.length === 0 ? (
                  <div className="empty-state">
                    <MonitorSmartphone aria-hidden="true" />
                    <span>尚未授權任何應用程式</span>
                  </div>
                ) : null}
              </div>
              <p className="section-note">
                <ShieldAlert aria-hidden="true" />
                看到冒名或可疑的應用程式？點該應用的「檢舉」回報，我們會盡快處理。
              </p>
            </section>
          ) : null}

          {tab === "admin" ? (
            <section className="page-section">
              {canManageUsers ? (
                <div className="admin-band admin-band-flush">
                  <div>
                    <span className="eyebrow">Administration</span>
                    <h3>建立邀請資格</h3>
                    <p className="section-description">
                      若這個 Email 已有帳號，會直接套用所選角色。
                    </p>
                  </div>
                  <div className="invite-form">
                    <label>
                      <span>Email</span>
                      <div className="input-with-icon">
                        <Mail aria-hidden="true" />
                        <input
                          type="email"
                          value={inviteEmail}
                          onChange={(event) => setInviteEmail(event.target.value)}
                          autoComplete="off"
                        />
                      </div>
                    </label>
                    <label>
                      <span>角色</span>
                      <select
                        value={inviteRole}
                        onChange={(event) =>
                          setInviteRole(event.target.value as PlatformRole)
                        }
                      >
                        <option value="user">User</option>
                        <option value="developer">Developer</option>
                        {(viewerRole ?? sessionRole) === "bootadmin" ? (
                          <option value="admin">Admin</option>
                        ) : null}
                      </select>
                    </label>
                    <button
                      type="button"
                      className="button button-primary"
                      disabled={!inviteEmail || busy === "invite"}
                      onClick={createInvitation}
                    >
                      <Plus aria-hidden="true" />
                      建立
                    </button>
                  </div>
                </div>
              ) : null}

              {canManageUsers ? (
                <div className="admin-band">
                  <div>
                    <span className="eyebrow">Administration</span>
                    <h3>使用者管理</h3>
                    <p className="section-description">
                      角色變更、停權、session 撤銷與刪除都會寫入稽核紀錄。
                    </p>
                  </div>

                  {adminUsersError ? (
                    <div className="authorization-inline-error" role="alert">
                      <ShieldOff aria-hidden="true" />
                      <span>{adminUsersError}</span>
                    </div>
                  ) : null}

                  <form
                    className="invite-form user-search-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const query = userSearchDraft.trim();
                      setAdminUsersQuery(query);
                      void loadAdminUsers(1, query);
                    }}
                  >
                    <label>
                      <span>搜尋 Email 或名稱</span>
                      <div className="input-with-icon">
                        <Search aria-hidden="true" />
                        <input
                          type="search"
                          value={userSearchDraft}
                          maxLength={254}
                          onChange={(event) =>
                            setUserSearchDraft(event.target.value)
                          }
                          autoComplete="off"
                        />
                      </div>
                    </label>
                    <button
                      type="submit"
                      className="button button-secondary"
                      disabled={adminUsersState === "loading"}
                    >
                      <Search aria-hidden="true" />
                      搜尋
                    </button>
                  </form>

                  <div
                    className="item-list manage-list"
                    aria-busy={adminUsersState === "loading"}
                  >
                    {adminUsersState === "ready"
                      ? adminUsers.map((user) => {
                          const userBusy = busy === `user:${user.id}`;
                          const isSelf = user.id === session.user.id;
                          const isBootadmin = user.role === "bootadmin";
                          const actorRole = viewerRole ?? sessionRole;
                          const assignable = UI_ASSIGNABLE_ROLES[actorRole];
                          const roleLocked =
                            isSelf ||
                            isBootadmin ||
                            !assignable.includes(user.role);
                          const manageLocked = isSelf || isBootadmin;
                          const roleOptions = assignable.includes(user.role)
                            ? assignable
                            : [user.role, ...assignable];
                          return (
                            <div
                              className="list-item"
                              key={user.id}
                              aria-busy={userBusy}
                            >
                              <span className="item-icon">
                                <UserRound aria-hidden="true" />
                              </span>
                              <div className="item-copy">
                                <strong>
                                  {user.name || user.email}
                                  {isSelf ? "（你）" : ""}
                                </strong>
                                <span className="mono">{user.email}</span>
                                <span>
                                  {ROLE_LABELS[user.role]}
                                  {user.status === "suspended"
                                    ? " · 已停權"
                                    : " · Active"}
                                  {` · ${user.passkeyCount} passkeys`}
                                  {` · ${user.authorizedAppCount} 個授權 app`}
                                </span>
                                <span>
                                  建立於 {formatDate(user.createdAt)}
                                  {user.lastSessionAt
                                    ? ` · 最後 session ${formatDate(user.lastSessionAt)}`
                                    : " · 沒有 session 紀錄"}
                                </span>
                              </div>
                              <div className="manage-actions">
                                <select
                                  className="role-select"
                                  aria-label={`變更 ${user.email} 的角色`}
                                  value={user.role}
                                  disabled={userBusy || roleLocked}
                                  onChange={(event) => {
                                    const role = event.target
                                      .value as PlatformRole;
                                    if (role !== user.role) {
                                      void changeUserRole(user, role);
                                    }
                                  }}
                                >
                                  {roleOptions.map((role) => (
                                    <option key={role} value={role}>
                                      {ROLE_LABELS[role]}
                                    </option>
                                  ))}
                                </select>
                                <button
                                  type="button"
                                  className="icon-button"
                                  aria-label={
                                    user.status === "active"
                                      ? `停權 ${user.email}`
                                      : `復權 ${user.email}`
                                  }
                                  title={
                                    user.status === "active"
                                      ? "停權並撤銷 sessions/tokens"
                                      : "復權"
                                  }
                                  disabled={userBusy || manageLocked}
                                  onClick={() => void toggleUserStatus(user)}
                                >
                                  {user.status === "active" ? (
                                    <ShieldOff aria-hidden="true" />
                                  ) : (
                                    <ShieldCheck aria-hidden="true" />
                                  )}
                                </button>
                                <button
                                  type="button"
                                  className="icon-button"
                                  aria-label={`撤銷 ${user.email} 的全部 sessions`}
                                  title="撤銷全部 sessions"
                                  disabled={userBusy || manageLocked}
                                  onClick={() => void revokeUserSessions(user)}
                                >
                                  <LogOut aria-hidden="true" />
                                </button>
                                {userPendingDelete === user.id ? (
                                  <button
                                    type="button"
                                    className="button button-danger button-compact"
                                    disabled={userBusy || manageLocked}
                                    onClick={() => void deleteAdminUser(user)}
                                  >
                                    確認刪除
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    className="icon-button danger-icon"
                                    aria-label={`刪除 ${user.email}`}
                                    title="刪除使用者"
                                    disabled={userBusy || manageLocked}
                                    onClick={() =>
                                      setUserPendingDelete(user.id)
                                    }
                                  >
                                    <Trash2 aria-hidden="true" />
                                  </button>
                                )}
                              </div>
                            </div>
                          );
                        })
                      : null}
                    {adminUsersState === "loading" ? (
                      <div className="empty-state">
                        <RefreshCw aria-hidden="true" className="is-spinning" />
                        <span>正在載入使用者...</span>
                      </div>
                    ) : null}
                    {adminUsersState === "error" ? (
                      <div className="empty-state empty-state-error" role="alert">
                        <ShieldOff aria-hidden="true" />
                        <span>無法載入使用者列表。</span>
                        <button
                          type="button"
                          className="button button-secondary button-compact"
                          onClick={() =>
                            void loadAdminUsers(adminUsersPage, adminUsersQuery)
                          }
                        >
                          <RefreshCw aria-hidden="true" />
                          重試
                        </button>
                      </div>
                    ) : null}
                    {adminUsersState === "ready" && adminUsers.length === 0 ? (
                      <div className="empty-state">
                        <UserRound aria-hidden="true" />
                        <span>找不到符合的使用者</span>
                      </div>
                    ) : null}
                  </div>

                  {adminUsersState === "ready" && adminUsersTotal > 0 ? (
                    <div className="pagination-row">
                      <button
                        type="button"
                        className="button button-secondary button-compact"
                        disabled={adminUsersPage <= 1}
                        onClick={() =>
                          void loadAdminUsers(
                            adminUsersPage - 1,
                            adminUsersQuery,
                          )
                        }
                      >
                        上一頁
                      </button>
                      <span>
                        第 {adminUsersPage} 頁 · 共 {adminUsersTotal} 位使用者
                      </span>
                      <button
                        type="button"
                        className="button button-secondary button-compact"
                        disabled={adminUsersPage * 10 >= adminUsersTotal}
                        onClick={() =>
                          void loadAdminUsers(
                            adminUsersPage + 1,
                            adminUsersQuery,
                          )
                        }
                      >
                        下一頁
                      </button>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </section>
          ) : null}

          {tab === "developer" ? (
            <section className="page-section">
              {canManageClients ? (
                <div className="admin-band admin-band-flush">
                  <div>
                    <span className="eyebrow">Administration</span>
                    <h3>OAuth Clients</h3>
                    <p className="section-description">
                      {sessionRole === "developer"
                        ? "管理你擁有的 OIDC 應用程式。"
                        : "管理 OIDC 應用程式。"}
                      Client secret 只會在建立或重設時顯示一次，
                      請立即存入應用程式的 secret 管理機制。
                    </p>
                  </div>

                  {adminClientsError ? (
                    <div className="authorization-inline-error" role="alert">
                      <ShieldOff aria-hidden="true" />
                      <span>{adminClientsError}</span>
                    </div>
                  ) : null}

                  {issuedClientSecret ? (
                    <div className="client-secret-panel" role="status">
                      <div>
                        <strong>
                          {issuedClientSecret.clientId} 的 client secret
                        </strong>
                        <span>只會顯示這一次，關閉後無法再取得。</span>
                        <code className="mono">{issuedClientSecret.secret}</code>
                      </div>
                      <button
                        type="button"
                        className="icon-button"
                        aria-label="關閉 secret 顯示"
                        title="關閉"
                        onClick={() => setIssuedClientSecret(null)}
                      >
                        <X aria-hidden="true" />
                      </button>
                    </div>
                  ) : null}

                  <div className="invite-form client-form">
                    <label>
                      <span>名稱</span>
                      <input
                        type="text"
                        maxLength={64}
                        value={clientName}
                        onChange={(event) => setClientName(event.target.value)}
                        autoComplete="off"
                      />
                    </label>
                    <label>
                      <span>Client ID（選填，留空自動產生）</span>
                      <input
                        type="text"
                        maxLength={64}
                        value={clientIdDraft}
                        onChange={(event) => setClientIdDraft(event.target.value)}
                        autoComplete="off"
                        placeholder="pg72-copy"
                      />
                    </label>
                    <label>
                      <span>開發者名稱（顯示於授權畫面）</span>
                      <input
                        type="text"
                        maxLength={64}
                        value={clientDeveloperDraft}
                        onChange={(event) =>
                          setClientDeveloperDraft(event.target.value)
                        }
                        autoComplete="off"
                        placeholder="PG72 官方"
                      />
                    </label>
                    <label>
                      <span>服務條款 URL（選填，HTTPS）</span>
                      <input
                        type="url"
                        maxLength={512}
                        value={clientTermsUrlDraft}
                        onChange={(event) =>
                          setClientTermsUrlDraft(event.target.value)
                        }
                        autoComplete="off"
                        placeholder="https://copy.pg72.tw/terms"
                        spellCheck={false}
                      />
                    </label>
                    <label>
                      <span>隱私權政策 URL（選填，HTTPS）</span>
                      <input
                        type="url"
                        maxLength={512}
                        value={clientPrivacyUrlDraft}
                        onChange={(event) =>
                          setClientPrivacyUrlDraft(event.target.value)
                        }
                        autoComplete="off"
                        placeholder="https://copy.pg72.tw/privacy"
                        spellCheck={false}
                      />
                    </label>
                    <label className="client-form-full">
                      <span>Redirect URIs（每行一個，production 僅接受 HTTPS）</span>
                      <textarea
                        rows={3}
                        value={clientRedirectUrisDraft}
                        onChange={(event) =>
                          setClientRedirectUrisDraft(event.target.value)
                        }
                        placeholder="https://copy.pg72.tw/api/auth/callback/pg72-id"
                        spellCheck={false}
                      />
                    </label>
                    <label>
                      <span>類型</span>
                      <select
                        value={clientTypeDraft}
                        onChange={(event) =>
                          setClientTypeDraft(
                            event.target.value as "confidential" | "public",
                          )
                        }
                      >
                        <option value="confidential">
                          Confidential（server-side，發 secret）
                        </option>
                        <option value="public">Public（PKCE，無 secret）</option>
                      </select>
                    </label>
                    <label className="client-checkbox">
                      <span>Refresh token</span>
                      <span className="client-checkbox-row">
                        <input
                          type="checkbox"
                          checked={clientOfflineDraft}
                          onChange={(event) =>
                            setClientOfflineDraft(event.target.checked)
                          }
                        />
                        啟用 offline_access 與 refresh_token
                      </span>
                    </label>
                    <button
                      type="button"
                      className="button button-primary"
                      disabled={
                        !clientName.trim() ||
                        !clientDeveloperDraft.trim() ||
                        !clientRedirectUrisDraft.trim() ||
                        busy === "client:create"
                      }
                      onClick={() => void createAdminClient()}
                    >
                      <Plus aria-hidden="true" />
                      {busy === "client:create" ? "建立中..." : "建立"}
                    </button>
                  </div>

                  <div
                    className="item-list manage-list"
                    aria-busy={adminClientsState === "loading"}
                  >
                    {adminClientsState === "ready"
                      ? adminClients.map((client) => {
                          const clientBusy = busy === `client:${client.clientId}`;
                          const editingClient =
                            editingClientId === client.clientId;
                          return (
                            <div
                              className="list-item"
                              key={client.clientId}
                              aria-busy={clientBusy}
                            >
                              <span className="item-icon authorization-icon">
                                <MonitorSmartphone aria-hidden="true" />
                              </span>
                              <div className="item-copy">
                                <strong>{client.name}</strong>
                                <span className="mono">{client.clientId}</span>
                                <span>
                                  開發者：{client.developerName ?? "未填寫"}
                                  {client.termsOfServiceUrl ? " · 服務條款" : ""}
                                  {client.privacyPolicyUrl ? " · 隱私權政策" : ""}
                                </span>
                                <span>
                                  {client.public
                                    ? "Public · PKCE"
                                    : `Confidential · ${
                                        client.tokenEndpointAuthMethod ??
                                        "client_secret_post"
                                      }`}
                                  {client.grantTypes.includes("refresh_token")
                                    ? " · refresh_token"
                                    : ""}
                                  {client.trusted ? " · Trusted" : ""}
                                  {client.disabled ? " · 已停用" : ""}
                                </span>
                                <span className="mono">
                                  {client.redirectUris.join(" ")}
                                </span>
                                {editingClient ? (
                                  <form
                                    className="client-trust-form"
                                    onSubmit={(event) => {
                                      event.preventDefault();
                                      if (!clientBusy) {
                                        void updateAdminClientTrust(client);
                                      }
                                    }}
                                  >
                                    <label>
                                      <span>開發者名稱</span>
                                      <input
                                        type="text"
                                        maxLength={64}
                                        value={editDeveloperDraft}
                                        disabled={clientBusy}
                                        onChange={(event) =>
                                          setEditDeveloperDraft(event.target.value)
                                        }
                                        autoComplete="off"
                                      />
                                    </label>
                                    <label>
                                      <span>服務條款 URL（選填，HTTPS）</span>
                                      <input
                                        type="url"
                                        maxLength={512}
                                        value={editTermsUrlDraft}
                                        disabled={clientBusy}
                                        onChange={(event) =>
                                          setEditTermsUrlDraft(event.target.value)
                                        }
                                        autoComplete="off"
                                        spellCheck={false}
                                      />
                                    </label>
                                    <label>
                                      <span>隱私權政策 URL（選填，HTTPS）</span>
                                      <input
                                        type="url"
                                        maxLength={512}
                                        value={editPrivacyUrlDraft}
                                        disabled={clientBusy}
                                        onChange={(event) =>
                                          setEditPrivacyUrlDraft(event.target.value)
                                        }
                                        autoComplete="off"
                                        spellCheck={false}
                                      />
                                    </label>
                                    <div className="client-trust-actions">
                                      <button
                                        type="button"
                                        className="button button-secondary button-compact"
                                        disabled={clientBusy}
                                        onClick={() => setEditingClientId(null)}
                                      >
                                        取消
                                      </button>
                                      <button
                                        type="submit"
                                        className="button button-primary button-compact"
                                        disabled={
                                          clientBusy || !editDeveloperDraft.trim()
                                        }
                                      >
                                        {clientBusy ? "儲存中..." : "儲存"}
                                      </button>
                                    </div>
                                  </form>
                                ) : null}
                              </div>
                              <div className="manage-actions">
                                {!client.trusted ? (
                                  <button
                                    type="button"
                                    className="icon-button"
                                    aria-label={`編輯 ${client.clientId} 的信任資訊`}
                                    title="編輯開發者與條款資訊"
                                    disabled={clientBusy}
                                    onClick={() =>
                                      editingClient
                                        ? setEditingClientId(null)
                                        : beginClientTrustEdit(client)
                                    }
                                  >
                                    <Pencil aria-hidden="true" />
                                  </button>
                                ) : null}
                                {!client.trusted && !client.public ? (
                                  <button
                                    type="button"
                                    className="icon-button"
                                    aria-label={`重設 ${client.clientId} 的 secret`}
                                    title="重設 secret"
                                    disabled={clientBusy}
                                    onClick={() =>
                                      void rotateAdminClientSecret(client)
                                    }
                                  >
                                    <KeyRound aria-hidden="true" />
                                  </button>
                                ) : null}
                                {!client.trusted ? (
                                  <button
                                    type="button"
                                    className="icon-button"
                                    aria-label={
                                      client.disabled
                                        ? `啟用 ${client.clientId}`
                                        : `停用 ${client.clientId}`
                                    }
                                    title={client.disabled ? "啟用" : "停用並撤銷 tokens"}
                                    disabled={clientBusy}
                                    onClick={() =>
                                      void toggleAdminClientStatus(client)
                                    }
                                  >
                                    {client.disabled ? (
                                      <ShieldCheck aria-hidden="true" />
                                    ) : (
                                      <ShieldOff aria-hidden="true" />
                                    )}
                                  </button>
                                ) : null}
                                {!client.trusted ? (
                                  clientPendingDelete === client.clientId ? (
                                    <button
                                      type="button"
                                      className="button button-danger button-compact"
                                      disabled={clientBusy}
                                      onClick={() => void deleteAdminClient(client)}
                                    >
                                      確認刪除
                                    </button>
                                  ) : (
                                    <button
                                      type="button"
                                      className="icon-button danger-icon"
                                      aria-label={`刪除 ${client.clientId}`}
                                      title="刪除（連帶撤銷 tokens 與 consents）"
                                      disabled={clientBusy}
                                      onClick={() =>
                                        setClientPendingDelete(client.clientId)
                                      }
                                    >
                                      <Trash2 aria-hidden="true" />
                                    </button>
                                  )
                                ) : null}
                              </div>
                            </div>
                          );
                        })
                      : null}
                    {adminClientsState === "loading" ? (
                      <div className="empty-state">
                        <RefreshCw aria-hidden="true" className="is-spinning" />
                        <span>正在載入 clients...</span>
                      </div>
                    ) : null}
                    {adminClientsState === "error" ? (
                      <div className="empty-state empty-state-error" role="alert">
                        <ShieldOff aria-hidden="true" />
                        <span>無法載入 OAuth clients。</span>
                        <button
                          type="button"
                          className="button button-secondary button-compact"
                          onClick={() => void loadAdminClients()}
                        >
                          <RefreshCw aria-hidden="true" />
                          重試
                        </button>
                      </div>
                    ) : null}
                    {adminClientsState === "ready" && adminClients.length === 0 ? (
                      <div className="empty-state">
                        <MonitorSmartphone aria-hidden="true" />
                        <span>尚未建立任何 OAuth client</span>
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}

              <div className="developer-resources">
                <div className="section-heading developer-resources-heading">
                  <div>
                    <span className="eyebrow">Resources</span>
                    <h3>開發者資源</h3>
                    <p className="section-description">
                      串接 PGID 所需的說明文件與規範。
                    </p>
                  </div>
                  <span className="item-icon key-icon">
                    <BookOpen aria-hidden="true" />
                  </span>
                </div>
                <div className="item-list">
                  {DEVELOPER_RESOURCES.map((resource) => (
                    <a
                      className="list-item resource-item"
                      key={resource.href}
                      href={resource.href}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <span className="item-icon">
                        <Code2 aria-hidden="true" />
                      </span>
                      <div className="item-copy">
                        <strong>{resource.label}</strong>
                        <span>{resource.description}</span>
                      </div>
                      <ExternalLink aria-hidden="true" className="chevron" />
                    </a>
                  ))}
                </div>
              </div>
            </section>
          ) : null}

          {tab === "security" ? (
            <section className="page-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Sign-in methods</span>
                  <h2>登入方式</h2>
                  <p className="section-description">
                    只能在已登入時主動連結新的登入方式,且帳號至少要保留一種。
                  </p>
                </div>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="重新整理登入方式"
                  title="重新整理"
                  disabled={loginMethodsState === "loading"}
                  onClick={() => void loadLoginMethods()}
                >
                  <RefreshCw
                    aria-hidden="true"
                    className={
                      loginMethodsState === "loading" ? "is-spinning" : undefined
                    }
                  />
                </button>
              </div>
              {loginMethodsError ? (
                <div className="authorization-inline-error" role="alert">
                  <ShieldOff aria-hidden="true" />
                  <span>{loginMethodsError}</span>
                </div>
              ) : null}
              <div
                className="item-list"
                aria-busy={loginMethodsState === "loading"}
              >
                {loginMethodsState === "ready" && loginMethods
                  ? loginMethods.providers.map((method) => {
                      const methodBusy = busy === `login-method:${method.id}`;
                      return (
                        <div
                          className="list-item"
                          key={method.id}
                          aria-busy={methodBusy}
                        >
                          <span className="item-icon">
                            <LogIn aria-hidden="true" />
                          </span>
                          <div className="item-copy">
                            <strong>{providerLabel(method.provider)}</strong>
                            <span>已連結</span>
                            <time dateTime={method.createdAt}>
                              連結於 {formatDate(method.createdAt)}
                            </time>
                          </div>
                          {method.canUnlink ? (
                            unlinkPendingId === method.id ? (
                              <button
                                type="button"
                                className="button button-danger button-compact"
                                disabled={methodBusy}
                                onClick={() => void unlinkLoginMethod(method)}
                              >
                                {methodBusy ? "解除中..." : "確認解除"}
                              </button>
                            ) : (
                              <button
                                type="button"
                                className="button button-secondary button-compact"
                                disabled={methodBusy}
                                onClick={() => setUnlinkPendingId(method.id)}
                              >
                                <ShieldOff aria-hidden="true" />
                                解除連結
                              </button>
                            )
                          ) : (
                            <span className="section-description">
                              唯一登入方式
                            </span>
                          )}
                        </div>
                      );
                    })
                  : null}
                {loginMethodsState === "ready" && loginMethods ? (
                  <div className="list-item">
                    <span className="item-icon key-icon">
                      <KeyRound aria-hidden="true" />
                    </span>
                    <div className="item-copy">
                      <strong>Passkeys</strong>
                      <span>
                        {loginMethods.passkeyCount > 0
                          ? `${loginMethods.passkeyCount} 把,於下方管理。`
                          : "尚未註冊,可於下方新增。"}
                      </span>
                    </div>
                  </div>
                ) : null}
                {loginMethodsState === "ready" && loginMethods
                  ? loginMethods.linkable
                      .filter(isLinkableProviderId)
                      .map((provider) => (
                        <div className="list-item" key={`link-${provider}`}>
                          <span className="item-icon">
                            <Plus aria-hidden="true" />
                          </span>
                          <div className="item-copy">
                            <strong>{providerLabel(provider)}</strong>
                            <span>尚未連結</span>
                          </div>
                          {provider === "telegram" && telegramConfig?.enabled ? (
                            <TelegramLogin
                              config={telegramConfig}
                              disabled={busy !== null}
                              endpoint="/api/auth/telegram/link"
                              onSuccess={() => {
                                setNotice("Telegram 已連結。");
                                void loadLoginMethods();
                              }}
                            />
                          ) : (
                            <button
                              type="button"
                              className="button button-primary button-compact"
                              disabled={busy === `link:${provider}`}
                              onClick={() => void linkLoginMethod(provider)}
                            >
                              <LogIn aria-hidden="true" />
                              {busy === `link:${provider}`
                                ? "前往連結..."
                                : `連結 ${providerLabel(provider)}`}
                            </button>
                          )}
                        </div>
                      ))
                  : null}
                {loginMethodsState === "loading" ? (
                  <div className="empty-state">
                    <RefreshCw aria-hidden="true" className="is-spinning" />
                    <span>正在載入登入方式...</span>
                  </div>
                ) : null}
                {loginMethodsState === "error" ? (
                  <div className="empty-state empty-state-error" role="alert">
                    <ShieldOff aria-hidden="true" />
                    <span>{loginMethodsError}</span>
                    <button
                      type="button"
                      className="button button-secondary button-compact"
                      onClick={() => void loadLoginMethods()}
                    >
                      <RefreshCw aria-hidden="true" />
                      重試
                    </button>
                  </div>
                ) : null}
              </div>

              <div className="section-heading session-heading">
                <div>
                  <span className="eyebrow">Authentication</span>
                  <h2>Passkeys</h2>
                </div>
                <button
                  type="button"
                  className="button button-primary"
                  onClick={addPasskey}
                  disabled={busy === "passkey:add"}
                >
                  <Plus aria-hidden="true" />
                  {busy === "passkey:add" ? "新增中..." : "新增 Passkey"}
                </button>
              </div>

              {passkeyError ? (
                <div className="passkey-inline-error" role="alert">
                  <ShieldOff aria-hidden="true" />
                  <span>{passkeyError}</span>
                </div>
              ) : null}

              <PasskeyList
                busy={busy}
                editingPasskeyId={editingPasskeyId}
                passkeyName={passkeyName}
                onBeginRename={beginPasskeyRename}
                onRenameChange={setPasskeyName}
                onRenameSubmit={(passkey) => void updatePasskeyName(passkey)}
                onRenameCancel={() => {
                  setEditingPasskeyId(null);
                  setPasskeyName("");
                  setPasskeyError(null);
                }}
                onRequestDelete={(passkey) => {
                  setPasskeyDeleteError(null);
                  setPasskeyToDelete(passkey);
                }}
              />

              <div className="section-heading session-heading">
                <div>
                  <span className="eyebrow">Devices</span>
                  <h2>登入中的裝置</h2>
                </div>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="重新整理裝置"
                  title="重新整理"
                  onClick={loadSessions}
                >
                  <RefreshCw aria-hidden="true" />
                </button>
              </div>
              <div
                className="item-list"
                aria-busy={sessionsState === "loading"}
              >
                {sessionsState === "ready"
                  ? sessions.map((item) => (
                      <div className="list-item" key={item.id}>
                        <span className="item-icon">
                          {deviceIcon(item.userAgent)}
                        </span>
                        <div className="item-copy">
                          <strong>{friendlyDevice(item.userAgent)}</strong>
                          <span>{formatDate(item.updatedAt)}</span>
                        </div>
                        <button
                          type="button"
                          className="icon-button danger-icon"
                          aria-label="撤銷此裝置"
                          title="撤銷此裝置"
                          disabled={busy === item.token}
                          onClick={() => revokeSession(item.token)}
                        >
                          <Trash2 aria-hidden="true" />
                        </button>
                      </div>
                    ))
                  : null}
                {sessionsState === "loading" ? (
                  <div className="empty-state">
                    <RefreshCw aria-hidden="true" className="is-spinning" />
                    <span>正在載入裝置...</span>
                  </div>
                ) : null}
                {sessionsState === "error" ? (
                  <div className="empty-state empty-state-error" role="alert">
                    <ShieldOff aria-hidden="true" />
                    <span>無法載入登入中的裝置。</span>
                    <button
                      type="button"
                      className="button button-secondary button-compact"
                      onClick={() => void loadSessions()}
                    >
                      <RefreshCw aria-hidden="true" />
                      重試
                    </button>
                  </div>
                ) : null}
                {sessionsState === "ready" && sessions.length === 0 ? (
                  <div className="empty-state">
                    <MonitorSmartphone aria-hidden="true" />
                    <span>目前沒有登入中的裝置</span>
                  </div>
                ) : null}
              </div>
              <div className="danger-row">
                <div>
                  <strong>登出其他裝置</strong>
                  <span>保留目前瀏覽器的 session。</span>
                </div>
                <button
                  type="button"
                  className="button button-danger"
                  onClick={revokeOtherSessions}
                  disabled={busy === "revoke-others"}
                >
                  <LogOut aria-hidden="true" />
                  全部登出
                </button>
              </div>
            </section>
          ) : null}

          {tab === "activity" ? (
            <section className="page-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Audit</span>
                  <h2>安全活動</h2>
                  <p className="section-description">
                    登入、授權、Passkey 與個資變更等事件。裝置與來源摘要已去識別化。
                  </p>
                </div>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="重新整理活動"
                  title="重新整理"
                  disabled={activityState === "loading"}
                  onClick={() => void loadSecurityActivity()}
                >
                  <RefreshCw
                    aria-hidden="true"
                    className={
                      activityState === "loading" ? "is-spinning" : undefined
                    }
                  />
                </button>
              </div>
              <ol
                className="activity-timeline"
                aria-busy={activityState === "loading"}
              >
                {activityState === "ready"
                  ? activityEvents.map((event) => (
                      <li className="activity-item" key={event.id}>
                        <span className="activity-marker" aria-hidden="true" />
                        <div className="activity-body">
                          <strong>{securityActivityLabel(event.type)}</strong>
                          {event.summary ? (
                            <span>{event.summary}</span>
                          ) : null}
                          <time dateTime={event.at}>
                            {formatDate(event.at)}
                            {event.provider ? ` · ${providerLabel(event.provider)}` : ""}
                          </time>
                        </div>
                      </li>
                    ))
                  : null}
                {activityState === "loading" ? (
                  <li className="empty-state">
                    <RefreshCw aria-hidden="true" className="is-spinning" />
                    <span>正在載入安全活動...</span>
                  </li>
                ) : null}
                {activityState === "error" ? (
                  <li className="empty-state empty-state-error" role="alert">
                    <ShieldOff aria-hidden="true" />
                    <span>無法載入安全活動。</span>
                    <button
                      type="button"
                      className="button button-secondary button-compact"
                      onClick={() => void loadSecurityActivity()}
                    >
                      <RefreshCw aria-hidden="true" />
                      重試
                    </button>
                  </li>
                ) : null}
                {activityState === "ready" && activityEvents.length === 0 ? (
                  <li className="empty-state">
                    <Activity aria-hidden="true" />
                    <span>尚無安全活動</span>
                  </li>
                ) : null}
              </ol>
              {activityState === "ready" && activityCursor ? (
                <div className="activity-more">
                  {activityMoreError ? (
                    <div
                      className="authorization-inline-error"
                      role="alert"
                    >
                      <ShieldOff aria-hidden="true" />
                      <span>{activityMoreError}</span>
                    </div>
                  ) : null}
                  <button
                    type="button"
                    className="button button-secondary button-compact"
                    disabled={activityLoadingMore}
                    onClick={() => void loadMoreSecurityActivity()}
                  >
                    <RefreshCw
                      aria-hidden="true"
                      className={activityLoadingMore ? "is-spinning" : undefined}
                    />
                    {activityLoadingMore
                      ? "載入中..."
                      : activityMoreError
                        ? "重試"
                        : "載入更多"}
                  </button>
                </div>
              ) : null}
            </section>
          ) : null}
        </main>
      </div>
      {deleteDialogOpen ? (
        <DeleteAccountDialog
          busy={busy === "delete-account"}
          email={session.user.email}
          error={deleteError}
          onCancel={closeDeleteDialog}
          onConfirm={() => void deleteAccount()}
        />
      ) : null}
      {passkeyToDelete ? (
        <DeletePasskeyDialog
          busy={busy === `passkey:delete:${passkeyToDelete.id}`}
          error={passkeyDeleteError}
          passkey={passkeyToDelete}
          onCancel={() => {
            setPasskeyDeleteError(null);
            setPasskeyToDelete(null);
          }}
          onConfirm={() => void deletePasskey()}
        />
      ) : null}
      {reportTarget ? (
        <ReportDialog
          clientId={reportTarget.clientId}
          clientName={reportTarget.name}
          onClose={() => setReportTarget(null)}
        />
      ) : null}
    </div>
  );
}
