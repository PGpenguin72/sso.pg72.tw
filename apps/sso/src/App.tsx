import {
  Activity,
  Check,
  KeyRound,
  Laptop,
  LogIn,
  LogOut,
  Mail,
  MonitorSmartphone,
  Moon,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Sun,
  Trash2,
  UserRound,
  X,
} from "lucide-react";
import type { Passkey } from "@better-auth/passkey";
import { useCallback, useEffect, useRef, useState } from "react";

import { authClient } from "./auth-client";

interface DeviceSession {
  id: string;
  token: string;
  updatedAt: string | Date;
  userAgent?: string | null;
}

interface AuditEvent {
  id: string;
  event_type: string;
  outcome: "denied" | "failure" | "success";
  occurred_at: string;
}

interface AuditResponse {
  events: AuditEvent[];
}

interface PublicOAuthClient {
  client_id?: string;
  client_name?: string;
  client_uri?: string;
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
  uri: string | null;
  disabled: boolean;
  public: boolean;
  scopes: string[];
  redirectUris: string[];
  grantTypes: string[];
  tokenEndpointAuthMethod: string | null;
  hasSecret: boolean;
  trusted: boolean;
  createdAt: string | null;
  updatedAt: string | null;
}

interface AdminClientsResponse {
  clients: AdminOAuthClient[];
}

interface CreatedAdminClientResponse {
  client: AdminOAuthClient;
  clientSecret?: string;
}

const ADMIN_CLIENT_ERROR_MESSAGES: Record<string, string> = {
  client_exists: "這個 Client ID 已存在。",
  invalid_client_id: "Client ID 格式無效（小寫英數、-、_、.，3-64 字元）。",
  invalid_client_name: "名稱不能是空白且不可超過 64 字元。",
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

type Tab = "account" | "security" | "activity";
type Theme = "dark" | "light";
type LoadState = "error" | "loading" | "ready";

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
    ?.setAttribute("content", theme === "dark" ? "#151719" : "#f7f8fa");
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

function SignInView({ pending }: { pending: boolean }) {
  const [busy, setBusy] = useState<"google" | "passkey" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const query = new URLSearchParams(window.location.search);
  const oauthQuery = query.has("client_id") && query.has("sig");

  const googleSignIn = async () => {
    setBusy("google");
    setError(null);
    const result = await authClient.signIn.social({
      provider: "google",
      callbackURL: window.location.href,
    });
    if (result?.error) {
      setError(messageFrom(result.error, "Google sign-in failed."));
      setBusy(null);
    }
  };

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
          <p>使用你的 Google 帳號或已註冊的 Passkey。</p>
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

        {error ? <div className="notice notice-error">{error}</div> : null}
        <p className="invite-note">
          <ShieldCheck aria-hidden="true" />
          目前採邀請制
        </p>
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
    description: "允許網站在你離開後更新登入權杖。",
  },
};

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

function ConsentView({
  clientId,
  userEmail,
}: {
  clientId: string | null;
  userEmail: string;
}) {
  const [busy, setBusy] = useState<"allow" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [client, setClient] = useState<PublicOAuthClient | null>(null);
  const [clientLoading, setClientLoading] = useState(true);
  const scope =
    new URLSearchParams(window.location.search).get("scope") ?? "openid";
  const scopes = scope.split(" ").filter(Boolean);
  const appName = client?.client_name ?? "這個應用程式";
  const clientHost = safeClientHost(client?.client_uri);

  useEffect(() => {
    if (!clientId) {
      setError("缺少應用程式識別資料，請重新開始登入流程。");
      setClientLoading(false);
      return;
    }

    const controller = new AbortController();
    const loadClient = async () => {
      const query = new URLSearchParams({ client_id: clientId });
      const response = await fetch(`/oauth2/public-client?${query}`, {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error("Unable to load OAuth client metadata");
      }

      const data = (await response.json()) as PublicOAuthClient;
      if (data.client_id !== clientId || !data.client_name) {
        throw new Error("OAuth client metadata did not match the request");
      }
      setClient(data);
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
        <Brand />
        <div className="consent-heading">
          <span className="app-glyph">
            <MonitorSmartphone aria-hidden="true" />
          </span>
          <span className="eyebrow">應用程式授權</span>
          <h1>允許 {appName} 存取帳號？</h1>
          {clientHost ? <p className="client-host">{clientHost}</p> : null}
        </div>
        <p className="consent-account">
          將以 <strong>{userEmail}</strong> 繼續
        </p>
        <h2 className="scope-heading">這個網站將能夠：</h2>
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
                </span>
              </li>
            );
          })}
        </ul>
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
            {busy === "deny" ? "返回中..." : "拒絕"}
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
      </main>
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

function DeletePasskeyDialog({
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
          刪除後無法再用這把 Passkey 登入。你的 Google 登入方式不會受到影響。
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

export function App() {
  const sessionQuery = authClient.useSession();
  const passkeysQuery = authClient.useListPasskeys();
  const [tab, setTab] = useState<Tab>("account");
  const [sessions, setSessions] = useState<DeviceSession[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
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
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "user">("user");
  const [adminClients, setAdminClients] = useState<AdminOAuthClient[]>([]);
  const [adminClientsState, setAdminClientsState] =
    useState<LoadState>("loading");
  const [adminClientsError, setAdminClientsError] = useState<string | null>(null);
  const [clientName, setClientName] = useState("");
  const [clientIdDraft, setClientIdDraft] = useState("");
  const [clientRedirectUrisDraft, setClientRedirectUrisDraft] = useState("");
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

  const loadSessions = useCallback(async () => {
    const result = await authClient.listSessions();
    if (result.data) setSessions(result.data);
  }, []);

  const loadAudit = useCallback(async () => {
    const response = await fetch("/api/account/audit", {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (response.ok) {
      const data = (await response.json()) as AuditResponse;
      setAudit(data.events);
    }
  }, []);

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

  useEffect(() => {
    if (session) {
      void loadSessions();
      void loadAudit();
      void loadAuthorizations();
      if (session.user.role === "admin") {
        void loadAdminClients();
      }
    }
  }, [loadAdminClients, loadAudit, loadAuthorizations, loadSessions, session]);

  const isConsent = window.location.pathname === "/consent";
  const clientId = new URLSearchParams(window.location.search).get("client_id");

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

  if (isConsent) {
    return (
      <ConsentView clientId={clientId} userEmail={session.user.email} />
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
        setPasskeyDeleteError(
          message.toLowerCase().includes("fresh") ||
            message.toLowerCase().includes("session_not_fresh")
            ? "刪除最後一把 Passkey 前，請登出並重新登入。"
            : message,
        );
        return;
      }
      setPasskeyToDelete(null);
      setNotice("Passkey 已刪除。");
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

  const createInvitation = async () => {
    setBusy("invite");
    setNotice(null);
    const response = await fetch("/api/admin/invitations", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
    });
    if (response.ok) {
      setInviteEmail("");
      setNotice("邀請資格已建立，有效期限 7 天。 ");
    } else {
      setNotice("無法建立邀請資格。 ");
    }
    setBusy(null);
  };

  const createAdminClient = async () => {
    setBusy("client:create");
    setAdminClientsError(null);
    setIssuedClientSecret(null);
    try {
      const redirectUris = clientRedirectUrisDraft
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
      const isPublic = clientTypeDraft === "public";
      const body: Record<string, unknown> = {
        name: clientName.trim(),
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

  const rotateAdminClientSecret = async (client: AdminOAuthClient) => {
    setBusy(`client:${client.clientId}`);
    setAdminClientsError(null);
    setIssuedClientSecret(null);
    try {
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
        const payload = (await response.json()) as { error?: string };
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
      const response = await fetch(
        `/api/admin/clients/${encodeURIComponent(client.clientId)}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: { Accept: "application/json" },
        },
      );
      if (!response.ok) {
        const payload = (await response.json()) as { error?: string };
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
        <aside className="sidebar" aria-label="帳號中心">
          <h1>帳號中心</h1>
          <nav className="nav-tabs">
            <button
              type="button"
              className={tab === "account" ? "active" : ""}
              onClick={() => setTab("account")}
            >
              <UserRound aria-hidden="true" />
              帳號
            </button>
            <button
              type="button"
              className={tab === "security" ? "active" : ""}
              onClick={() => setTab("security")}
            >
              <ShieldCheck aria-hidden="true" />
              安全性
            </button>
            <button
              type="button"
              className={tab === "activity" ? "active" : ""}
              onClick={() => setTab("activity")}
            >
              <Activity aria-hidden="true" />
              活動
            </button>
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

              <dl className="profile-grid">
                <div>
                  <dt>顯示名稱</dt>
                  <dd>{session.user.name}</dd>
                </div>
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
                  <dd>{session.user.role ?? "user"}</dd>
                </div>
              </dl>

              <div className="section-heading authorization-heading">
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

              {session.user.role === "admin" ? (
                <div className="admin-band">
                  <div>
                    <span className="eyebrow">Administration</span>
                    <h3>建立邀請資格</h3>
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
                          setInviteRole(event.target.value as "admin" | "user")
                        }
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
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

              {session.user.role === "admin" ? (
                <div className="admin-band">
                  <div>
                    <span className="eyebrow">Administration</span>
                    <h3>OAuth Clients</h3>
                    <p className="section-description">
                      管理 OIDC 應用程式。Client secret 只會在建立或重設時顯示一次，
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
                    className="item-list"
                    aria-busy={adminClientsState === "loading"}
                  >
                    {adminClientsState === "ready"
                      ? adminClients.map((client) => {
                          const clientBusy = busy === `client:${client.clientId}`;
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
                                  {client.public
                                    ? "Public · PKCE"
                                    : "Confidential · client_secret_basic"}
                                  {client.grantTypes.includes("refresh_token")
                                    ? " · refresh_token"
                                    : ""}
                                  {client.trusted ? " · Trusted" : ""}
                                  {client.disabled ? " · 已停用" : ""}
                                </span>
                                <span className="mono">
                                  {client.redirectUris.join(" ")}
                                </span>
                              </div>
                              <div className="passkey-actions">
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

          {tab === "security" ? (
            <section className="page-section">
              <div className="section-heading">
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

              <div className="item-list passkey-list" aria-busy={busy?.startsWith("passkey:") === true}>
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
                              if (!updating) void updatePasskeyName(passkey);
                            }}
                          >
                            <input
                              autoFocus
                              type="text"
                              maxLength={64}
                              value={passkeyName}
                              aria-label="Passkey 名稱"
                              disabled={updating}
                              onChange={(event) => setPasskeyName(event.target.value)}
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
                              onClick={() => void updatePasskeyName(passkey)}
                            >
                              <Check aria-hidden="true" />
                            </button>
                            <button
                              type="button"
                              className="icon-button"
                              aria-label="取消重新命名"
                              title="取消"
                              disabled={updating}
                              onClick={() => {
                                setEditingPasskeyId(null);
                                setPasskeyName("");
                                setPasskeyError(null);
                              }}
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
                              onClick={() => beginPasskeyRename(passkey)}
                            >
                              <Pencil aria-hidden="true" />
                            </button>
                            <button
                              type="button"
                              className="icon-button danger-icon"
                              aria-label={`刪除 ${passkey.name?.trim() || "Passkey"}`}
                              title="刪除"
                              disabled={busy?.startsWith("passkey:") === true}
                              onClick={() => {
                                setPasskeyDeleteError(null);
                                setPasskeyToDelete(passkey);
                              }}
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
              <div className="item-list">
                {sessions.map((item) => (
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
                ))}
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
                </div>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="重新整理活動"
                  title="重新整理"
                  onClick={loadAudit}
                >
                  <RefreshCw aria-hidden="true" />
                </button>
              </div>
              <div className="activity-table" role="table">
                {audit.map((event) => (
                  <div className="activity-row" role="row" key={event.id}>
                    <span className={`outcome-dot ${event.outcome}`} />
                    <strong>{event.event_type}</strong>
                    <span>{event.outcome}</span>
                    <time>{formatDate(event.occurred_at)}</time>
                  </div>
                ))}
                {audit.length === 0 ? (
                  <div className="empty-state">
                    <Activity aria-hidden="true" />
                    <span>尚無安全活動</span>
                  </div>
                ) : null}
              </div>
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
    </div>
  );
}
