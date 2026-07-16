/**
 * Shared helpers for the OAuth client trust metadata surfaced on the consent
 * screen: developer identity, terms-of-service and privacy-policy links, and
 * the registered redirect hosts.
 *
 * The `oauthClient` table already provides the `tos` and `policy` columns and
 * a free-form `metadata` JSON column (used by e.g. the diary client for
 * `backchannel_logout_uri`), so no schema change is required. The developer
 * name lives in `metadata.developer_name`; helpers here must always preserve
 * unrelated metadata keys.
 */

export const DEVELOPER_NAME_MAX_LENGTH = 64;
export const DEVELOPER_NAME_METADATA_KEY = "developer_name";
const TRUST_URL_MAX_LENGTH = 512;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export function validDeveloperName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= DEVELOPER_NAME_MAX_LENGTH &&
    !CONTROL_CHARACTERS.test(value)
  );
}

/**
 * Trust links shown to end users on the consent screen must be canonical
 * HTTPS URLs without embedded credentials, in every environment. Returns the
 * normalized URL string, or null when the value is unacceptable.
 */
export function trustUrlOrNull(value: unknown): string | null {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > TRUST_URL_MAX_LENGTH
  ) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    return null;
  }
  return value;
}

/**
 * Parses the oauthClient.metadata JSON column. Unknown shapes collapse to an
 * empty object so a corrupted row can never break the consent screen.
 */
export function parseClientMetadataRecord(
  value: string | null | undefined,
): Record<string, unknown> {
  if (!value) return {};
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

export function developerNameFromMetadata(
  metadata: Record<string, unknown>,
): string | null {
  const value = metadata[DEVELOPER_NAME_METADATA_KEY];
  return validDeveloperName(value) ? value.trim() : null;
}

/**
 * Derives the hosts a client can redirect back to from its registered
 * redirect URIs. This is the anti-impersonation anchor on the consent screen:
 * names are free-form, but these hosts were pinned by an administrator when
 * the client was registered.
 */
export function redirectHostsFromUris(uris: string[]): string[] {
  const hosts = new Set<string>();
  for (const uri of uris) {
    try {
      const host = new URL(uri).host;
      if (host) hosts.add(host);
    } catch {
      // Malformed registered URIs are unreachable through the admin API and
      // are simply skipped for display purposes.
    }
  }
  return [...hosts];
}
