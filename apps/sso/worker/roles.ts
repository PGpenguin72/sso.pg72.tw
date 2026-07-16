import { normalizeEmail, type RuntimeConfig } from "./config";

/**
 * Four-tier platform role hierarchy.
 *
 * - `bootadmin`: the bootstrap administrator bound to BOOTSTRAP_ADMIN_EMAIL.
 *   Cannot be deleted, demoted, or suspended, and is the only role that can
 *   grant or revoke `admin`.
 * - `admin`: manages users (invite, suspend, delete, assign developer/user)
 *   and every OAuth client.
 * - `developer`: creates and manages only the OAuth clients they own.
 * - `user`: no administrative access.
 */
export const PLATFORM_ROLES = [
  "bootadmin",
  "admin",
  "developer",
  "user",
] as const;

export type PlatformRole = (typeof PLATFORM_ROLES)[number];

export type AdminPermission =
  /** Create and manage OAuth clients owned by the actor. */
  | "clients.manage"
  /** Manage every OAuth client regardless of owner. */
  | "clients.manage_all"
  /** List and search user accounts. */
  | "users.read"
  /** Create invitations (role limited by ASSIGNABLE_ROLES). */
  | "users.invite"
  /** Suspend/reactivate, revoke sessions, and delete user accounts. */
  | "users.manage"
  /** Change platform roles (targets limited by ASSIGNABLE_ROLES). */
  | "users.assign_roles";

/**
 * Role-to-permission mapping. Adjust capabilities here; route handlers only
 * ever check permissions, never role names.
 */
export const ROLE_PERMISSIONS: Record<
  PlatformRole,
  readonly AdminPermission[]
> = {
  bootadmin: [
    "clients.manage",
    "clients.manage_all",
    "users.read",
    "users.invite",
    "users.manage",
    "users.assign_roles",
  ],
  admin: [
    "clients.manage",
    "clients.manage_all",
    "users.read",
    "users.invite",
    "users.manage",
    "users.assign_roles",
  ],
  developer: ["clients.manage"],
  user: [],
};

/**
 * Roles an actor may grant to, or take away from, another account. This also
 * bounds invitation roles. `bootadmin` is never assignable: it is derived
 * from BOOTSTRAP_ADMIN_EMAIL, not granted.
 */
export const ASSIGNABLE_ROLES: Record<PlatformRole, readonly PlatformRole[]> = {
  bootadmin: ["admin", "developer", "user"],
  admin: ["developer", "user"],
  developer: [],
  user: [],
};

export function isPlatformRole(value: unknown): value is PlatformRole {
  return (
    typeof value === "string" &&
    (PLATFORM_ROLES as readonly string[]).includes(value)
  );
}

export function hasPermission(
  role: PlatformRole,
  permission: AdminPermission,
): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}

/**
 * Resolves the effective platform role for access control and token claims.
 *
 * The account whose email matches BOOTSTRAP_ADMIN_EMAIL is always
 * `bootadmin`, even before its stored role has been converted (rows created
 * before the four-tier model stored `admin`). Conversely a stale stored
 * `bootadmin` row whose email no longer matches (BOOTSTRAP_ADMIN_EMAIL was
 * rotated) keeps administrator rights but loses bootadmin powers and
 * protections.
 */
export function effectivePlatformRole(
  storedRole: unknown,
  email: string,
  config: Pick<RuntimeConfig, "bootstrapAdminEmail">,
): PlatformRole {
  if (normalizeEmail(email) === config.bootstrapAdminEmail) {
    return "bootadmin";
  }
  if (storedRole === "bootadmin") return "admin";
  return isPlatformRole(storedRole) ? storedRole : "user";
}

export type AdminActionDenial =
  | "bootadmin_protected"
  | "cannot_modify_self"
  | "role_not_assignable";

export interface RoleChangeRequest {
  actorRole: PlatformRole;
  actorUserId: string;
  nextRole: PlatformRole;
  targetProtected: boolean;
  targetRole: PlatformRole;
  targetUserId: string;
}

/**
 * Validates a role change (direct or via invitation to an existing user).
 * Returns a denial reason, or null when the change is allowed.
 */
export function denyRoleChange(
  request: RoleChangeRequest,
): AdminActionDenial | null {
  if (request.targetProtected) return "bootadmin_protected";
  if (request.actorUserId === request.targetUserId) {
    return "cannot_modify_self";
  }
  const assignable = ASSIGNABLE_ROLES[request.actorRole];
  // The target's current role must also be assignable by the actor so an
  // admin cannot demote another admin; only bootadmin can.
  if (
    !assignable.includes(request.nextRole) ||
    !assignable.includes(request.targetRole)
  ) {
    return "role_not_assignable";
  }
  return null;
}

/**
 * Validates suspend/reactivate, session revocation, and deletion targets.
 * Any admin may manage any non-bootadmin account except their own.
 */
export function denyUserManagement(request: {
  actorUserId: string;
  targetProtected: boolean;
  targetUserId: string;
}): AdminActionDenial | null {
  if (request.targetProtected) return "bootadmin_protected";
  if (request.actorUserId === request.targetUserId) {
    return "cannot_modify_self";
  }
  return null;
}
