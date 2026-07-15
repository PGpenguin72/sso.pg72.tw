import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import {
  createAuthenticatedUser,
  createBootstrapAdmin,
  sha256Base64Url,
  type TestPlatformRole,
} from "./helpers";

const BASE_URL = "http://localhost:5173";
const USERS_URL = `${BASE_URL}/api/admin/users`;
const INVITATIONS_URL = `${BASE_URL}/api/admin/invitations`;
const CLIENTS_URL = `${BASE_URL}/api/admin/clients`;

interface AdminUserView {
  id: string;
  name: string;
  email: string;
  role: TestPlatformRole;
  status: "active" | "suspended";
  createdAt: string;
  lastSessionAt: string | null;
  passkeyCount: number;
  authorizedAppCount: number;
}

interface UsersResponse {
  page: number;
  perPage: number;
  total: number;
  viewerRole: TestPlatformRole;
  users: AdminUserView[];
}

interface AuditRow {
  actor_user_id: string | null;
  event_type: string;
  metadata_json: string | null;
  outcome: string;
  subject_id: string | null;
}

async function randomUser(role: TestPlatformRole = "user") {
  return createAuthenticatedUser(`${crypto.randomUUID()}@example.com`, role);
}

function listUsers(headers: Headers, query = ""): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}${query}`, { headers }),
  );
}

function setRole(
  headers: Headers,
  userId: string,
  role: string,
): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}/role`, {
      method: "POST",
      headers,
      body: JSON.stringify({ role }),
    }),
  );
}

function setStatus(
  headers: Headers,
  userId: string,
  suspended: boolean,
): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}/status`, {
      method: "POST",
      headers,
      body: JSON.stringify({ suspended }),
    }),
  );
}

function revokeSessions(headers: Headers, userId: string): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}/revoke-sessions`, {
      method: "POST",
      headers,
    }),
  );
}

function deleteUser(headers: Headers, userId: string): Promise<Response> {
  return exports.default.fetch(
    new Request(`${USERS_URL}/${userId}`, { method: "DELETE", headers }),
  );
}

function invite(
  headers: Headers,
  email: string,
  role: string,
): Promise<Response> {
  return exports.default.fetch(
    new Request(INVITATIONS_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, role }),
    }),
  );
}

async function createClient(
  headers: Headers,
  body: Record<string, unknown>,
): Promise<Response> {
  return exports.default.fetch(
    new Request(CLIENTS_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    }),
  );
}

async function storedRole(userId: string): Promise<string | null> {
  const row = await env.PG72_ID_DB.prepare(
    "SELECT role FROM user WHERE id = ?",
  )
    .bind(userId)
    .first<{ role: string | null }>();
  return row?.role ?? null;
}

async function latestAudit(
  eventType: string,
  subjectId: string,
): Promise<AuditRow | null> {
  return env.PG72_ID_DB.prepare(
    `SELECT event_type, actor_user_id, subject_id, outcome, metadata_json
       FROM audit_event
      WHERE event_type = ? AND subject_id = ?
      ORDER BY occurred_at DESC
      LIMIT 1`,
  )
    .bind(eventType, subjectId)
    .first<AuditRow>();
}

async function createPasskey(userId: string): Promise<void> {
  await env.PG72_ID_DB.prepare(
    `INSERT INTO passkey
      (id, name, publicKey, userId, credentialID, counter, deviceType,
       backedUp, transports, createdAt, aaguid)
     VALUES (?, ?, ?, ?, ?, 0, 'singleDevice', 0, 'internal', ?, ?)`,
  )
    .bind(
      crypto.randomUUID(),
      "Matrix Passkey",
      "test-public-key",
      userId,
      crypto.randomUUID(),
      new Date().toISOString(),
      "00000000-0000-0000-0000-000000000000",
    )
    .run();
}

describe("Admin user management", () => {
  it("enforces the role hierarchy access matrix", async () => {
    const unauthenticated = await listUsers(
      new Headers({ Origin: BASE_URL }),
    );
    expect(unauthenticated.status).toBe(401);

    const regular = await randomUser("user");
    const developer = await randomUser("developer");
    const admin = await randomUser("admin");
    const bootadmin = await createBootstrapAdmin();
    const target = await randomUser("user");

    // users.read
    expect((await listUsers(regular.headers)).status).toBe(403);
    expect((await listUsers(developer.headers)).status).toBe(403);
    expect((await listUsers(admin.headers)).status).toBe(200);
    expect((await listUsers(bootadmin.headers)).status).toBe(200);

    // clients.manage: developer gains access, user stays out
    expect(
      (
        await exports.default.fetch(
          new Request(CLIENTS_URL, { headers: regular.headers }),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await exports.default.fetch(
          new Request(CLIENTS_URL, { headers: developer.headers }),
        )
      ).status,
    ).toBe(200);

    // users.invite and users.manage stay closed to developers
    expect(
      (
        await invite(
          developer.headers,
          `${crypto.randomUUID()}@example.com`,
          "user",
        )
      ).status,
    ).toBe(403);
    expect(
      (await setRole(developer.headers, target.userId, "user")).status,
    ).toBe(403);
    expect(
      (await setStatus(developer.headers, target.userId, true)).status,
    ).toBe(403);
    expect(
      (await deleteUser(developer.headers, target.userId)).status,
    ).toBe(403);
  });

  it("lists users with counts, search, and pagination", async () => {
    const admin = await randomUser("admin");
    const tag = crypto.randomUUID().slice(0, 8);
    const first = await createAuthenticatedUser(`${tag}-a@example.com`);
    const second = await createAuthenticatedUser(`${tag}-b@example.com`);
    const third = await createAuthenticatedUser(`${tag}-c@example.com`);
    await createPasskey(first.userId);
    await env.PG72_ID_DB.prepare("UPDATE user SET name = ? WHERE id = ?")
      .bind(`named-${tag}`, second.userId)
      .run();

    const search = await listUsers(
      admin.headers,
      `?q=${encodeURIComponent(tag)}`,
    );
    expect(search.status).toBe(200);
    const found = (await search.json()) as UsersResponse;
    expect(found.total).toBe(3);
    expect(found.viewerRole).toBe("admin");
    const firstView = found.users.find((user) => user.id === first.userId);
    expect(firstView).toMatchObject({
      email: `${tag}-a@example.com`,
      role: "user",
      status: "active",
      passkeyCount: 1,
      authorizedAppCount: 0,
    });
    expect(firstView?.lastSessionAt).toBeTruthy();
    expect(firstView?.createdAt).toBeTruthy();

    // Name search matches too.
    const byName = await listUsers(
      admin.headers,
      `?q=${encodeURIComponent(`named-${tag}`)}`,
    );
    expect(((await byName.json()) as UsersResponse).total).toBe(1);

    // Pagination is stable and bounded.
    const pageOne = await listUsers(
      admin.headers,
      `?q=${encodeURIComponent(tag)}&page=1&perPage=2`,
    );
    const pageOneBody = (await pageOne.json()) as UsersResponse;
    expect(pageOneBody.users).toHaveLength(2);
    expect(pageOneBody.total).toBe(3);
    const pageTwo = await listUsers(
      admin.headers,
      `?q=${encodeURIComponent(tag)}&page=2&perPage=2`,
    );
    const pageTwoBody = (await pageTwo.json()) as UsersResponse;
    expect(pageTwoBody.users).toHaveLength(1);
    expect(
      new Set([
        ...pageOneBody.users.map((user) => user.id),
        ...pageTwoBody.users.map((user) => user.id),
      ]).size,
    ).toBe(3);
    expect([third.userId, second.userId, first.userId]).toContain(
      pageTwoBody.users[0]?.id,
    );

    // LIKE wildcards are escaped, not interpreted.
    const wildcard = await listUsers(admin.headers, "?q=%25");
    expect(((await wildcard.json()) as UsersResponse).total).toBe(0);

    // Invalid paging is rejected.
    expect((await listUsers(admin.headers, "?page=0")).status).toBe(400);
    expect((await listUsers(admin.headers, "?perPage=100")).status).toBe(400);

    // Directory queries leave a redacted audit trail (no search text).
    const audit = await env.PG72_ID_DB.prepare(
      `SELECT metadata_json FROM audit_event
        WHERE event_type = 'admin.users_listed' AND actor_user_id = ?
        ORDER BY occurred_at DESC LIMIT 1`,
    )
      .bind(admin.userId)
      .first<{ metadata_json: string | null }>();
    expect(audit).not.toBeNull();
    expect(audit?.metadata_json ?? "").not.toContain(tag);
    expect(audit?.metadata_json ?? "").not.toContain("@example.com");
  });

  it("applies the role assignment matrix and audits changes", async () => {
    const admin = await randomUser("admin");
    const otherAdmin = await randomUser("admin");
    const bootadmin = await createBootstrapAdmin();
    const target = await randomUser("user");

    // admin: user <-> developer is allowed.
    expect((await setRole(admin.headers, target.userId, "developer")).status).toBe(200);
    expect(await storedRole(target.userId)).toBe("developer");
    const changed = await latestAudit("user.role_changed", target.userId);
    expect(changed).toMatchObject({
      outcome: "success",
      actor_user_id: admin.userId,
    });
    expect(JSON.parse(changed?.metadata_json ?? "{}")).toMatchObject({
      from: "user",
      to: "developer",
      via: "admin",
    });

    expect((await setRole(admin.headers, target.userId, "user")).status).toBe(200);
    expect(await storedRole(target.userId)).toBe("user");

    // admin cannot promote to admin; only bootadmin can.
    const promote = await setRole(admin.headers, target.userId, "admin");
    expect(promote.status).toBe(403);
    expect(await promote.json()).toEqual({ error: "role_not_assignable" });
    expect(await storedRole(target.userId)).toBe("user");

    expect((await setRole(bootadmin.headers, target.userId, "admin")).status).toBe(200);
    expect(await storedRole(target.userId)).toBe("admin");

    // admin cannot touch another admin; bootadmin can demote them.
    const demoteByAdmin = await setRole(admin.headers, target.userId, "user");
    expect(demoteByAdmin.status).toBe(403);
    expect(await demoteByAdmin.json()).toEqual({
      error: "role_not_assignable",
    });
    expect(
      (await setRole(admin.headers, otherAdmin.userId, "developer")).status,
    ).toBe(403);
    expect(
      (await setRole(bootadmin.headers, target.userId, "developer")).status,
    ).toBe(200);

    // bootadmin is never assignable, unknown roles are rejected.
    const grantBoot = await setRole(bootadmin.headers, target.userId, "bootadmin");
    expect(grantBoot.status).toBe(400);
    expect(await grantBoot.json()).toEqual({ error: "invalid_role" });
    expect((await setRole(bootadmin.headers, target.userId, "owner")).status).toBe(400);
  });

  it("protects the bootstrap administrator from all admin actions", async () => {
    const bootstrap = await createBootstrapAdmin();
    const admin = await randomUser("admin");
    const roleBefore = await storedRole(bootstrap.userId);

    const roleChange = await setRole(
      admin.headers,
      bootstrap.userId,
      "developer",
    );
    expect(roleChange.status).toBe(403);
    expect(await roleChange.json()).toEqual({ error: "bootadmin_protected" });
    expect(await storedRole(bootstrap.userId)).toBe(roleBefore);

    const suspend = await setStatus(admin.headers, bootstrap.userId, true);
    expect(suspend.status).toBe(403);
    expect(await suspend.json()).toEqual({ error: "bootadmin_protected" });

    const revoke = await revokeSessions(admin.headers, bootstrap.userId);
    expect(revoke.status).toBe(403);

    const deletion = await deleteUser(admin.headers, bootstrap.userId);
    expect(deletion.status).toBe(403);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM user WHERE id = ?")
        .bind(bootstrap.userId)
        .first(),
    ).not.toBeNull();

    // Denied attempts are audited.
    const deniedDelete = await latestAudit("user.deleted", bootstrap.userId);
    expect(deniedDelete?.outcome).toBe("denied");
    expect(deniedDelete?.actor_user_id).toBe(admin.userId);
  });

  it("guards bootadmin rows at the database boundary", async () => {
    // Any row whose stored role is 'bootadmin' is trigger-protected,
    // independent of the configured email.
    const guarded = await createAuthenticatedUser(
      `${crypto.randomUUID()}@example.com`,
      "bootadmin",
    );

    await expect(
      env.PG72_ID_DB.prepare("DELETE FROM user WHERE id = ?")
        .bind(guarded.userId)
        .run(),
    ).rejects.toThrow("bootadmin account is protected");

    await expect(
      env.PG72_ID_DB.prepare("UPDATE user SET role = 'user' WHERE id = ?")
        .bind(guarded.userId)
        .run(),
    ).rejects.toThrow("bootadmin account is protected");

    await expect(
      env.PG72_ID_DB.prepare(
        "UPDATE user SET status = 'suspended' WHERE id = ?",
      )
        .bind(guarded.userId)
        .run(),
    ).rejects.toThrow("bootadmin account is protected");
  });

  it("rejects self-modification through the admin API", async () => {
    const admin = await randomUser("admin");

    const roleChange = await setRole(admin.headers, admin.userId, "user");
    expect(roleChange.status).toBe(409);
    expect(await roleChange.json()).toEqual({ error: "cannot_modify_self" });

    const suspend = await setStatus(admin.headers, admin.userId, true);
    expect(suspend.status).toBe(409);
    expect(await suspend.json()).toEqual({ error: "cannot_suspend_self" });

    const revoke = await revokeSessions(admin.headers, admin.userId);
    expect(revoke.status).toBe(409);

    const deletion = await deleteUser(admin.headers, admin.userId);
    expect(deletion.status).toBe(409);
    expect(
      await env.PG72_ID_DB.prepare("SELECT id FROM user WHERE id = ?")
        .bind(admin.userId)
        .first(),
    ).not.toBeNull();
  });

  it("derives bootadmin capabilities from the configured email, not the stored role", async () => {
    // The helper stores the pre-conversion legacy role for this row.
    const bootstrap = await createBootstrapAdmin();
    const target = await randomUser("user");
    expect(await storedRole(bootstrap.userId)).not.toBe("bootadmin");

    const list = await listUsers(bootstrap.headers);
    expect(list.status).toBe(200);
    expect(((await list.json()) as UsersResponse).viewerRole).toBe("bootadmin");

    expect(
      (await setRole(bootstrap.headers, target.userId, "admin")).status,
    ).toBe(200);
    expect(await storedRole(target.userId)).toBe("admin");
  });

  it("suspension revokes sessions and blocks further session use", async () => {
    const admin = await randomUser("admin");
    const target = await randomUser("user");

    const before = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/audit`, {
        headers: target.headers,
      }),
    );
    expect(before.status).toBe(200);

    const suspend = await setStatus(admin.headers, target.userId, true);
    expect(suspend.status).toBe(200);
    expect(
      (
        await env.PG72_ID_DB.prepare(
          "SELECT COUNT(*) AS count FROM session WHERE userId = ?",
        )
          .bind(target.userId)
          .first<{ count: number }>()
      )?.count,
    ).toBe(0);

    const after = await exports.default.fetch(
      new Request(`${BASE_URL}/api/account/audit`, {
        headers: target.headers,
      }),
    );
    expect(after.status).toBe(401);

    const suspended = await latestAudit("user.suspended", target.userId);
    expect(suspended).toMatchObject({
      outcome: "success",
      actor_user_id: admin.userId,
    });

    // Reactivation restores the account but not the revoked sessions.
    const reactivate = await setStatus(admin.headers, target.userId, false);
    expect(reactivate.status).toBe(200);
    const status = await env.PG72_ID_DB.prepare(
      "SELECT status FROM user WHERE id = ?",
    )
      .bind(target.userId)
      .first<{ status: string }>();
    expect(status?.status).toBe("active");
    expect(
      (
        await exports.default.fetch(
          new Request(`${BASE_URL}/api/account/audit`, {
            headers: target.headers,
          }),
        )
      ).status,
    ).toBe(401);
  });

  it("revokes every session of a user on demand", async () => {
    const admin = await randomUser("admin");
    const target = await randomUser("user");

    const response = await revokeSessions(admin.headers, target.userId);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      userId: target.userId,
      revokedSessions: 1,
    });
    expect(
      (
        await exports.default.fetch(
          new Request(`${BASE_URL}/api/account/audit`, {
            headers: target.headers,
          }),
        )
      ).status,
    ).toBe(401);
    const audit = await latestAudit("user.sessions_revoked", target.userId);
    expect(audit).toMatchObject({
      outcome: "success",
      actor_user_id: admin.userId,
    });
  });

  it("deletes a user together with sessions and passkeys", async () => {
    const admin = await randomUser("admin");
    const target = await randomUser("user");
    await createPasskey(target.userId);

    const response = await deleteUser(admin.headers, target.userId);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      deleted: true,
      userId: target.userId,
    });

    for (const [table, column] of [
      ["user", "id"],
      ["session", "userId"],
      ["passkey", "userId"],
    ] as const) {
      expect(
        await env.PG72_ID_DB.prepare(
          `SELECT 1 FROM ${table} WHERE ${column} = ? LIMIT 1`,
        )
          .bind(target.userId)
          .first(),
      ).toBeNull();
    }

    const audit = await latestAudit("user.deleted", target.userId);
    expect(audit).toMatchObject({
      outcome: "success",
      actor_user_id: admin.userId,
    });
  });

  it("creates role-carrying invitations within the assignment matrix", async () => {
    const admin = await randomUser("admin");
    const bootadmin = await createBootstrapAdmin();

    const developerInvite = `${crypto.randomUUID()}@example.com`;
    const created = await invite(admin.headers, developerInvite, "developer");
    expect(created.status).toBe(201);
    const invitation = await env.PG72_ID_DB.prepare(
      "SELECT role FROM invitation WHERE email_normalized = ?",
    )
      .bind(developerInvite)
      .first<{ role: string }>();
    expect(invitation?.role).toBe("developer");

    // Only bootadmin can hand out admin; bootadmin never.
    const adminInvite = `${crypto.randomUUID()}@example.com`;
    const deniedAdmin = await invite(admin.headers, adminInvite, "admin");
    expect(deniedAdmin.status).toBe(403);
    expect(await deniedAdmin.json()).toEqual({ error: "role_not_assignable" });
    expect((await invite(bootadmin.headers, adminInvite, "admin")).status).toBe(201);
    expect(
      (
        await invite(
          bootadmin.headers,
          `${crypto.randomUUID()}@example.com`,
          "bootadmin",
        )
      ).status,
    ).toBe(400);
  });

  it("applies an invitation to an existing account immediately", async () => {
    const admin = await randomUser("admin");
    const email = `${crypto.randomUUID()}@example.com`;
    const target = await createAuthenticatedUser(email);

    // Email lookup is normalized; no pending invitation row remains.
    const response = await invite(
      admin.headers,
      email.toUpperCase(),
      "developer",
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      applied: true,
      userId: target.userId,
      role: "developer",
    });
    expect(await storedRole(target.userId)).toBe("developer");
    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT id FROM invitation WHERE email_normalized = ?",
      )
        .bind(email)
        .first(),
    ).toBeNull();

    // The audit trail records that the role change came from an invitation.
    const audit = await latestAudit("user.role_changed", target.userId);
    expect(audit?.outcome).toBe("success");
    expect(JSON.parse(audit?.metadata_json ?? "{}")).toMatchObject({
      from: "user",
      to: "developer",
      via: "invitation",
    });

    // The assignment matrix still applies to existing accounts.
    const escalate = await invite(admin.headers, email, "admin");
    expect(escalate.status).toBe(403);
    expect(await storedRole(target.userId)).toBe("developer");

    // Inviting the bootstrap administrator cannot change their role.
    const bootstrap = await createBootstrapAdmin();
    const roleBefore = await storedRole(bootstrap.userId);
    const bootstrapEmail = env.BOOTSTRAP_ADMIN_EMAIL.trim().toLowerCase();
    const protectBoot = await invite(admin.headers, bootstrapEmail, "user");
    expect(protectBoot.status).toBe(403);
    expect(await protectBoot.json()).toEqual({ error: "bootadmin_protected" });
    expect(await storedRole(bootstrap.userId)).toBe(roleBefore);
  });
});

describe("Developer-owned OAuth clients", () => {
  function clientBody(clientId: string): Record<string, unknown> {
    return {
      clientId,
      name: "Owned Client",
      redirectUris: [`https://${clientId}.example/callback`],
    };
  }

  it("scopes developer access to owned clients", async () => {
    const developer = await randomUser("developer");
    const otherDeveloper = await randomUser("developer");
    const admin = await randomUser("admin");

    const ownedId = `owned-${crypto.randomUUID()}`;
    const createResponse = await createClient(
      developer.headers,
      clientBody(ownedId),
    );
    expect(createResponse.status).toBe(201);
    const createdRow = await env.PG72_ID_DB.prepare(
      "SELECT ownerUserId FROM oauthClient WHERE clientId = ?",
    )
      .bind(ownedId)
      .first<{ ownerUserId: string | null }>();
    expect(createdRow?.ownerUserId).toBe(developer.userId);

    const adminOwnedId = `admin-owned-${crypto.randomUUID()}`;
    expect(
      (await createClient(admin.headers, clientBody(adminOwnedId))).status,
    ).toBe(201);

    // Developers list only their own clients; admins see everything.
    const developerList = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers: developer.headers }),
    );
    const developerClients = (
      (await developerList.json()) as {
        clients: { clientId: string }[];
      }
    ).clients.map((client) => client.clientId);
    expect(developerClients).toContain(ownedId);
    expect(developerClients).not.toContain(adminOwnedId);

    const adminList = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers: admin.headers }),
    );
    const adminClients = (
      (await adminList.json()) as { clients: { clientId: string }[] }
    ).clients.map((client) => client.clientId);
    expect(adminClients).toContain(ownedId);
    expect(adminClients).toContain(adminOwnedId);

    // Foreign developers get an existence-hiding 404 on mutations.
    const foreignDisable = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${ownedId}/status`, {
        method: "POST",
        headers: otherDeveloper.headers,
        body: JSON.stringify({ disabled: true }),
      }),
    );
    expect(foreignDisable.status).toBe(404);
    const foreignRotate = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${ownedId}/rotate-secret`, {
        method: "POST",
        headers: otherDeveloper.headers,
      }),
    );
    expect(foreignRotate.status).toBe(404);
    const foreignDelete = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${ownedId}`, {
        method: "DELETE",
        headers: otherDeveloper.headers,
      }),
    );
    expect(foreignDelete.status).toBe(404);

    // The owner and admins can manage the client.
    expect(
      (
        await exports.default.fetch(
          new Request(`${CLIENTS_URL}/${ownedId}/status`, {
            method: "POST",
            headers: developer.headers,
            body: JSON.stringify({ disabled: true }),
          }),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await exports.default.fetch(
          new Request(`${CLIENTS_URL}/${ownedId}/status`, {
            method: "POST",
            headers: admin.headers,
            body: JSON.stringify({ disabled: false }),
          }),
        )
      ).status,
    ).toBe(200);
  });

  it("treats unowned clients as admin-managed", async () => {
    const developer = await randomUser("developer");
    const admin = await randomUser("admin");

    const legacyId = `legacy-${crypto.randomUUID()}`;
    expect(
      (await createClient(admin.headers, clientBody(legacyId))).status,
    ).toBe(201);
    await env.PG72_ID_DB.prepare(
      "UPDATE oauthClient SET ownerUserId = NULL WHERE clientId = ?",
    )
      .bind(legacyId)
      .run();

    const developerList = await exports.default.fetch(
      new Request(CLIENTS_URL, { headers: developer.headers }),
    );
    expect(
      (
        (await developerList.json()) as { clients: { clientId: string }[] }
      ).clients.map((client) => client.clientId),
    ).not.toContain(legacyId);
    expect(
      (
        await exports.default.fetch(
          new Request(`${CLIENTS_URL}/${legacyId}`, {
            method: "DELETE",
            headers: developer.headers,
          }),
        )
      ).status,
    ).toBe(404);

    const adminDisable = await exports.default.fetch(
      new Request(`${CLIENTS_URL}/${legacyId}/status`, {
        method: "POST",
        headers: admin.headers,
        body: JSON.stringify({ disabled: true }),
      }),
    );
    expect(adminDisable.status).toBe(200);
  });

  it("disables and orphans owned clients when the owner is deleted", async () => {
    const admin = await randomUser("admin");
    const developer = await randomUser("developer");
    const bystander = await randomUser("user");

    const clientId = `orphan-${crypto.randomUUID()}`;
    expect(
      (await createClient(developer.headers, clientBody(clientId))).status,
    ).toBe(201);

    // Another user's credentials on the owned client must die with it.
    const now = new Date();
    const later = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
    await env.PG72_ID_DB.batch([
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthAccessToken
          (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        `pg72_at_${crypto.randomUUID()}`,
        clientId,
        bystander.userId,
        later,
        now.toISOString(),
        '["openid"]',
      ),
      env.PG72_ID_DB.prepare(
        `INSERT INTO oauthRefreshToken
          (id, token, clientId, userId, expiresAt, createdAt, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        crypto.randomUUID(),
        `pg72_rt_${crypto.randomUUID()}`,
        clientId,
        bystander.userId,
        later,
        now.toISOString(),
        '["openid","offline_access"]',
      ),
    ]);

    expect((await deleteUser(admin.headers, developer.userId)).status).toBe(200);

    const client = await env.PG72_ID_DB.prepare(
      "SELECT disabled, ownerUserId FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ disabled: number; ownerUserId: string | null }>();
    expect(client).toMatchObject({ disabled: 1, ownerUserId: null });

    expect(
      await env.PG72_ID_DB.prepare(
        "SELECT 1 FROM oauthAccessToken WHERE clientId = ? LIMIT 1",
      )
        .bind(clientId)
        .first(),
    ).toBeNull();
    const refresh = await env.PG72_ID_DB.prepare(
      "SELECT revoked FROM oauthRefreshToken WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ revoked: string | null }>();
    expect(refresh?.revoked).not.toBeNull();
  });

  it("preserves and disables owned clients on self-deletion too", async () => {
    const developer = await randomUser("developer");
    const clientId = `self-orphan-${crypto.randomUUID()}`;
    expect(
      (await createClient(developer.headers, clientBody(clientId))).status,
    ).toBe(201);

    const response = await exports.default.fetch(
      new Request(`${BASE_URL}/delete-user`, {
        method: "POST",
        headers: developer.headers,
        body: "{}",
      }),
    );
    expect(response.status).toBe(200);

    const client = await env.PG72_ID_DB.prepare(
      "SELECT disabled, ownerUserId FROM oauthClient WHERE clientId = ?",
    )
      .bind(clientId)
      .first<{ disabled: number; ownerUserId: string | null }>();
    expect(client).toMatchObject({ disabled: 1, ownerUserId: null });
  });
});

describe("Role claims in issued ID tokens", () => {
  it("emits the effective role for a legacy bootstrap admin row", async () => {
    // Stored role stays a stale 'user'; the claim must still say bootadmin.
    const bootstrap = await createBootstrapAdmin();

    const clientId = `claims-${crypto.randomUUID()}`;
    const redirectUri = `https://${clientId}.example/callback`;
    const createResponse = await exports.default.fetch(
      new Request(CLIENTS_URL, {
        method: "POST",
        headers: bootstrap.headers,
        body: JSON.stringify({
          clientId,
          name: "Claims Test Client",
          redirectUris: [redirectUri],
          public: true,
        }),
      }),
    );
    expect(createResponse.status).toBe(201);

    const verifier = "claims-verifier-claims-verifier-claims-verifier";
    const challenge = await sha256Base64Url(verifier);
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid profile email",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "B".repeat(43),
      nonce: "C".repeat(43),
    });
    const authorizeResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/authorize?${query}`, {
        headers: bootstrap.headers,
        redirect: "manual",
      }),
    );
    expect(authorizeResponse.status).toBe(302);
    const consentLocation = new URL(
      authorizeResponse.headers.get("location") ?? "",
      BASE_URL,
    );
    expect(consentLocation.pathname).toBe("/consent");

    const consentHeaders = new Headers(bootstrap.headers);
    consentHeaders.set("Sec-Fetch-Mode", "cors");
    const consentResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/consent`, {
        method: "POST",
        headers: consentHeaders,
        body: JSON.stringify({
          accept: true,
          oauth_query: consentLocation.search.slice(1),
        }),
      }),
    );
    expect(consentResponse.status).toBe(200);
    const consentResult = (await consentResponse.json()) as { url?: string };
    const code = new URL(consentResult.url ?? "").searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenResponse = await exports.default.fetch(
      new Request(`${BASE_URL}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          redirect_uri: redirectUri,
          client_id: clientId,
          code_verifier: verifier,
        }),
      }),
    );
    expect(tokenResponse.status).toBe(200);
    const tokens = (await tokenResponse.json()) as { id_token?: string };
    expect(tokens.id_token).toBeTruthy();

    const payloadPart = (tokens.id_token ?? "").split(".")[1] ?? "";
    const claims = JSON.parse(
      atob(payloadPart.replaceAll("-", "+").replaceAll("_", "/")),
    ) as Record<string, unknown>;
    expect(claims["https://pg72.tw/role"]).toBe("bootadmin");
  });
});
