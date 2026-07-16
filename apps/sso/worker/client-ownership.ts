/**
 * Shutdown statements for OAuth clients owned by an account that is being
 * deleted. The clients are preserved (never cascaded away with the owner)
 * but are disabled and orphaned: access tokens are deleted, refresh tokens
 * revoked, pending authorization codes purged, and ownership cleared so the
 * client becomes unowned and therefore admin-managed. Administrators can
 * re-enable or re-assign the client afterwards.
 *
 * Must run before the user row is removed; the ownerUserId foreign key's
 * ON DELETE SET NULL would otherwise clear ownership first and make the
 * owned clients unfindable.
 */
export function ownedClientShutdownStatements(
  env: Env,
  ownerUserId: string,
  nowIso: string,
): D1PreparedStatement[] {
  const ownedClientIds =
    "SELECT clientId FROM oauthClient WHERE ownerUserId = ?";

  return [
    env.PG72_ID_DB.prepare(
      `DELETE FROM oauthAccessToken WHERE clientId IN (${ownedClientIds})`,
    ).bind(ownerUserId),
    env.PG72_ID_DB.prepare(
      `UPDATE oauthRefreshToken SET revoked = ?
        WHERE revoked IS NULL AND clientId IN (${ownedClientIds})`,
    ).bind(nowIso, ownerUserId),
    env.PG72_ID_DB.prepare(
      `DELETE FROM verification
        WHERE CASE WHEN json_valid(value) THEN
          json_extract(value, '$.type') = 'authorization_code'
          AND json_extract(value, '$.query.client_id') IN (${ownedClientIds})
        ELSE 0 END`,
    ).bind(ownerUserId),
    env.PG72_ID_DB.prepare(
      `UPDATE oauthClient
          SET disabled = 1, ownerUserId = NULL, updatedAt = ?
        WHERE ownerUserId = ?`,
    ).bind(nowIso, ownerUserId),
  ];
}
