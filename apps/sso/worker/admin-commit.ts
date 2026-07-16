/**
 * Immutable actor snapshot captured by the request-scoped admin gate.
 * Mutations embed this predicate in their D1 batch so permission-relevant
 * account state is still current when the write commits.
 */
export interface AdminActorCommitGuard {
  expectedEmail: string;
  expectedRole: string | null;
  sessionId: string;
  userId: string;
}

export const ADMIN_ACTOR_COMMIT_PREDICATE = `EXISTS (
  SELECT 1
    FROM user AS commit_actor
   WHERE commit_actor.id = ?
     AND commit_actor.email = ?
     AND commit_actor.role IS ?
     AND commit_actor.status = 'active'
     AND commit_actor.accessLevel = 'standard'
     AND EXISTS (
       SELECT 1
         FROM session AS commit_session
        WHERE commit_session.id = ?
          AND commit_session.userId = commit_actor.id
          AND commit_session.expiresAt > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     )
)`;

export function adminActorCommitBindings(
  guard: AdminActorCommitGuard,
): unknown[] {
  return [
    guard.userId,
    guard.expectedEmail,
    guard.expectedRole,
    guard.sessionId,
  ];
}
