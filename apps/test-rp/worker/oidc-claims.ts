export function requireCentralSessionId(claims: object): string {
  if (
    !("sid" in claims) ||
    typeof claims.sid !== "string" ||
    claims.sid.length === 0
  ) {
    throw new Error("Validated ID token did not contain a central session ID");
  }
  return claims.sid;
}
