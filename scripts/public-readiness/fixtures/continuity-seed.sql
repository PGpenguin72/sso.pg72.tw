-- Synthetic-only continuity fixture. The runner replaces every named marker
-- with an ephemeral SQL literal in a mode-0600 temporary copy. This tracked
-- template contains no session token, client secret, credential private key,
-- signing private key, or real identity data.

INSERT INTO "user" (
  "id", "name", "email", "emailVerified", "image", "createdAt",
  "updatedAt", "role", "status", "googleImage", "termsAcceptedVersion",
  "privacyAcceptedVersion", "legalAcceptedAt", "accessLevel"
) VALUES (
  '10000000-0000-4000-8000-000000000001',
  'Continuity Fixture',
  'continuity-user@example.invalid',
  1,
  NULL,
  datetime('now'),
  datetime('now'),
  'user',
  'active',
  NULL,
  NULL,
  NULL,
  NULL,
  'standard'
);

INSERT INTO "account" (
  "id", "accountId", "providerId", "userId", "createdAt", "updatedAt"
) VALUES (
  '11000000-0000-4000-8000-000000000001',
  'continuity-provider-subject',
  'google',
  '10000000-0000-4000-8000-000000000001',
  datetime('now'),
  datetime('now')
);

INSERT INTO "session" (
  "id", "expiresAt", "token", "createdAt", "updatedAt", "ipAddress",
  "userAgent", "userId", "passkeyStepUpAt"
) VALUES
  (
    '30000000-0000-4000-8000-000000000001',
    datetime('now', '+1 hour'),
    {{LIVE_SESSION_TOKEN}},
    datetime('now'),
    datetime('now'),
    NULL,
    NULL,
    '10000000-0000-4000-8000-000000000001',
    NULL
  ),
  (
    '30000000-0000-4000-8000-000000000002',
    datetime('now', '-1 hour'),
    {{EXPIRED_SESSION_TOKEN}},
    datetime('now', '-2 hours'),
    datetime('now', '-2 hours'),
    NULL,
    NULL,
    '10000000-0000-4000-8000-000000000001',
    NULL
  );

INSERT INTO "passkey" (
  "id", "name", "publicKey", "userId", "credentialID", "counter",
  "deviceType", "backedUp", "transports", "createdAt", "aaguid"
) VALUES (
  '20000000-0000-4000-8000-000000000001',
  'Continuity authenticator',
  {{PASSKEY_PUBLIC_KEY}},
  '10000000-0000-4000-8000-000000000001',
  {{PASSKEY_CREDENTIAL_ID}},
  0,
  'singleDevice',
  0,
  'internal',
  datetime('now'),
  NULL
);

INSERT INTO "oauthClient" (
  "id", "clientId", "clientSecret", "disabled", "skipConsent",
  "enableEndSession", "subjectType", "scopes", "userId", "createdAt",
  "updatedAt", "name", "redirectUris", "postLogoutRedirectUris",
  "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "public",
  "type", "requirePKCE", "metadata", "ownerUserId",
  "backchannelLogoutUri"
) VALUES (
  '50000000-0000-4000-8000-000000000001',
  'continuity-rp',
  {{CLIENT_SECRET_HASH}},
  0,
  0,
  1,
  'public',
  '["openid","profile","email","offline_access"]',
  NULL,
  datetime('now'),
  datetime('now'),
  'Continuity RP',
  '["http://127.0.0.1:5184/callback"]',
  '["http://127.0.0.1:5184/signed-out"]',
  'client_secret_post',
  '["authorization_code","refresh_token"]',
  '["code"]',
  0,
  'web',
  1,
  '{"developer_name":"Continuity Fixture","backchannel_logout_uri":"http://127.0.0.1:5184/backchannel-logout"}',
  '10000000-0000-4000-8000-000000000001',
  'http://127.0.0.1:5184/backchannel-logout'
);

INSERT INTO "oauthConsent" (
  "id", "clientId", "userId", "referenceId", "scopes", "createdAt",
  "updatedAt"
) VALUES (
  '40000000-0000-4000-8000-000000000001',
  'continuity-rp',
  '10000000-0000-4000-8000-000000000001',
  NULL,
  '["openid","profile"]',
  datetime('now'),
  datetime('now')
);

INSERT INTO "rp_session_client" (
  "session_id", "client_id", "first_seen_at", "last_seen_at"
) VALUES (
  '30000000-0000-4000-8000-000000000001',
  'continuity-rp',
  datetime('now'),
  datetime('now')
);

INSERT INTO "jwks" (
  "id", "publicKey", "privateKey", "createdAt", "expiresAt"
) VALUES
  (
    'continuity-signing-key-a',
    {{JWK_A_PUBLIC}},
    {{JWK_A_PRIVATE_ENCRYPTED}},
    {{JWK_A_CREATED_AT}},
    {{JWK_A_EXPIRES_AT}}
  ),
  (
    'continuity-signing-key-b',
    {{JWK_B_PUBLIC}},
    {{JWK_B_PRIVATE_ENCRYPTED}},
    {{JWK_B_CREATED_AT}},
    {{JWK_B_EXPIRES_AT}}
  );
