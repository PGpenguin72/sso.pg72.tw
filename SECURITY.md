# Security Policy

Existing deployment records describe PGID as an invite-only production beta and
show Copy and Link using PGID for production sign-in. They are historical
evidence, not a live-state assertion; an authorized operator must reverify the
current deployment and registration mode.

That recorded state is not the same as full Production GO or general-public approval. Local source now includes the central ID-token `sid`, visited-client ledger, replay-safe durable back-channel logout delivery, an idempotent test RP receiver, and a default-disabled recovery-code path. Final independent source review of this release candidate, Preview and production rollout, external alerting, recovery/rotation drills, and the other gates below are still incomplete; no document may treat local tests or historical production traffic alone as proof that those controls passed.

The repository's ordered local migration ledger runs from `0001` through head
`0024`. It includes the narrowly scoped Mail Path A introspection prerequisite,
Passkey step-up for every OAuth client mutation, public-registration
prerequisites using Turnstile, versioned legal acceptance and persistent
restricted-account access, the global-logout source contract, recovery migration
`0019`, observability migration `0020`, archive ledger migration `0021`,
evaluator proof migration `0022`, archive evidence migration `0023`, and the
forward evidence guard in `0024`. The guard preserves existing immutable legacy
receipts while rejecting new terminal R2-version evidence that lacks an observed
byte count. The observability source includes pure alert rule/evaluator/parser
modules; evaluator runtime and lifecycle-state repositories; bounded source
slices for ten `audit_event` rules, the OAuth client-report rule, the global
fan-out-gap rule, the logout-delivery health rule, the global runtime-health
rule, and the four approximate Queue-DLQ dimensions; the additive
run/source/decision proof ledger and compatible run/state proof APIs; an unwired
nine-source evaluator orchestration; plus the pure audit-archive record/envelope
crypto contract, an unwired request-scoped archive D1 repository, a pure unwired
create-only R2 writer, and a pure non-HTTP one-object restore verifier over
injected dependencies.

The runtime repository owns initialization, immutable first-success bootstrap, and exact health projection. After `0022`, the compatible run repository owns evaluator lease acquisition/renewal, source/decision manifests, and terminal success/failure through exact run/runtime fencing. The state repository reconstructs the lifecycle snapshot and can atomically persist an already-pure decision, incident state, immutable Email outbox snapshot, canonical payload digest, and optional same-batch applied/no-state decision proof. The bounded source repositories expose only their reviewed redacted projections; through `0024`, the archive repository owns fingerprint-only sentinel continuity, bounded source selection, canonical batch persistence, exact dispatch-generation leases, lease-bound claimed-envelope reads, bounded runtime-work projections, error-specific terminal receipts, and audited dead replay. The writer owns the fixed 30/120/480/900-second retry timing and supplies `nextAttemptAt`; the repository validates and persists it. On attempt five, only transient-error or lease-expiry exhaustion becomes `dead`; integrity failures, object conflicts, and readback mismatches remain `corrupt`. Startup accepts an exact still-live current lease. If the persisted lease has changed, including after an ambiguous renewal result, recovery may adopt only a live strict descendant under the exact same fence.

None of these repositories, evaluator orchestration, archive writer, or restore
verifier is imported, invoked, or awaited by the Worker entry point's existing
scheduled handler. That handler schedules logout delivery dispatch only. The
fan-out source does not add durable general security-event delivery, a replayer,
or Queue wiring; the logout source does not change delivery, replay, Queue, or
Cron guarantees; the runtime-health source does not schedule evaluation or
claim/deliver outbox work; the Queue metrics source adds no binding or sampling
loop; and the archive modules add no archive binding, Queue, KEK adapter, Cron,
or runtime wiring. The pure restore verifier validates the externally supplied
exact manifest, object identity, metadata, size, stored/computed digests, and
returns detached records. Authenticated independently retained manifest
provenance, archive-domain fingerprint derivation and KEK custody, runtime R2
binding/integration, a restore sink/exercise, external backup/retention, and
remote proof remain absent. Observability must therefore remain
`source_present_unverified`, while `encrypted_r2_archive` remains
`dependency_missing`; local transaction, orchestration, writer, or verifier
proofs do not make either dependency operational or verified. Only
module/writer-owned temporary copies are cleared; caller-, provider-, and
R2-owned buffers are never mutated.

The local `0020` source also adds sparse single-column indexes over only non-canonical `audit_event.occurred_at`, `oauth_client_report.created_at`, `logout_delivery.created_at`, and non-null `logout_delivery_attempt.completed_at` rows, then prevents future non-canonical inserts or timestamp updates. Audit, OAuth-report, fan-out, and logout repositories probe the appropriate sparse indexes with covering `EXISTS ... LIMIT 1` statements at the start of the same D1 batch as their lexical windows. Any legacy corruption fails closed with a fixed repository error; healthy empty indexes permit the bounded window reads. `0021` independently validates each parent audit timestamp by primary key before capture or backfill can allocate a sequence. These are local migration/source contracts, not evidence that production has applied them or that observability is operational.

The last recorded production state was through migration `0012` and did not
include migrations `0013` through `0024` or this Worker version. The same record
showed no `pgid-mail-introspect` provisioning, public-registration or
logout/alert/archive Queue bindings, mail VPS cutover, or production RP receiver
cutover, and recorded `RECOVERY_MODE` as disabled. This historical state must be
reverified before any maintenance operation; local results must not be
represented as current production behavior.

The repository also retains historical fail-closed synthetic continuity and
bounded-load tooling. Its source contract required an exact clean Git commit,
fresh local D1 state, complete ordered migration-ledger comparison, literal
loopback Workers, ephemeral Web Crypto fixtures, a fixed bounded profile,
redacted mode-`0600` reports, and no Cloudflare credentials. This is source
inventory only: the tooling and its runbooks are owner-only deferred material,
and no agent may invoke, request, delegate, schedule, or prompt their execution.
No historical local result is current Preview, restore, rotation, Queue/DLQ/R2,
external-alert, or production evidence.

## Reporting

Do not open a public issue containing secrets, tokens, personal data, or an
exploit against a live PG72 service. Email
[`contact@pg72.tw`](mailto:contact@pg72.tw?subject=PGID%20security%20report) with:

- affected endpoint and environment;
- minimal reproduction steps;
- expected and observed behavior;
- impact assessment;
- logs with credentials and personal data removed.

## Testing Authorization

The owner currently prohibits every agent and subagent from running, requesting,
delegating, scheduling, or prompting for any security test or security scanner in
any environment. This includes SAST, DAST, active or adversarial scans, fuzzing,
attack simulation, penetration-testing prompts, credential guessing, load or
stress testing, rate exhaustion, fault injection, and live security probes.
Only ordinary type, lint, unit, integration, and build checks plus minimal
non-adversarial deployment health checks are authorized. Existing source tools,
workflows, and the deferred gates below cannot reauthorize themselves or be
represented as passed while this prohibition remains active.

## Invite Beta Release Gate

The following are release criteria, not evidence that any candidate or current
production deployment has passed them. Each release requires contemporaneous,
candidate-specific evidence.

An invite-beta release requires:

- strict TypeScript, ordinary workerd unit/integration tests, and production builds appropriate to the change;
- security scans and adversarial protocol checks remain deferred pending new explicit owner authorization;
- an explicit rollback path and post-release smoke checks.

Passing this narrower gate permits an invite-beta release only. It does not authorize public registration or a full Production GO claim.

## Automated Source Assurance (Owner-Only Deferred)

This section records historical repository capabilities, not executable agent
instructions. While `Testing Authorization` remains in force, no agent may
invoke the security-tool bootstrap, composite source-assurance, local DAST, or
Preview DAST entry points; trigger their workflows through push, pull request,
manual dispatch, or delegation; or represent their historical output as current
evidence. Exact shell commands are intentionally omitted. A future owner who
explicitly reauthorizes this work can recover implementation details from the
tracked manifests and history.

The historical composite source-assurance entry point combined type-aware Worker Promise analysis, required
checksum-pinned Gitleaks full-history scanning, an explicit bounded/redacted
tracked/untracked/ignored-sensitive-path scan plus captured Secretlint,
actionlint and recursive workflow/package-script allowlists with exact scoped
environment key/value and expression contracts, exact source and generated
Wrangler binding/resource contracts, dependency-advisory
reconciliation, a production Worker dry-run artifact scan, and a
dependency/license inventory. The artifact gate uses the same redacted secret
families for bounded UTF-8, UTF-16LE/BE, and NUL-interleaved strings and rejects
source maps, private machine paths, unexpected files, binding/config drift, and
size regressions. CI keeps only the redacted inventories for seven days.
JavaScript/TypeScript keys and values come from the pinned compiler AST and a
bounded static evaluator; the separate line/dotenv parser handles export and
declaration forms. Source fixture and reviewed generated enum/metadata
allowances are exact path/key/value contracts. The generated Better Auth
fallback must retain its three exact digests, literal forms, occurrence counts,
and AST contexts. Both workflows run a dependency-free Node standard-library
identity check immediately after checkout, before Preview authorization,
package installation, or any other repository script. It pins exact workflow
raw bytes/file set, all manifest and complete script-map identities, and the
pnpm workspace lifecycle/build policy. It also pins the frozen lockfile and
exact `patches/` file set/digests, and rejects workspace pnpm hooks or project
`.npmrc` files before pnpm starts. Every code-owned package root must also lack
`binding.gyp` and pre-existing `node_modules`, preventing implicit native builds
and dependency-tree lifecycle hooks. The later validator independently pins
every complete workspace `scripts` object and the reachable graph while
expanding implicit `pre*`/`post*` and
`preinstall`/`install`/`postinstall`/`prepare` execution. Policy cannot extend
these contracts. The release upload is exactly `.artifacts/release` with fixed
missing-file, hidden-file, and retention behavior. Workflow environment
keys/values are restricted by a code-owned allowlist; all
`CLOUDFLARE_*`, legacy `CF_*`, and `WRANGLER_*` keys are independently denied.
The production Wrangler `index.js` must match its code-owned whole-file SHA-256
before file, secret-family, and AST checks run. Before building, the artifact
gate requires every code-owned package's `node_modules` to be a local directory
and every installed dependency symlink to resolve inside the same checkout.
This prevents Rolldown's retained module-provenance comments and derived chunk
hashes from depending on another worktree's module realpath. The identity still
covers raw, unminified deployed bytes; no runtime section, provenance comment,
or source-map reference is normalized or omitted, and source maps remain
forbidden. A runtime, dependency, bundler, or build-chain change requires human
review and two byte-identical clean build/dry-run results before deliberately
updating that digest; no policy or generated artifact can update it
automatically. The current local candidate was measured byte-identically across
two different local checkout paths, each with its own frozen install, for the
entry and every emitted Worker chunk. This topology fix does not update the
code-owned digest while later runtime inputs remain unfinished; the final
candidate still requires a separate freeze and owner review. Linux equality has
not yet been measured; it is neither claimed nor disproven.
Unsafe diagnostic paths are normalized and represented only by a short SHA-256
identifier.

The historical local DAST entry point was limited to ephemeral loopback Workers
with synthetic values and fresh local D1 state. Its credential-free probes covered health/readiness,
discovery, JWKS public-key shape, OIDC error surfaces, resource-indicator
rejection, dynamic-registration denial, logout/admin unauthenticated behavior,
security/cache headers, and a cross-Origin mutation denial. This baseline does
not cover real login, consent, authenticated admin/gateway/logout behavior,
abuse/load testing, or an independent review, and it remains owner-only deferred.

Historical CI artifacts contained source-assurance inventories, not DAST
evidence. No new DAST evidence may be produced by an agent under the current
authorization boundary.

The retained isolated-Preview workflow was designed as an owner-only manual
workflow with exact-origin, actor, branch, and protected-environment guards. Its
approved origin remains unset, it has not produced Preview evidence for this
candidate, and agents must not configure, dispatch, request, or delegate it.
Its runbook is historical owner-only deferred material under the current policy.

## Full Production GO and Public Registration Gate

Before enabling `REGISTRATION_MODE=public` or declaring full Production GO, complete and record:

- independent security review, OIDC security testing, authenticated DAST, SAST,
  dependency, secret, workflow/IaC/config and security artifact scanning remain
  deferred blockers and are not executable agent assignments without new explicit
  owner authorization;
- the locally implemented central visited-client ledger and replay-safe
  back-channel logout still require owner-directed rollout after migration
  `0018`; all security review, failure exercise, and adversarial verification
  associated with Queue/DLQ, alerting, and production RPs remain owner-only
  deferred;
- migration `0019` and the default-disabled recovery path remain rollout
  backlog; lost-device, concurrency, rollback, revocation, logout-delivery,
  signing-key rotation, D1 restore, and Queue retry/DLQ drills are owner-only
  deferred and must not be run, requested, delegated, or prompted by an agent;
- independently review the integrated local recovery and release-automation source/proofs, finalize the Worker artifact identity only after all runtime inputs are frozen, and complete and independently review the observability repository/Cron/delivery proof plus the `0021`/`0023`/`0024` encrypted R2 writer/checkpoint/restore and external-backup path; the local `0020` schema, `0022` transaction-proof foundation, pure evaluator/parser, unwired evaluator/source/archive repositories and nine-source orchestration, archive crypto contract, pure unwired writer and verifier, `0021` ledger, and `0023`/`0024` evidence contracts do not complete this gate; only then may a clean synthetic run be recorded without treating it as remote evidence;
- deploy and configure the locally implemented Turnstile, versioned Terms/Privacy
  acceptance, and restricted-account paths after migrations `0016` and `0017`;
  exact live policy approval belongs to the owner, while security review,
  threshold testing, and external-alert testing remain owner-only deferred;
- deploy the locally implemented Passkey step-up for high-risk system-client
  provisioning and secret rotation after migration `0014`; its independent
  security review remains owner-only deferred, and session-age freshness remains
  an additional product condition rather than a substitute;
- no unresolved Critical or High finding; every accepted Medium still needs an owner, deadline, and compensating control.

The canonical checklist is [`codex.md`](./codex.md) §9.2. The committed
production-target configuration remains `invite`; that is not proof of the live
mode. A switch requires the gate, explicit owner approval, deployment, and live
verification.

The verified-email enrollment boundary applies to every new account. Telegram Login Widget payloads contain no email, so an unmatched Telegram identity is rate-limited, audited without its Telegram ID or other PII, and rejected in both `invite` and `public` modes. Telegram may authenticate only an active account to which that provider identity was explicitly linked from a standard authenticated PGID session; an existing link remains an ordinary login method after later restriction. No placeholder-email account is created. D1 enforces one owner for every `(providerId, accountId)` pair, and Telegram linking uses the constraint result rather than a race-prone read-then-insert decision.

The local public-registration path fails closed unless the browser explicitly accepts the configured current policy versions and completes Turnstile. The Worker validates the Turnstile response server-side for the exact issuer hostname and fixed registration action, returns a random short-lived one-time intent once, and stores only its SHA-256 digest. Registration exchanges the raw intent for an independent reference whose digest is bound to Better Auth's actual OAuth state digest; the callback consumes that pair atomically before Google verified-email account creation. Optional social providers cannot create public users. Only the public site key and policy version identifiers are exposed as configuration; the Turnstile secret belongs in Wrangler secrets or Secrets Store. Migration `0016` stores the server-side acceptance time and guards the version history against direct UPDATE/DELETE while its account exists; deleting the parent account removes its account-scoped history under the published privacy policy. The last recorded production state did not include these controls; an authorized operator must reverify the current remote state.

## Local Restricted Account Boundary

Migration `0017` adds an independent `user.accessLevel` with `standard` and `restricted` values. Existing rows backfill to `standard`; invited and bootstrap registrations remain standard, while an uninvited public registration is persisted as restricted. `user.status` remains the lifecycle control: a restricted active user may sign in, manage ordinary account state and Passkeys, consent, and complete ordinary OIDC, whereas suspension blocks session creation.

- Restricted accounts have effective PGID platform role `user`. D1 rejects elevated stored roles, optional provider-account inserts after the initial verified Google identity, and new/updated OAuth client ownership assignments targeting inactive/restricted users. Restriction does not implicitly disable an already owned RP; client containment remains a separate administrator decision.
- Request-scoped guards re-read D1 before provider linking and every admin/developer/client-management permission check. Management/developer writes and their success audit then commit only while the same D1 actor session remains live and the account snapshot is still active, standard, and role-consistent; a changed snapshot writes neither. Existing linked providers remain valid ordinary login methods.
- Restricting an account demotes it to `user` and revokes its central sessions, access tokens, and refresh tokens. Promotion changes only access level; it does not reactivate a suspended user or restore a previous elevated role. Role assignment remains a separate hierarchy-checked operation.
- Restrict/promote and suspend/reactivate state transitions use guarded D1 batches so the state mutation and success audit either both match the same user snapshot or neither is written. Restricted-action denials expose only a user UUID and fixed surface enum in audit metadata.
- [`docs/runbooks/public-registration-abuse.md`](./docs/runbooks/public-registration-abuse.md) defines the current manual, redacted D1 evidence, initial thresholds, triage, containment, false-positive handling, and configuration rollback. It is not an external monitoring system; Preview threshold validation, operator assignment, aggregation, and alert delivery remain public-launch gates.

The last recorded production state was invite-only and did not include `0017` or
this Worker version. No retained Preview/production exercise evidence establishes
these controls, and an authorized operator must reverify the current remote
state.

## Local Recovery Boundary

Migration `0019` and the current local Worker source add a recovery path that is
disabled by default. The last recorded production state did not include this
Worker path; current remote state must be reverified. `RECOVERY_MODE=disabled`
returns 404 from both account-management and lost-device recovery endpoints;
applying the migration alone does not enable the feature. Existing users receive
no recovery-code rows automatically.

- An active user must first create codes from a normal session less than ten minutes old after completing Passkey step-up on that exact session. There is no administrator or `bootadmin` bypass. Each generation contains ten 160-bit `PGID-R1` codes; D1 stores only globally unique SHA-256 digests, and raw codes are returned once under `Cache-Control: no-store`.
- Recovery entry is independently rate-limited before parsing or lookup. Malformed, unknown, consumed, revoked, expired, suspended, and concurrent-loser inputs return the same generic denial. A successfully accepted code is consumed permanently even if the user cancels or the later Passkey ceremony fails.
- The recovery cookie is host-only, `Secure`, `HttpOnly`, `SameSite=Strict`, and restricted to `/api/recovery`. Only its hash is stored. The ten-minute recovery principal is separate from a Better Auth session and cannot access account, admin, consent, OIDC, token, or ordinary Passkey-management surfaces.
- Replacement Passkey registration uses a two-minute one-time challenge, exact configured origin and RP ID, required user verification, bounded input, no attestation, and a globally unique credential ID. It does not disclose email or provider identities.
- Successful completion atomically creates the replacement Passkey and audit event, revokes the old code set, creates a new generation, revokes all central sessions and access/refresh tokens, clears relevant verification state, and creates durable logout work for visited RPs. Any core D1 failure rolls back the batch. Queue fan-out happens only after commit and cannot resurrect sessions or codes.
- Removing the final linked social provider requires both another sign-in method and at least one active unused recovery code while recovery is enabled. The committing DELETE repeats the code and login-method predicates so a concurrent recovery-code consume cannot bypass the policy.
- Audit, Queue, logs, and operator views must never contain raw recovery codes, recovery cookies, Passkey challenges, credential IDs, full email, or full IP. Recovery codes are not daily login credentials, cannot be reconstructed from backups, and must not become an email-based account-merging or support override path.

The local workerd suite covers hash-only storage, one-view rotation, revoke/cascade, freshness and step-up races, restricted/suspended state, concurrent consumption, cookie scope, cancellation, limiter failure, exact origin, required UV, challenge replay, completion rollback, Queue failure, normal Passkey re-login, and logout outbox creation. This evidence is local only. Before owner-approved enablement, complete the migration, isolated Preview, independent review, lost-device, concurrency, rollback, and multi-RP logout acceptance in [`docs/runbooks/account-recovery.md`](./docs/runbooks/account-recovery.md). The last production record showed migrations only through `0012` and `RECOVERY_MODE` disabled; reverify rather than treating it as current state.

## Local Mail Introspection Boundary

The only delegated introspection relationship is the fixed confidential client `pgid-mail-introspect` inspecting opaque access tokens issued to `pg72-webmail`. Authorization requires a live central session, the `email` scope, and an active user with a verified email. JWTs, refresh tokens, every other client pair, and tokens missing any required state must be reported as RFC 7662 inactive.

- Unknown, expired, revoked, disabled-target, missing-`kid`, and token-controlled JOSE failures return HTTP 200 `{"active":false}`. `token_type_hint` is only a lookup hint and cannot suppress fallback to the other supported token type. JWKS corruption, duplicate matching keys, fetch failures, and other infrastructure faults remain server errors instead of being hidden as inactive tokens.
- A successful mail response exposes only the minimal allowlist required by Dovecot. It omits `sub` and `sid`; the verified email is solely a legacy mailbox lookup value, never a PGID/RP primary key, general authorization input, or account-linking key.
- Introspection uses an IP limiter at 1200 requests per 60 seconds in namespace `1004`, plus a client-class/IP limiter at 600 requests per 60 seconds in namespace `1005`. Binding failure fails closed with 503. Cloudflare's binding is per-location and permissive/eventually consistent, so these thresholds mitigate abuse but are not an exact global security counter and do not replace client authentication or D1 revocation state.
- The service secret is returned once and stored only as a hash. On suspected compromise, disable `pgid-mail-introspect` first, rotate it, and update the managed secret store and Dovecot configuration. A disabled client cannot pass a real introspection smoke test, so re-enable it in a maintenance window, run the smoke check immediately, and re-disable and roll back if it fails. Never place the secret in source, plaintext D1, logs, documents, issues, or chat.
- Provisioning, rotation, status changes, and deletion require `clients.manage_all` for system-reserved clients, a session less than 10 minutes old, and a recent Passkey step-up timestamp on that exact D1 session. The local ceremony uses a one-time session/user-bound challenge, exact origin/RP ID, required user verification, and guarded credential counters. The last production record did not include `0014` or this code; current remote state must be reverified, and independent review, deployment, and production smoke remain rollout blockers.
- Client state mutations and their audit insert commit together in D1 before a response. The D1 `audit_event` row is the source of truth; Queue delivery is post-commit, best-effort event fan-out and must not make a committed mutation appear rolled back when delivery fails. There is no durable outbox or replayer yet, so a Queue failure before acceptance can lose fan-out while the authoritative D1 audit row remains; closing that gap stays on the Production GO gate.

This behavior is pinned by the exact-version patch `patches/@better-auth__oauth-provider@1.6.23.patch`. It keeps same-client introspection as the default and adds only an opt-in opaque-access-token authorization hook, RFC 7662 inactive handling, hint fallback, and JOSE/`kid` classification. Do not carry the patch mechanically to another provider version or use `allowUnusedPatches` to hide a mismatch. Remove it only after an audited pinned stable provider supplies equivalent behavior, a clean frozen install succeeds without the patch, and the full introspection/protocol regression suite passes.

## Wiki Build-Tool Compatibility Exception

The Wiki exact-pins `vitepress@1.6.4`. That release declares
`vite@^5.4.14`, whose entire allowed range is affected by High
`GHSA-fx2h-pf6j-xcff` / `CVE-2026-53571`. The workspace therefore applies the
single dependency-scoped override `vitepress@1.6.4>vite=6.4.3`, the first
patched Vite 6 release. This does not override the SSO application's exact
Vite 8 dependency and does not add Vite as a direct Wiki dependency.

- Exposure: the advisory requires a network-exposed Vite development server
  and Windows/NTFS path behavior. Production deploys only validated static
  VitePress output; the build validator rejects Pages Functions, `_worker.js`,
  `_routes.json`, and source maps. Local `pnpm dev:wiki` remains loopback-only
  unless an operator explicitly changes the host.
- Compatibility control: Vite 6.4.3 is outside VitePress 1.6.4's declared
  range. Ordinary frozen install and Wiki parser/build/link/asset/header checks
  remain permitted; browser crawl and dependency-security audit are owner-only
  deferred while `Testing Authorization` is active. An audit ignore is not
  allowed, and the deferred security gate must not be represented as passed.
- Exit condition: remove this override when an audited stable VitePress release
  used by PGID officially supports a Vite version patched for this advisory;
  exact-pin that release and rerun the same compatibility and browser gates.

## Accepted Phase 0 Finding

`GHSA-p2fr-6hmx-4528` affects `@better-auth/oauth-provider@1.6.23`. The stable `1.6.x` line has no patched release; the current fix is pre-release only.

The canonical machine-readable acceptance is
[`security/accepted-advisories.json`](./security/accepted-advisories.json).
Historical CI policy required a live dependency-audit result to match every
recorded advisory field and installed version exactly; stale, changed, expired,
or unrecorded findings failed. That audit and its CI trigger are now owner-only
deferred and may not be invoked or delegated by an agent. The maximum waiver
duration remains 180 days, and High/Critical findings are never accepted by this
mechanism.

- Severity: Moderate.
- Owner: PGID maintainer.
- Target date: 2026-10-16, or before full Production GO or adoption of the first
  audited stable fixed release, whichever comes first. The owner must review
  the accepted risk at that boundary even if no stable fix is available.
- Exposure: resource indicators could otherwise select an audience not bound to the original grant.
- Controls: exactly one `validAudiences` entry; the Worker rejects every `resource` parameter at `/oauth2/authorize` and `/oauth2/token`; v1 resource servers must require an exact single audience and must not use RFC 8707 resource indicators as an authorization boundary.
- Exit condition: upgrade core and all Better Auth plugins together to the first audited stable release containing the fix, run its schema migration, remove the temporary edge rejection only after protocol regression tests pass.

The accepted finding blocks general-purpose resource indicators. It does not permit ignoring future High or Critical advisories.
