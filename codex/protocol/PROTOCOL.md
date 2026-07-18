# Asynchronous Coordination Protocol

## Authority

Instruction priority is:

1. The owner's latest request.
2. Repository `codex.md`, then root `AGENTS.md` and `CLAUDE.md`.
3. This protocol and the principal's `AGENT_<ROLE>.md`.
4. The immutable task definition.
5. Mailbox messages and status files.

If a lower-priority instruction conflicts with a higher-priority one, stop that
action, preserve the worktree and notify A. Coordination files never authorize
production or remote mutations.

## Single-Writer Ownership

- A alone writes `codex/BOARD.md`, `codex/WORKTREE_REGISTRY.md`,
  `codex/DECISIONS.md` and the
  canonical repository `log/YYYY-MM-DD.md` entries for this organization.
- Each principal alone writes its own `codex/<ROLE>/STATUS.md` and files under its own
  `codex/<ROLE>/log/` and `codex/acks/<ROLE>/` directories.
- A alone creates task definitions. The assignee owns its implementation report;
  a task's named reviewer independently owns a separate role-qualified review
  report. A may explicitly name another report owner in the task.
- Mailbox messages are immutable after creation. Corrections are new messages.
- Product files have one editing owner per task. Reviewers do not edit an
  author's worktree.

Never append concurrently to a shared file. If ownership is unclear, send a
message to A before editing.

## Shared Coordination Checkout Exception

The owner explicitly requested a file-based asynchronous channel. Therefore the
following coordination-only paths may be written in the shared checkout without
creating a product worktree:

- `codex/mailboxes/<RECIPIENT>/*.md`;
- `codex/acks/<ROLE>/*.ack.md`;
- the writer's own `codex/<ROLE>/STATUS.md`;
- the writer's own `codex/<ROLE>/log/*.md`;
- immutable `codex/reports/*.md` owned by the assigned principal.

This is a narrow operational exception, not permission to edit product source,
repository specifications, root logs or Git metadata in the shared checkout.
C, D and E must not run `git add`, `git commit`, merge, reset, clean or rebase in
that checkout. A alone decides when coordination records are archived or
committed. All product/docs/test changes still use the registered task worktree.

Before A commits mutable coordination records while C/D/E are active, A sends a
`freeze` message, receives acknowledgements from every active role, and verifies
that no role is writing. A then stages explicit paths and reviews the exact diff;
never use a blanket stage while the channel is live. The initial scaffold may be
committed before C/D/E onboard. Runtime mailbox/status records should otherwise
remain uncommitted until a coordinated freeze or final archive.

## Messages

To send a message, create a new file with `apply_patch`:

```text
codex/mailboxes/<RECIPIENT>/YYYYMMDDTHHMMSSZ__FROM-<SENDER>__<topic>.md
```

Use UTC. If that name already exists, add `-02`, `-03`, and so on. Never
overwrite an existing message. Use `codex/templates/MESSAGE.md` as the body. A
correction sets `supersedes` to the prior message ID.

Valid message kinds are `ready`, `assignment`, `amendment`, `status`, `request`,
`blocker`, `decision`, `review`, `freeze` and `handoff`. A blocker that stops
safe progress must go directly to A even when another role is collaborating on
the lane.

The recipient acknowledges by creating:

```text
codex/acks/<RECIPIENT>/<MESSAGE_ID>.ack.md
```

Acknowledgement means read, not approved. Approval must be an explicit decision
message or task report.

Check the mailbox at the start of every turn, before and after a long-running
gate, before a commit, after a subagent report, and before declaring completion.
Use `codex/bin/check-mailbox.sh <ROLE>` for a read-only list of unacknowledged
messages.

The filesystem is a durable asynchronous channel, not a push notification
service. An active principal polls it at the checkpoints above. A Codex session
whose turn has ended cannot wake itself when a file appears; the owner must send
`resume` (or another message) to that session. Status and mailbox files preserve
the exact state across that wake-up.

## Tasks

A creates `codex/tasks/<TASK_ID>.md` from `codex/templates/TASK.md`. A task must pin:

- assignee and optional reviewer;
- repository, exact base commit, branch and worktree path;
- owned files and forbidden overlaps;
- scope, deliverables and required gates;
- whether edits and commits are allowed;
- explicit remote/production prohibition;
- dependencies and completion criteria.

After creating the task, A sends the assignee an immutable `assignment` mailbox
message containing the task path and SHA-256. The assignee verifies that digest,
acknowledges the message and updates status before acting. A task file without a
matching assignment message is not active.

Independent review is a separate task created only after an immutable candidate
commit or exact snapshot exists. Its task pins that candidate and a distinct
detached review worktree registered by A. A reviewer never runs tests or builds
in the author's live worktree.

The task file is immutable. A changes scope with a new task amendment message;
the assignee records the amendment ID in status and the final report. A task is
not complete merely because code exists. The required tests, clean status,
evidence and report must also exist.

## Status And Reports

Each principal replaces only its own `codex/<ROLE>/STATUS.md` using
`codex/templates/STATUS.md`. Update it after assignment, after each meaningful gate,
when blocked, before a long command, after every subagent finishes, and before
going idle.

Final or checkpoint reports are immutable files:

```text
codex/reports/<TASK_ID>__<ROLE>__YYYYMMDDTHHMMSSZ.md
```

Use `codex/templates/REPORT.md`. Report exact commit IDs, parent IDs, worktree state,
test counts, evidence paths and residual blockers. Do not write `GO` when a
required gate is red or unexecuted.

## Worktrees And Git

- All product, specification, documentation and test changes use the exact
  worktree assigned in the task. Only the coordination-only paths listed above
  use the shared-checkout exception.
- A registers the path and branch before edits start.
- Never reset, clean, amend, rebase or remove another role's worktree.
- Never reuse a dirty worktree for another task.
- Do not push. Do not deploy. Do not run remote D1/R2/Queue commands.
- Commits are single-purpose English messages with the repository-required
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer.
- Existing user changes are preserved. Unexpected changes are reported, not
  reverted.

## Subagents

Each A, C, D or E principal may run at most three subagents. A principal must:

- give every subagent a bounded, non-overlapping subtask;
- keep one editing owner for each file/worktree;
- independently inspect subagent output;
- include subagent results in its own status and report;
- stop or reassign a silent/stalled subagent without discarding its worktree.

Subagents do not send instructions directly to other principals and do not edit
the organization board, registry, decisions or another role's status.

## Logs, Evidence And Secrets

C, D and E write bounded entries only to their role log. A consolidates the
material facts into `log/YYYY-MM-DD.md`, preventing concurrent append races.
Evidence containing local paths or diagnostics must use mode `0600` when the
existing runbooks require it. Coordination files contain secret names only,
never values, tokens, codes, cookies, personal data, D1 dumps or credentials.

All production, Preview and public-readiness claims remain subject to the
canonical gates. A local test or synthetic proof is not deployment evidence.
