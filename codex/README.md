# Codex Coordination

This directory coordinates four independent Codex principals working in the
same repository:

| Role | Responsibility | Reports to |
| --- | --- | --- |
| A | Technical lead, task owner, integration and final decisions | Owner |
| C | Independent security and correctness review | A |
| D | Scoped implementation | A |
| E | Verification, release evidence and documentation | A |

There is intentionally no B role. A directly coordinates C, D and E. Each
principal may use at most three subagents inside its assigned lane, but the
principal remains accountable for their work and sends one consolidated report.

## Start Here

Every Codex principal must do the following before taking action:

1. Read the repository root `AGENTS.md`, `CLAUDE.md`, `codex.md` and `handoff.md`.
2. Read `codex/protocol/PROTOCOL.md` completely.
3. Read its role file, for example `codex/C/AGENT_C.md`.
4. Update only its own `codex/<ROLE>/STATUS.md`.
5. Send a `READY` message to `codex/mailboxes/A/` using the message protocol.
6. Wait for an immutable task file from A. Do not infer an assignment from the
   board or from another role's status.

The repository specifications and security boundaries remain authoritative.
This coordination layer does not grant permission to push, deploy, access
production, use remote D1/R2/Queue resources, expose secrets or bypass a gate.

## Shared Surfaces

- `codex/BOARD.md`: current roll-up, written only by A.
- `codex/WORKTREE_REGISTRY.md`: branch/worktree ownership, written only by A.
- `codex/DECISIONS.md`: final cross-lane decisions, appended only by A.
- `codex/tasks/`: immutable task definitions created by A.
- `codex/mailboxes/<ROLE>/`: immutable messages addressed to that role.
- `codex/acks/<ROLE>/`: acknowledgements written only by that role.
- `codex/reports/`: immutable task reports written by the assigned principal.
- `codex/<ROLE>/STATUS.md`: current status written only by that role.
- `codex/<ROLE>/log/`: append-only role log written only by that role. A consolidates
  material entries into the repository daily log.

## Owner Prompt

When starting another Codex, the owner only needs to say:

```text
You are Codex C. Work in /Users/pgpenguin72/sso.pg72.tw. Read the root
AGENTS.md, then codex/README.md, codex/protocol/PROTOCOL.md and
codex/C/AGENT_C.md. Follow the file mailbox protocol and report to A.
```

Replace `C` with `D` or `E` for the other principals.
