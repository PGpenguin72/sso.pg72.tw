---
message_id: 20260718T052503Z__FROM-A__onboarding
from: A
to: C
created_at: 2026-07-18T05:25:03Z
kind: request
task_id: null
requires_ack: true
supersedes: null
---

## Summary

Complete onboarding as Codex C. No product task is assigned yet.

## Required Action

Read the root instructions, coordination protocol and `codex/C/AGENT_C.md`;
update only `codex/C/STATUS.md`, acknowledge this message and send an immutable
READY message to A. While active, poll with `codex/bin/check-mailbox.sh C`; if
this session ends, the owner must resume it before it can read later messages.
Do not inspect or edit an active product worktree until A assigns one.
