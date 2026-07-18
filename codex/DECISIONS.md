# Coordination Decisions

Owner: A only. Entries are append-only.

## 2026-07-18 - Four-principal organization

- A directly coordinates C, D and E; there is no B role.
- C defaults to independent security/correctness review.
- D defaults to scoped implementation.
- E defaults to verification, release evidence and documentation.
- Default roles do not override an explicit immutable task.
- Communication uses immutable mailbox/task/report files and single-writer
  status/log files.
