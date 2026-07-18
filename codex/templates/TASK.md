---
task_id: YYYYMMDD-X-short-name
created_at: YYYY-MM-DDTHH:MM:SSZ
created_by: A
assignee: D
reviewer: C
review_task_id: pending-until-candidate-exists
state: assigned
repository: absolute-path
exact_base: full-commit-sha
branch: codex-d/task-name
worktree: /private/tmp/project-codex-d-task-name
edits_allowed: true
commit_allowed: true
push_allowed: false
deploy_allowed: false
remote_allowed: false
---

# Objective

Concrete, testable outcome.

# Owned Files

- Exact paths or module boundary.

# Forbidden Overlap

- Files/worktrees owned by another task.

# Required Reading

- Canonical sections, evidence and relevant source.

# Deliverables

- Source, tests, docs, evidence and report requirements.

# Gates

- Exact focused/full commands and expected evidence.

# Completion Criteria

- Exact commit, clean worktree, passing gates, report and residual blockers.

# Independent Review Handoff

- The named reviewer is planned, not active in this implementation worktree.
- After the candidate commit exists, A creates a separate review task with a
  distinct detached worktree and exact candidate/tree.
