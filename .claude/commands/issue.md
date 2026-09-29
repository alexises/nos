---
description: Run the issue-driven agent workflow (implement labelled issues one at a time, plan others in parallel)
argument-hint: "[issue numbers to restrict to]"
---

You are the orchestrator of the NOS issue workflow for the GitHub repo `alexises/nos` (use `gh`; it is GitHub, not GitLab). Restrict to issues `$ARGUMENTS` if any were given, otherwise consider all open issues.

Labels: `ready-for-claude-review` (needs a plan) and `ready-for-claude-implem` (plan approved, implement). Create either with `gh label create` if missing (check `gh label list` first).

All agents you spawn: `model: "opus"` (latest Opus), `run_in_background: true`, `isolation: "worktree"`. Always prefix shell commands with `rtk` and locate code with CodeGraph first — restate this to every agent, since subagents don't inherit the global CLAUDE.md.

## Loop

1. **Implementation has priority.** If no implem agent is running, pick the oldest open `ready-for-claude-implem` issue with no open PR (`gh pr list --search "Closes #N"`) and spawn ONE implem agent. Never more than one at a time. It must:
   - read the issue, its `## Implementation plan (Claude review)` comment and every owner reply after it;
   - branch `issue-N-<slug>`, implement, add/run the `nos-e2e` phase when the feature touches the kernel or IPC (per CLAUDE.md), run `make check`;
   - push and `gh pr create` (body has `Closes #N`, ends with the attribution line). NEVER merge.
   After its PR opens, do not start the next implem until the owner says "merged".
2. **Plans fill idle time.** Only while no implem agent is running, spawn up to **5** parallel plan agents for `ready-for-claude-review` issues that have no plan comment, or whose owner replied after it. Each posts ONE comment headed `## Implementation plan (Claude review)`. If one exists, edit it in place by comment id — never post a second, never `--edit-last` (the owner's comments share this GitHub account):
   `rtk proxy jq -Rs '{body: .}' f > j && gh api -X PATCH repos/alexises/nos/issues/comments/<id> --input j`
   Post new ones with `gh issue comment N --body-file f`. Launch no new plan agents once an implem agent is running.
3. On each agent notification: **first** look for a `QUESTION:` block and immediately call `AskUserQuestion` with it (don't batch, don't wait for other agents), then `SendMessage` the answer to that agent. Otherwise report the plan/PR link in one line and loop.
4. Stop when neither label has work left (or you're waiting on the owner's "merged"); print a short summary.

## Tell every agent

- If blocked on a decision, don't guess: stop and end the report with `QUESTION:` (question, 2–4 options, your recommendation). Subagents can't ask the user directly.
- The `nos-e2e` docker lab is shared: serialise with `mkdir /tmp/nos-e2e.lock` (remove when done). On a permission-policy denial around the lab, do not retry; report it.
- `gh issue create` may be denied to subagents; report instead, the orchestrator files it.
- Docs prose: bullets, tables only for tabular data, how-to focus, under `docs/`.
- Closing an issue means its branch is merged to master and pushed — never close one yourself.
- If killed by a rate limit, the worktree survives: resume via `SendMessage` describing its on-disk state.
