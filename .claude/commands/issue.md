---
description: Run the issue-driven agent workflow (implement labelled issues one at a time, plan others in parallel)
argument-hint: "[issue numbers to restrict to]"
model: sonnet
---

You are the orchestrator of the NOS issue workflow for the GitHub repo `alexises/nos` (use `gh`; it is GitHub, not GitLab). Restrict to issues `$ARGUMENTS` if any were given, otherwise consider all open issues.

Labels: `ready-for-claude-review` (needs a plan), `ready-for-user-plan-review` (plan posted, waiting for the owner to review it) and `ready-for-claude-implem` (plan approved, implement). Create either with `gh label create` if missing (check `gh label list` first).

Agents (defined in `.claude/agents/`, each with its own default `model:` — the owner tunes it there):

- `issue-planner` — plans one issue; splits big work into linked sub-issues.
- `issue-implementer` — implements one issue or sub-issue, opens one PR.

Spawn them with `subagent_type`, `run_in_background: true`, `isolation: "worktree"` and **no `model` argument** (the agent file's default applies). Their files already carry the `rtk`/CodeGraph/lab-lock rules; still restate `rtk` + CodeGraph in the prompt, and pass the attribution lines from your system reminder (commit trailers, PR footer).

## Loop

1. **Implementation has priority.** If no implementer is running, pick the oldest open `ready-for-claude-implem` issue with no open PR (`gh pr list --search "Closes #N"`) and spawn ONE `issue-implementer`. Never more than one at a time. Skip an issue whose `Depends on #M` (see its body) isn't merged/closed yet. If the issue has sub-issues and none is labelled implem, it's the planner's umbrella: skip it. After its PR opens, do not start the next implementer until the owner says "merged". A merged PR whose issue stays open (no auto-close) isn't yours to close: mention it.
2. **Plans fill idle time.** Only while no implementer is running, spawn up to **5** parallel `issue-planner`s for `ready-for-claude-review` issues that have no plan comment, or whose owner replied after it. Launch no new planners once an implementer is running. When a planner finishes (plan posted, and any `QUESTION:` answered), swap the label on its issue: `gh issue edit N --add-label ready-for-user-plan-review --remove-label ready-for-claude-review`; do the same for every sub-issue that has its own plan comment. When the owner replies on a plan, they put `ready-for-claude-review` back; treat that as a re-plan. Sub-issues a planner creates carry no `ready-for-claude-*` label: the owner approves each by labelling it `ready-for-claude-implem`. If the planner couldn't create them (denied), file them yourself from its report.
3. On each agent notification: **first** look for a `QUESTION:` block and immediately call `AskUserQuestion` with it (don't batch, don't wait for other agents), then `SendMessage` the answer to that agent. Otherwise, for a PR: run `gh pr view N --json mergeable,mergeStateStatus` (retry a few seconds if `UNKNOWN`); if `CONFLICTING`/`DIRTY`, `SendMessage` the implementer to merge master into the branch, resolve, re-run `make check` and push, and only tell the owner once it is clean (never report a conflicting PR as ready). Then report the plan/PR link in one line and loop. A "completed" notice saying the agent still has background work isn't its final report: wait for the hand-back.
4. Stop when neither label has work left (or you're waiting on the owner's "merged"); print a short summary.

## Model upgrades (only with the owner's permission)

Never override an agent's `model` on your own. If a task looks too complex for the agent's default model, ask first with `AskUserQuestion` (options: keep current / upgrade to the next model, recommendation first), then spawn with the `model` argument only on a yes. Ladder: `sonnet` → `opus` → `fable`. Signals worth asking about:

- before spawning: the plan says it spans several daemons plus kernel/IPC/wire changes, has many open decisions, or the issue is a protocol state machine (graceful restart, ADD-PATH, EVPN multi-homing, …);
- after: the agent stopped with a failure it couldn't fix, looped on the same failing check, or its report admits gaps it couldn't close.

For an already-running agent you can't change the model: ask, then re-spawn (or `SendMessage` the old one's on-disk state to the new agent). Ask at most once per issue; remember the answer for its later PRs.

## Tell every agent

- If blocked on a decision, don't guess: stop and end the report with `QUESTION:` (question, 2–4 options, your recommendation). Subagents can't ask the user directly.
- The `nos-e2e` docker lab is shared: serialise with `mkdir /tmp/nos-e2e.lock` (remove when done). On a permission-policy denial around the lab, do not retry; report it.
- `gh issue create` may be denied to subagents; report instead, the orchestrator files it.
- Docs prose: bullets, tables only for tabular data, how-to focus, under `docs/`.
- Closing an issue means its branch is merged to master and pushed — never close one yourself.
- If killed by a rate limit, the worktree survives: resume via `SendMessage` describing its on-disk state.
