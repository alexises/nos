#!/usr/bin/env bash
# Fails when a tracked CLAUDE.md exceeds its ceiling in tools/ci/claude-md-budget.txt (#252, #258).
set -euo pipefail
cd "$(dirname "$0")/../.."
budget=tools/ci/claude-md-budget.txt
declare -A max
while read -r path bytes extra; do
  [[ -z "$path" || "$path" == \#* ]] && continue
  if [[ -z "$bytes" || -n "$extra" || ! "$bytes" =~ ^[0-9]+$ ]]; then
    echo "$budget: malformed line: $path $bytes $extra" >&2
    exit 1
  fi
  max[$path]=$bytes
done <"$budget"
fail=0 n=0 total=0
declare -A seen
while read -r f; do
  seen[$f]=1
  size=$(wc -c <"$f")
  n=$((n + 1))
  total=$((total + size))
  if [[ -z "${max[$f]:-}" ]]; then
    echo "$f: no entry in $budget"
    fail=1
  elif ((size > max[$f])); then
    echo "$f: $size bytes > ceiling ${max[$f]}"
    fail=1
  fi
done < <(git ls-files '*CLAUDE.md') # tracked only: ignores .claude/worktrees copies
for f in "${!max[@]}"; do
  [[ -n "${seen[$f]:-}" ]] || {
    echo "$f: stale entry in $budget (file not tracked)"
    fail=1
  }
done
if ((fail)); then
  echo "shrink the file (move detail to docs/) or, if justified, edit the ceiling in $budget (visible in review)"
  exit 1
fi
echo "claude-md: $n files within budget (total $total bytes)"
