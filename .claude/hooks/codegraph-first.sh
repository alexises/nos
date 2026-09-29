#!/usr/bin/env bash
# PreToolUse: this repo has a .codegraph/ index, so deny the grep reflex and
# point at codegraph_explore instead. Escape hatch: put "# cg-ok" in the command.
input=$(cat)
tool=$(jq -r '.tool_name // empty' <<<"$input")

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

use_cg='Use codegraph_explore (MCP) or `codegraph explore "<query>"` first — this repo is indexed. If you genuinely need a raw text scan (logs, transcripts, non-code files), re-run it as Bash with a trailing `# cg-ok`.'

case "$tool" in
Grep)
  deny "Grep is disabled here. $use_cg"
  ;;
Bash)
  cmd=$(jq -r '.tool_input.command // empty' <<<"$input")
  [[ $cmd == *"# cg-ok"* ]] && exit 0
  # Check the first word of each &&/;/|| segment only. A search after a pipe
  # (docker logs ... | grep) is filtering output, not searching the codebase.
  while IFS= read -r seg; do
    read -r first _ <<<"$seg"
    case "$(basename -- "${first:-x}")" in
    grep | rg | ag | ack)
      deny "\`$first\` as a search over the tree is disabled here. $use_cg"
      ;;
    esac
  done < <(printf '%s\n' "$cmd" | sed -E 's/(\&\&|\|\||;)/\n/g')
  ;;
esac
exit 0
