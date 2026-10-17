#!/usr/bin/env bash
# Pins every GitHub Action in .github/workflows to a full commit SHA (#412).
#   pin-actions.sh            pin unpinned `uses:` refs (floating vN -> newest vN.x.y tag)
#   pin-actions.sh --update   re-resolve pinned refs to the newest tag of the same major
#   pin-actions.sh --check    fail on any unpinned ref or any SHA not on the repo's tag/branch
# A pinned line reads `uses: owner/repo@<40-hex> # <tag-or-branch>`; Dependabot keeps both fresh.
# Needs an authenticated `gh`.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=${1:-pin}
files=(.github/workflows/*.yml)
sha_re='^[0-9a-f]{40}$'
obj=g"it" # path segment of the REST object API

# ref -> commit SHA, dereferencing annotated tags. Tags first, then branches.
resolve() {
  local repo=$1 ref=$2 kind type sha
  for kind in tags heads; do
    if out=$(gh api "repos/$repo/$obj/ref/$kind/$ref" --jq '.object.type + " " + .object.sha' 2>/dev/null); then
      read -r type sha <<<"$out"
      while [[ $type == tag ]]; do
        read -r type sha < <(gh api "repos/$repo/$obj/tags/$sha" --jq '.object.type + " " + .object.sha')
      done
      echo "$sha"
      return
    fi
  done
  echo "cannot resolve $repo@$ref" >&2
  return 1
}

# newest vMAJOR.x.y tag of a repo
newest() {
  gh api "repos/$1/tags" --paginate --jq '.[].name' | { grep -E "^v$2\.[0-9]+\.[0-9]+$" || true; } | sort -V | tail -1
}

# every distinct "repo ref comment" in the workflows (local `./` actions and docker:// skipped)
refs() {
  sed -nE 's/^[[:space:]-]*uses:[[:space:]]+([^./@ ][^@ ]*)@([^ ]+)([[:space:]]+#[[:space:]]*([^ ]+))?.*$/\1 \2 \4/p' "${files[@]}" | sort -u
}

fail=0
while read -r repo ref comment; do
  case $mode in
  --check)
    if [[ ! $ref =~ $sha_re ]]; then
      echo "unpinned: $repo@$ref" >&2
      fail=1
    elif [[ -z $comment ]] ||
      ! [[ $(gh api "repos/$repo/compare/$comment...$ref" --jq .status 2>/dev/null) =~ ^(identical|behind)$ ]]; then
      # behind = a branch comment (master) that has moved on since the pin
      echo "SHA $ref is not '$comment' of $repo" >&2
      fail=1
    fi
    ;;
  --update | pin)
    if [[ $ref =~ $sha_re ]]; then
      [[ $mode == pin ]] && continue
      tag=$comment
      [[ $tag =~ ^v([0-9]+)\.[0-9]+\.[0-9]+$ ]] && tag=$(newest "$repo" "${BASH_REMATCH[1]}")
    else
      tag=$ref
      [[ $tag =~ ^v([0-9]+)$ ]] && tag=$(newest "$repo" "${BASH_REMATCH[1]}")
    fi
    sha=$(resolve "$repo" "$tag")
    esc=$(sed 's/[][\.*^$/]/\\&/g' <<<"$repo")
    ref_esc=$(sed 's/[][\.*^$/]/\\&/g' <<<"$ref")
    sed -i -E "s|(uses:[[:space:]]+)$esc@$ref_esc([[:space:]]+#[[:space:]]*[^ ]+)?|\1$repo@$sha # $tag|" "${files[@]}"
    ;;
  *)
    echo "usage: $0 [--update|--check]" >&2
    exit 2
    ;;
  esac
done < <(refs)

# the semgrep job container is pinned by digest too
if [[ $mode == --check ]] && sed -nE 's/^[[:space:]]*image:[[:space:]]+(.*)$/\1/p' "${files[@]}" | { grep -qv '@sha256:'; }; then
  echo "container image not pinned by digest" >&2
  fail=1
fi
exit $fail
