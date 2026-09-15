#!/usr/bin/env bash
# Public-release scan. Reports likely credentials, local paths, and private links.
set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

PATTERN='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}|gh(p|o|u|s|r)_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[A-Za-z0-9_-]{30,}|(AKIA|ASIA)[A-Z0-9]{16}|[A-Za-z]:\\Users\\|/(home|Users)/[^/[:space:]]+/|file:''///|docs\.google\.com|drive\.google\.com|notion\.(so|com)'

FILES=()
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' path; do
    FILES+=("$path")
  done < <(git ls-files -z --cached --others --exclude-standard)
else
  while IFS= read -r -d '' path; do
    FILES+=("$path")
  done < <(find . -name .git -prune -o -type f -print0)
fi

if [[ "${#FILES[@]}" -eq 0 ]]; then
  echo "PUBLIC RELEASE SCAN PASSED"
  exit 0
fi

set +e
HITS=$(grep -HInEi \
  --binary-files=without-match \
  -- "$PATTERN" "${FILES[@]}" 2>/dev/null)
RC=$?
set -e

if [[ "$RC" -eq 0 && -n "$HITS" ]]; then
  echo "PUBLIC RELEASE SCAN FAILED"
  echo "$HITS"
  exit 1
fi

if [[ "$RC" -eq 1 ]]; then
  echo "PUBLIC RELEASE SCAN PASSED"
  exit 0
fi

echo "PUBLIC RELEASE SCAN ERROR (grep rc=$RC)"
exit 2
