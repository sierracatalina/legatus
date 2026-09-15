#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SCAN="$SCRIPT_DIR/leak-scan.sh"
TMP_BASE=$(cd "${TMPDIR:-/tmp}" && pwd -P)
FIXTURE_ROOT=$(mktemp -d "$TMP_BASE/legatus-leak-scan.XXXXXX")

cleanup() {
  case "$FIXTURE_ROOT" in
    "$TMP_BASE"/legatus-leak-scan.*) rm -rf -- "$FIXTURE_ROOT" ;;
    *) echo "refusing unsafe fixture cleanup: $FIXTURE_ROOT" >&2; return 1 ;;
  esac
}
trap cleanup EXIT

# A linked worktree stores its administrative path in a regular .git file.
printf '%s%s\n' 'gitdir: C:' '\Users\fixture\repo\.git\worktrees\linked' > "$FIXTURE_ROOT/.git"
printf '%s\n' 'public release fixture' > "$FIXTURE_ROOT/release.txt"

PASS_OUTPUT=$(bash "$SCAN" "$FIXTURE_ROOT")
[[ "$PASS_OUTPUT" == "PUBLIC RELEASE SCAN PASSED" ]]

# A matching path in a release file must still fail the scan.
printf '%s%s\n' 'C:' '\Users\fixture\private.txt' > "$FIXTURE_ROOT/release.txt"
set +e
FAIL_OUTPUT=$(bash "$SCAN" "$FIXTURE_ROOT" 2>&1)
FAIL_RC=$?
set -e

[[ "$FAIL_RC" -eq 1 ]]
[[ "$FAIL_OUTPUT" == *"PUBLIC RELEASE SCAN FAILED"* ]]
[[ "$FAIL_OUTPUT" == *"release.txt"* ]]

echo "PUBLIC RELEASE SCAN REGRESSION PASSED"
