#!/usr/bin/env bash
#
# Refresh the public snapshot on origin/main.
#
# This repo uses an orphan `publish` branch as a single-commit
# snapshot — origin/main only ever contains that one commit, while
# local `main` keeps full development history (which may include
# operator-internal context that doesn't belong public). This
# script brings main's current tree onto publish, amends the
# snapshot commit, and force-pushes publish:main to origin.
#
# Run from main, with a clean working tree. Refuses both otherwise.
#
# Usage:
#   ./scripts/publish-snapshot.sh

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! git diff --quiet HEAD 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
    echo "publish-snapshot: working tree has uncommitted changes — commit or stash first" >&2
    exit 1
fi

current=$(git rev-parse --abbrev-ref HEAD)
if [[ $current != "main" ]]; then
    echo "publish-snapshot: must be run from main (currently on '$current')" >&2
    exit 1
fi

if ! git show-ref --verify --quiet refs/heads/publish; then
    cat >&2 <<'EOF'
publish-snapshot: 'publish' branch not found locally.

To create it for the first time:
    git checkout --orphan publish
    git reset --hard
    git checkout main -- .
    git add -A
    git commit -m "Initial public release"
    git push -u origin publish:main
    git checkout main
EOF
    exit 1
fi

main_sha=$(git rev-parse main)
echo "publish-snapshot: snapshotting main @ ${main_sha:0:7} → origin/main"

git checkout publish
git checkout main -- .
git add -A

# Amend with no message change — keeps the snapshot commit message
# stable while updating its tree.
git commit --amend --no-edit >/dev/null

git push -f origin publish:main

git checkout main
echo "publish-snapshot: done"
