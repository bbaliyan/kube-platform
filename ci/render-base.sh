#!/usr/bin/env bash
# Render the base commit into out/base. A base that no longer renders (say, an
# upstream chart version was pulled) must not block the change, so this only
# warns; the diff comment then says there is nothing to compare against.
# Usage: ci/render-base.sh <base-commit>
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
base="${1:-}"
tree="$(mktemp -d)"
trap 'git worktree remove --force "$tree/src" >/dev/null 2>&1; rm -rf "$tree"' EXIT

if [ -z "$base" ] || [[ "$base" =~ ^0+$ ]]; then
  echo "render-base: no base commit, skipping."
  exit 0
fi

rm -rf out/base out/base.tmp
git worktree add -q --detach "$tree/src" "$base" || { echo "render-base: cannot check out $base, skipping."; exit 0; }

# Render both sides with this branch's ci/, so a change to the harness itself
# does not show up as a manifest diff.
rm -rf "$tree/src/ci"
cp -r ci "$tree/src/ci"

# Only a complete render is kept, so a partial one cannot pose as the base.
if python3 ci/render.py "$tree/src" out/base.tmp; then
  mv out/base.tmp out/base
else
  # A new harness file can set a value that the base chart does not know yet, for
  # example a cluster file that sets a value this change adds. The base then fails
  # on its schema. Retry with the base's own ci/, which always rendered that base.
  # The diff can then show harness changes along with chart changes.
  echo "render-base: the base does not render with this branch's ci/; retrying with its own."
  rm -rf out/base.tmp "$tree/src/ci"
  git -C "$tree/src" checkout -q "$base" -- ci
  if python3 ci/render.py "$tree/src" out/base.tmp; then
    mv out/base.tmp out/base
  else
    echo "render-base: the base commit does not render; continuing without a comparison."
    rm -rf out/base.tmp
  fi
fi
exit 0
