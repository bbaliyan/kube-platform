#!/usr/bin/env bash
# Create or update the rendered-diff comment on a pull request.
# Usage: ci/post-comment.sh <pr-number> <comment.md>   (needs GH_TOKEN and GITHUB_REPOSITORY)
set -euo pipefail

pr="${1:?usage: post-comment.sh <pr-number> <comment.md>}"
body="${2:?usage: post-comment.sh <pr-number> <comment.md>}"

id=$(gh api "repos/$GITHUB_REPOSITORY/issues/$pr/comments" --paginate \
       --jq '.[] | select(.user.login == "github-actions[bot]" and (.body | startswith("<!-- rendered-manifests-diff -->"))) | .id' | head -1)
if [ -n "$id" ]; then
  gh api -X PATCH "repos/$GITHUB_REPOSITORY/issues/comments/$id" -F body=@"$body" >/dev/null
else
  gh pr comment "$pr" --body-file "$body"
fi
