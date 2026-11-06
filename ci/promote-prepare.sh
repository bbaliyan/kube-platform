#!/usr/bin/env bash
# Re-validate the gate results and prepare the release files. The two final
# jobs of the promote workflow (the dry run and the real promotion) run it, so
# both do the same checks. Run it from a trusted checkout of main.
#
# A script is needed because the steps join git, ci/promote.py and file copies
# in one place that both jobs must run the same way; no action does this.
#
#   CANDIDATE=<sha> FIRST_PROMOTION=true|false \
#     SELECT_DIGEST=... SCANNED_DIGEST=... RISK_DIGEST=... ci/promote-prepare.sh [inputs-dir]
#
# inputs-dir holds the downloaded artifacts of the chosen candidate:
#   select/select.json  scanned/promotion-record-scanned.json
#   risk/manifest-risk.json  risk/manifest-risk.md  risk/revert.json
# It writes release/ (the files for the release and the attestation) and, when
# GITHUB_OUTPUT is set, the outputs `tag` and `stable_sha`. It trusts none of the
# gate jobs: it compares each input with the digest its job reported, and
# ci/promote.py verify re-checks the record, the verdict, the commit,
# the baseline and the age of the scan.
set -euo pipefail

: "${CANDIDATE:?CANDIDATE is not set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
in="${1:-inputs}"
first=()
[ "${FIRST_PROMOTION:-false}" = true ] && first=(--first-promotion)

# Each artifact must be the one its producing job described. The digests come
# from job outputs, not from the artifacts.
: "${SELECT_DIGEST:?SELECT_DIGEST is not set}" "${SCANNED_DIGEST:?SCANNED_DIGEST is not set}" "${RISK_DIGEST:?RISK_DIGEST is not set}"
python3 ci/promote.py check-digest --path "$in/select/select.json" --expected "$SELECT_DIGEST"
python3 ci/promote.py check-digest --path "$in/scanned/promotion-record-scanned.json" --expected "$SCANNED_DIGEST"
python3 ci/promote.py check-digest --path "$in/risk" --expected "$RISK_DIGEST"

stable="$(git ls-remote origin refs/heads/stable | cut -f1)"
[[ "$stable" =~ ^[a-f0-9]{40}$ ]] || { echo "prepare: cannot read stable" >&2; exit 1; }
git cat-file -e "$CANDIDATE^{commit}" || { echo "prepare: the candidate is not in this checkout" >&2; exit 1; }
git merge-base --is-ancestor "$stable" "$CANDIDATE" \
  || { echo "prepare: stable is not an ancestor of the candidate; the push would not be a fast-forward" >&2; exit 1; }

python3 ci/promote.py verify --select "$in/select/select.json" \
  --record "$in/scanned/promotion-record-scanned.json" \
  --risk "$in/risk/manifest-risk.json" --revert "$in/risk/revert.json" \
  --candidate "$CANDIDATE" --stable-sha "$stable" ${first[@]+"${first[@]}"}

tag="$(git ls-remote --tags origin 'refs/tags/stable-*' | python3 ci/promote.py tag-name)"

rm -rf release
mkdir release
cp "$in/scanned/promotion-record-scanned.json" release/promotion-record.json
cp "$in/risk/manifest-risk.json" "$in/risk/manifest-risk.md" release/
python3 ci/promote.py notes --select "$in/select/select.json" --record release/promotion-record.json \
  --risk-md release/manifest-risk.md --candidate "$CANDIDATE" --tag "$tag" \
  --repo "$GITHUB_REPOSITORY" > release/notes.md

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'tag=%s\nstable_sha=%s\n' "$tag" "$stable" >> "$GITHUB_OUTPUT"
fi
echo "prepare: ready to move stable from $stable to $CANDIDATE with tag $tag"
