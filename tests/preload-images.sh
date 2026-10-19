#!/usr/bin/env bash
# Tests for ci/e2e/preload-images.sh with stand-in docker and kind commands.
set -euo pipefail

script="$(cd "$(dirname "$0")/.." && pwd)/ci/e2e/preload-images.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >>"$LOG"
case "$1" in
  pull) ! grep -qxF "${*: -1}" "$FAIL_PULL" ;;
  tag) echo "$3" >>"$HAVE" ;;
  image) grep -qxF "$3" "$HAVE" ;;
  version) echo amd64 ;;
  save) [ "$2" = --platform ] && : >"$5" ;;
esac
EOF
cat >"$work/bin/kind" <<'EOF'
#!/usr/bin/env bash
echo "kind $*" >>"$LOG"
[ -z "${FAIL_KIND:-}" ]
EOF
chmod +x "$work/bin/docker" "$work/bin/kind"

export PATH="$work/bin:$PATH" KIND="$work/bin/kind" PRELOAD_PAUSE=0
export LOG="$work/log" FAIL_PULL="$work/fail" HAVE="$work/have"
ecr='ecr-public.aws.com/docker/library/redis:8.6.4-alpine'
hub='docker.io/library/redis:8.6.4-alpine'
gcr='mirror.gcr.io/library/redis:8.6.4-alpine'
other='quay.io/argoproj/argocd:v3.5.4'

reset() { : >"$LOG"; : >"$HAVE"; printf '%s\n' "$@" >"$FAIL_PULL"; unset FAIL_KIND; }
run() { "$script" <<<"        image: \"$1\"" 2>&1; }
expect_fail() { echo "FAIL $1"; cat "$LOG"; exit 1; }
ok() { echo "ok   $1"; }

reset
out="$(run "$ecr")"
grep -qE "^docker save --platform linux/amd64 -o [^ ]+ $ecr\$" "$LOG" || expect_fail "one platform is saved"
grep -qE "^kind load image-archive [^ ]+\$" "$LOG" || expect_fail "pulled image is loaded into kind"
grep -q 'pulled' <<<"$out" || expect_fail "pulled image is reported"
ok "pulled image is saved for one platform and loaded into kind"

reset "$ecr"
out="$(run "$ecr")"
grep -qxF "docker tag $hub $ecr" "$LOG" || expect_fail "fallback image is tagged as the original"
grep -qE "^docker save --platform linux/amd64 -o [^ ]+ $ecr\$" "$LOG" || expect_fail "fallback image is loaded under the original name"
grep -q 'FALLBACK' <<<"$out" || expect_fail "fallback is reported"
ok "refused image falls back to Docker Hub and keeps its name"

reset "$ecr" "$hub"
run "$ecr" >/dev/null
grep -qxF "docker tag $gcr $ecr" "$LOG" || expect_fail "second mirror is used"
ok "second mirror is used when Docker Hub is also refused"

reset "$ecr" "$hub" "$gcr"
status=0
out="$(run "$ecr")" || status=$?
[ "$status" -ne 0 ] || expect_fail "exit is non-zero when every source fails"
grep -q "could not pull $ecr" <<<"$out" || expect_fail "failure names the image"
ok "every source failing stops with the image name"

reset "$other"
status=0
out="$(run "$other")" || status=$?
[ "$status" -ne 0 ] || expect_fail "image without alternatives fails when refused"
grep -q "could not pull $other" <<<"$out" || expect_fail "failure names the image"
ok "an image with no alternatives fails when refused"

reset
export FAIL_KIND=1
status=0
out="$(run "$ecr")" || status=$?
[ "$status" -ne 0 ] || expect_fail "exit is non-zero when kind cannot load the image"
grep -q "kind could not load $ecr" <<<"$out" || expect_fail "load failure names the image"
ok "a failed load into kind stops with the image name"

reset
status=0
out="$("$script" <<<"no images here" 2>&1)" || status=$?
[ "$status" -ne 0 ] || expect_fail "exit is non-zero for an empty image list"
ok "an empty image list fails"
