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
  pull) image="${*: -1}"; ! grep -qxF "$image" "$FAIL_PULL" ;;
  save) : >"$3" ;;
  *) ;;
esac
EOF
cat >"$work/bin/kind" <<'EOF'
#!/usr/bin/env bash
echo "kind $*" >>"$LOG"
EOF
chmod +x "$work/bin/docker" "$work/bin/kind"

export PATH="$work/bin:$PATH" KIND="$work/bin/kind" PRELOAD_PAUSE=0
export LOG="$work/log" FAIL_PULL="$work/fail"
ecr='ecr-public.aws.com/docker/library/redis:8.6.4-alpine'
hub='docker.io/library/redis:8.6.4-alpine'
manifest="        image: \"$ecr\""

run() { : >"$LOG"; "$script" <<<"$manifest" 2>&1; }
fail() { echo "FAIL $1"; cat "$LOG"; exit 1; }
ok() { echo "ok   $1"; }

: >"$FAIL_PULL"
out="$(run)"
grep -qxF "kind load docker-image $ecr" "$LOG" || fail "pulled image is loaded into kind"
grep -q 'pulled' <<<"$out" || fail "pulled image is reported"
ok "pulled image is loaded into kind"

echo "$ecr" >"$FAIL_PULL"
out="$(run)"
grep -qxF "docker tag $hub $ecr" "$LOG" || fail "fallback image is tagged as the original"
grep -qxF "kind load docker-image $ecr" "$LOG" || fail "fallback image is loaded under the original name"
grep -q 'FALLBACK' <<<"$out" || fail "fallback is reported"
ok "rate-limited image falls back to Docker Hub and keeps its name"

printf '%s\n' "$ecr" "$hub" "mirror.gcr.io/library/redis:8.6.4-alpine" >"$FAIL_PULL"
status=0
out="$(run)" || status=$?
[ "$status" -ne 0 ] || fail "exit is non-zero when every source fails"
grep -q "could not pull $ecr" <<<"$out" || fail "failure names the image"
ok "every source failing stops with the image name"

: >"$FAIL_PULL"
cache="$work/cache"
export IMAGE_CACHE_DIR="$cache"
out="$(run)"
[ -n "$(ls "$cache")" ] || fail "pulled image is saved to the cache"
ok "pulled image is saved to the cache"

echo "$ecr" >"$FAIL_PULL"
out="$(run)"
grep -q '^docker pull' "$LOG" && fail "cache hit does not pull"
grep -q '^docker load' "$LOG" || fail "cache hit loads the saved image"
grep -q 'cache' <<<"$out" || fail "cache hit is reported"
ok "cache hit loads without pulling"
