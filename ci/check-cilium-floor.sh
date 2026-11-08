#!/usr/bin/env bash
# Fails when the platform's Cilium version is older than the bootstrap Cilium
# that the node image bakes. The platform's Cilium app takes over the baked
# install, so an older version would downgrade the CNI of every new node.
#
# A script is needed because no CI job definition compares two versions.
#
#   ci/check-cilium-floor.sh [versions-file]
set -euo pipefail

file="${1:-$(dirname "$0")/../platform/platform-versions/values.yaml}"
read_key() {
  local value
  value="$(sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"[:space:]]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$file")"
  [ -n "$value" ] || { echo "check-cilium-floor: $1 is not set in $file" >&2; exit 1; }
  printf '%s\n' "$value"
}

platform="$(read_key ciliumVersion)"
baked="$(read_key bootstrapCiliumVersion)"
lowest="$(printf '%s\n%s\n' "$platform" "$baked" | sort -V | head -n1)"
if [ "$lowest" != "$baked" ]; then
  echo "check-cilium-floor: ciliumVersion $platform is older than bootstrapCiliumVersion $baked." >&2
  echo "Raise ciliumVersion, or lower bootstrapCiliumVersion only after the node image no longer bakes $baked." >&2
  exit 1
fi
echo "check-cilium-floor: ciliumVersion $platform >= bootstrapCiliumVersion $baked"
