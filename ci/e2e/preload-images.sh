#!/usr/bin/env bash
# Pull every image named in the manifests on stdin and load it into the kind
# node, so the node never pulls from a registry itself. A registry that rate
# limits an anonymous runner would otherwise fail the run.
#
# Needs KIND (the kind binary). PRELOAD_PAUSE is the base wait in seconds: try
# N waits N times this after it fails (default 15, 0 in tests).
set -euo pipefail

: "${KIND:?set KIND to the kind binary}"
pause="${PRELOAD_PAUSE:-15}"

# Docker Official Images are the same image, with the same digest, on every
# registry that mirrors them.
alternatives() {
  case "$1" in
    ecr-public.aws.com/docker/library/*)
      echo "docker.io/library/${1#ecr-public.aws.com/docker/library/}"
      echo "mirror.gcr.io/library/${1#ecr-public.aws.com/docker/library/}" ;;
  esac
}

pull_with_retries() {
  local image="$1" tries="$2" attempt
  for ((attempt = 1; attempt <= tries; attempt++)); do
    docker pull -q "$image" >/dev/null 2>&1 && return 0
    [ "$attempt" -eq "$tries" ] || sleep $((attempt * pause))
  done
  return 1
}

# On a Docker with the containerd image store, a pulled image keeps its full
# multi-platform index but only this platform's blobs. A plain `kind load
# docker-image` saves the whole index, and `ctr import --all-platforms` then
# fails on the missing blobs. Saving one platform avoids that.
load_into_kind() {
  local image="$1" platform archive status=0
  platform="linux/$(docker version --format '{{.Server.Arch}}')"
  archive="$(mktemp)"
  docker save --platform "$platform" -o "$archive" "$image" &&
    "$KIND" load image-archive "$archive" >/dev/null || status=1
  rm -f "$archive"
  return "$status"
}

preload() {
  local image="$1" alternative
  if pull_with_retries "$image" 5; then
    echo "preload: $image pulled"
  else
    while read -r alternative; do
      pull_with_retries "$alternative" 3 || continue
      docker tag "$alternative" "$image" || return 1
      echo "preload: $image FALLBACK pulled as $alternative"
      break
    done < <(alternatives "$image")
    docker image inspect "$image" >/dev/null 2>&1 || {
      echo "preload: could not pull $image or any alternative"
      return 1
    }
  fi
  load_into_kind "$image" || {
    echo "preload: kind could not load $image"
    return 1
  }
}

images="$(grep -oE 'image: *"?[^" ]+' | sed -E 's/image: *"?//' | sort -u)"
[ -n "$images" ] || {
  echo "preload: no images in the manifests"
  exit 1
}

status=0
while read -r image; do
  preload "$image" || status=1
done <<<"$images"
exit "$status"
