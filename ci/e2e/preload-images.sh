#!/usr/bin/env bash
# Pull every image named in the manifests on stdin and load it into the kind
# node, so the node never pulls from a registry itself. A registry that rate
# limits an anonymous runner would otherwise fail the run.
#
# Needs KIND (the kind binary). Optional:
#   IMAGE_CACHE_DIR  directory of saved images, kept between runs
#   PRELOAD_PAUSE    seconds to wait after the first failed pull; doubles as a
#                    multiplier on later tries (default 15, 0 in tests)
set -euo pipefail

: "${KIND:?set KIND to the kind binary}"
pause="${PRELOAD_PAUSE:-15}"
cache="${IMAGE_CACHE_DIR:-}"
[ -z "$cache" ] || mkdir -p "$cache"

# Docker Official Images are the same images on every registry that mirrors them.
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

preload() {
  local image="$1" file="" alternative got=0
  [ -z "$cache" ] || file="$cache/$(printf '%s' "$image" | sha256sum | cut -d' ' -f1).tar"

  if [ -n "$file" ] && [ -f "$file" ] && docker load -i "$file" >/dev/null; then
    "$KIND" load docker-image "$image" >/dev/null
    echo "preload: $image from cache"
    return 0
  fi

  if pull_with_retries "$image" 5; then
    got=1
    echo "preload: $image pulled"
  else
    while read -r alternative; do
      [ -n "$alternative" ] || continue
      if pull_with_retries "$alternative" 3; then
        docker tag "$alternative" "$image"
        got=1
        echo "preload: $image FALLBACK pulled as $alternative"
        break
      fi
    done < <(alternatives "$image")
  fi
  [ "$got" -eq 1 ] || {
    echo "preload: could not pull $image or any alternative"
    return 1
  }

  [ -z "$file" ] || docker save -o "$file" "$image"
  "$KIND" load docker-image "$image" >/dev/null
}

status=0
while read -r image; do
  preload "$image" || status=1
done < <(grep -oE 'image: *"?[^" ]+' | sed -E 's/image: *"?//' | sort -u)
exit "$status"
