#!/usr/bin/env bash
# Checks platform/observability against files like the one a cluster keeps at
# platform-values/observability.yaml. Rendering is the only way to run the
# chart's values.schema.json, and a file the schema must reject needs an
# assertion on the failure, so this cannot be a declarative CI job.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
chart="$root/platform/observability"
fixtures="$root/tests/fixtures/observability-values"
failures=0

render() { helm template obs "$chart" "$@"; }

expect_valid() { # name, values file
  if render -f "$2" >/dev/null 2>&1; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    render -f "$2" 2>&1 | tail -5
    failures=$((failures + 1))
  fi
}

expect_rejected() { # name, values file, text the error must contain
  local out
  if out="$(render -f "$2" 2>&1)"; then
    echo "FAIL $1 (rendered)"
    failures=$((failures + 1))
  elif grep -q -- "$3" <<<"$out"; then
    echo "ok   $1"
  else
    echo "FAIL $1 (wrong error)"
    echo "$out" | tail -5
    failures=$((failures + 1))
  fi
}

expect_valid "default values render" "$chart/values.yaml"
expect_valid "every documented key is accepted" "$fixtures/all-set.yaml"
expect_rejected "an undocumented key in a component is rejected" "$fixtures/unknown-key.yaml" "retentionn"
expect_rejected "an undocumented key in storage is rejected" "$fixtures/unknown-nested-key.yaml" "iops"
expect_rejected "an undocumented top-level key is rejected" "$fixtures/unknown-top-level.yaml" "lokii"
expect_rejected "a value of the wrong type is rejected" "$fixtures/wrong-type.yaml" "retentionSize"

exit $((failures > 0))
