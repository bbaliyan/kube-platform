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

expect_rejected "a drop preset that is not a boolean is rejected" "$fixtures/wrong-type-drop-preset.yaml" "dropUnusedControlPlaneMetrics"
expect_rejected "extraDropMetrics that is not a list is rejected" "$fixtures/wrong-type-extra-drop.yaml" "extraDropMetrics"
expect_rejected "an empty extraDropMetrics regex is rejected" "$fixtures/empty-extra-drop.yaml" "extraDropMetrics"

# The Prometheus Application carries the chart values as one string, so these
# assertions count lines of the rendered text.
count_lines() { # pattern, values file or empty
  local file=()
  [ -z "${2:-}" ] || file=(-f "$2")
  render "${file[@]}" | grep -c -- "$1" || true
}

expect_count() { # name, wanted count, pattern, values file or empty
  local got
  got="$(count_lines "$3" "${4:-}")"
  if [ "$got" = "$2" ]; then
    echo "ok   $1"
  else
    echo "FAIL $1 (wanted $2, got $got)"
    failures=$((failures + 1))
  fi
}

preset="$fixtures/drop-preset.yaml"
extra_only="$fixtures/drop-extra-only.yaml"
expect_count "defaults render no metric drop rule" 0 "metricRelabelings"
expect_count "the preset adds a metricRelabelings list to the four ServiceMonitors" 4 "metricRelabelings:" "$preset"
expect_count "the preset keeps the chart's own API server drop rule" 1 "apiserver_request_slo|apiserver_request_sli|apiserver_request)_duration_seconds_bucket;" "$preset"
expect_count "the preset drops on the metric name, once per component" 4 "go_(gc|godebug" "$preset"
expect_count "extraDropMetrics reaches every component" 4 "extra_one_.\*|extra_two" "$preset"
expect_count "extraDropMetrics alone adds no preset regex" 0 "go_(gc|godebug" "$extra_only"
expect_count "extraDropMetrics alone reaches every component" 4 "^ *regex: only_extra_.\*$" "$extra_only"

exit $((failures > 0))
