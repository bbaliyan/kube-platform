#!/usr/bin/env bash
# Renders the bootstrap chart with and without imdsGuard and checks the
# instance metadata policy it produces.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

render() { # extra helm flags; writes the guard policies as JSON to $work/out
  local status=0
  helm template platform "$root/bootstrap" \
    --values "$root/platform/platform-versions/values.yaml" "$@" \
    >"$work/rendered" 2>"$work/err" || status=$?
  python3 - "$work/rendered" >"$work/out" <<'PY'
import json, sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if isinstance(d, dict)]
print(json.dumps([d for d in docs if d.get("kind") == "CiliumClusterwideNetworkPolicy"]))
PY
  [ "$status" -eq 0 ] || cat "$work/err" >&2
  return "$status"
}

expect() { # name, python expression on `policies` that must be true
  if python3 -c "import json, sys; policies = json.load(open(sys.argv[1])); sys.exit(0 if ($2) else 1)" "$work/out"; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    cat "$work/out" "$work/err"
    failures=$((failures + 1))
  fi
}

expect_failure() { # name, text the error must contain, helm flags...
  local name="$1" text="$2"
  shift 2
  if ! render "$@" && grep -q -- "$text" "$work/err"; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    cat "$work/err"
    failures=$((failures + 1))
  fi
}

render --set awsRegion=eu-west-1
expect "disabled renders no policy" "policies == []"

render --set awsRegion=eu-west-1 --set imdsGuard.enabled=true
expect "enabled renders one policy" "len(policies) == 1"
expect "it denies egress to the metadata address" \
  "policies[0]['spec']['egressDeny'] == [{'toCIDR': ['169.254.169.254/32']}]"
expect "it leaves default-deny off in both directions" \
  "policies[0]['spec']['enableDefaultDeny'] == {'egress': False, 'ingress': False}"
expect "it has no allow rules" \
  "not {'egress', 'ingress'} & set(policies[0]['spec'])"
expect "it selects every namespace outside the default allow list" \
  "policies[0]['spec']['endpointSelector'] == {'matchExpressions': [{'key': 'io.kubernetes.pod.namespace', 'operator': 'NotIn', 'values': ['kube-system', 'external-secrets', 'cluster-autoscaler', 'external-dns']}]}"

render --set awsRegion=eu-west-1 --set imdsGuard.enabled=true --set 'imdsGuard.allowedNamespaces={external-secrets}'
expect "the allow list is a value" \
  "policies[0]['spec']['endpointSelector']['matchExpressions'][0]['values'] == ['external-secrets']"

render --set awsRegion=eu-west-1 --set imdsGuard.enabled=true --set imdsGuard.allowedNamespaces=null
expect "an empty allow list selects every pod" "policies[0]['spec']['endpointSelector'] == {}"

expect_failure "enabled without awsRegion fails" "imdsGuard is for AWS clusters" --set imdsGuard.enabled=true

render
expect "a cluster without awsRegion renders no policy" "policies == []"

[ "$failures" -eq 0 ]
