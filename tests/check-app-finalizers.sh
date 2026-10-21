#!/usr/bin/env bash
# Runs scripts/check-app-finalizers.sh against small fixtures.
set -euo pipefail

check="$(cd "$(dirname "$0")/.." && pwd)/ci/check-app-finalizers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

application() { # file, extra metadata lines
  cat >"$1" <<YAML
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: demo
  namespace: argocd
$2
spec:
  project: default
YAML
}

expect() { # name, want (pass|fail), directory, text the output must contain
  local status=0
  "$check" "$3" >"$work/out" 2>&1 || status=$?
  if [ "$2" = pass ] && [ "$status" -eq 0 ]; then
    echo "ok   $1"
  elif [ "$2" = fail ] && [ "$status" -eq 1 ] && grep -q -- "$4" "$work/out"; then
    echo "ok   $1"
  else
    echo "FAIL $1 (exit $status)"
    cat "$work/out"
    failures=$((failures + 1))
  fi
}

mkdir "$work/with"
application "$work/with/app.yaml" '  finalizers:
    - resources-finalizer.argocd.argoproj.io'
expect "finalizer present passes" pass "$work/with"

mkdir "$work/without"
application "$work/without/app.yaml" ''
expect "finalizer missing fails" fail "$work/without" "lacks the"

mkdir "$work/other"
application "$work/other/app.yaml" '  finalizers:
    - something.else/finalizer'
expect "a different finalizer fails" fail "$work/other" "lacks the"

mkdir "$work/optout"
application "$work/optout/app.yaml" '  annotations:
    kube-stack/keep-resources-on-delete: holds the database volume claim
    argocd.argoproj.io/sync-options: Prune=false,Delete=false'
expect "opt-out with a reason passes" pass "$work/optout"

mkdir "$work/nosync"
application "$work/nosync/app.yaml" '  annotations:
    kube-stack/keep-resources-on-delete: holds the database volume claim'
expect "opt-out without sync options fails" fail "$work/nosync" "lacks Prune=false and Delete=false"

mkdir "$work/halfsync"
application "$work/halfsync/app.yaml" '  annotations:
    kube-stack/keep-resources-on-delete: holds the database volume claim
    argocd.argoproj.io/sync-options: Prune=false'
expect "opt-out with only Prune=false fails" fail "$work/halfsync" "lacks Prune=false and Delete=false"

mkdir "$work/emptyreason"
application "$work/emptyreason/app.yaml" '  annotations:
    kube-stack/keep-resources-on-delete: ""
    argocd.argoproj.io/sync-options: Prune=false,Delete=false'
expect "opt-out without a reason fails" fail "$work/emptyreason" "empty"

mkdir "$work/both"
application "$work/both/app.yaml" '  annotations:
    kube-stack/keep-resources-on-delete: holds the database volume claim
    argocd.argoproj.io/sync-options: Prune=false,Delete=false
  finalizers:
    - resources-finalizer.argocd.argoproj.io'
expect "finalizer and opt-out together fail" fail "$work/both" "has both"

mkdir "$work/mixed"
application "$work/mixed/good.yaml" '  finalizers:
    - resources-finalizer.argocd.argoproj.io'
application "$work/mixed/bad.yaml" ''
expect "one bad Application among good ones fails" fail "$work/mixed" "lacks the"

mkdir "$work/multidoc"
{
  printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n---\n'
  application /dev/stdout ''
} >"$work/multidoc/app.yaml"
expect "a bare Application after another document fails" fail "$work/multidoc" "lacks the"

mkdir "$work/ignored"
application "$work/ignored/app.yaml" '  finalizers:
    - resources-finalizer.argocd.argoproj.io'
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n---\n- a list\n' >"$work/ignored/cm.yaml"
expect "non-Application documents are ignored" pass "$work/ignored"

mkdir "$work/empty"
expect "a directory with no Application fails" fail "$work/empty" "no Applications found"

[ "$failures" -eq 0 ]
