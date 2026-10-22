#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests for .gitlab-ci.yml: it must stay a thin wrapper. The last cases change a
# copy of the file to show that each rule can fail.
# Run: tests/check-gitlab-ci.sh
set -uo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
failures=0

command -v python3 >/dev/null || { echo "tests/check-gitlab-ci.sh needs python3 (it is in the kube-devenv image)" >&2; exit 2; }

# check <pipeline file> <workflow file> <rule>: exit 0 when the file keeps the rule
check() {
  python3 -I -c '
import re, sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
workflow = open(sys.argv[2]).read()
makefile = open(sys.argv[4]).read()
reserved = {"workflow", "default", "variables", "stages", "include", "image", "cache"}
jobs = {k: v for k, v in doc.items() if k not in reserved and isinstance(v, dict)}
commit = jobs.get("commit", {})
lines = [str(s) for s in commit.get("script", [])]
tag = lambda text: re.findall(r"kube-devenv:([0-9][0-9.]*)", text)
make_targets = set(re.findall(r"^([a-z][a-z-]*):", makefile, re.M))
every = str(doc)
rules = {
  # The diff job in tiers.yaml also names the image, so compare as sets.
  "image": set(tag(doc["default"]["image"])) == set(tag(workflow.split("integration:")[0])) and tag(doc["default"]["image"]) != [],
  "runner": commit.get("tags") == ["commit"],
  "one-job": list(jobs) == ["commit"],
  "script": bool(lines) and all(l.startswith("make ") or l == "git config --global --add safe.directory \"$CI_PROJECT_DIR\"" for l in lines),
  "entry-point": all(w in make_targets for l in lines if l.startswith("make ") for w in l.split()[1:] if not "=" in w),
  "no-privilege": not any(w in every for w in ("privileged", "services", "docker.sock", "DOCKER_HOST", "docker:dind", "id_tokens")),
  "no-secret": not re.search(r"(TOKEN|SECRET|PASSWORD|PASSPHRASE|_KEY|CREDENTIAL)", every, re.I),
  "no-cache": doc["default"].get("cache") == [] and "cache" not in commit and "artifacts" not in commit,
  "interruptible": doc["default"].get("interruptible") is True,
  "no-tags": any(r.get("when") == "never" and "CI_COMMIT_TAG" in r.get("if", "") for r in doc["workflow"]["rules"]),
  "bounded": "timeout" in commit,
}
sys.exit(0 if rules[sys.argv[3]] else 1)' "$1" "$2" "$3" "$repo/Makefile"
}

report() { # name, exit code, wanted exit code
  if [ "$2" -eq "$3" ]; then echo "ok   $1"; else echo "FAIL $1"; failures=$((failures + 1)); fi
}

ci="$repo/.gitlab-ci.yml"
workflow="$repo/.github/workflows/tiers.yaml"

for rule in image runner one-job script entry-point no-privilege no-secret no-cache interruptible no-tags bounded; do
  check "$ci" "$workflow" "$rule"
  report "the pipeline file keeps the rule: $rule" "$?" 0
done

# Each change below breaks one rule, so the rule must fail.
break_it() { # rule, sed expression
  sed -e "$2" "$ci" >"$dir/changed.yml"
  cmp -s "$ci" "$dir/changed.yml" && { echo "FAIL the change for $1 did not change the file"; failures=$((failures + 1)); return; }
  check "$dir/changed.yml" "$workflow" "$1"
  report "a change that breaks '$1' is caught" "$?" 1
}
break_it image 's#kube-devenv:[0-9.]*#kube-devenv:0.0.1#'
break_it runner 's#tags: \[commit\]#tags: [sync]#'
break_it one-job '$a\
integration:\
  script:\
    - make test-integration'
break_it script 's#    - make test-commit#    - tofu fmt -check#'
break_it entry-point 's#make test-commit#make test-nothing#'
break_it no-privilege '$a\
  services: ["docker:dind"]'
break_it no-secret 's#GIT_DEPTH: "0"#GIT_DEPTH: "0"\n  API_TOKEN: abc#'
break_it no-cache 's#  cache: \[\]#  cache: {paths: [.terraform]}#'
break_it interruptible 's#interruptible: true#interruptible: false#'
break_it no-tags 's#when: never#when: always#'
break_it bounded '/timeout:/d'

[ "$failures" -eq 0 ] && echo "all gitlab pipeline file tests passed" || { echo "$failures gitlab pipeline file test(s) failed"; exit 1; }
