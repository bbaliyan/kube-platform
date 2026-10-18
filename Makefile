# Every check lives here. The CI workflow only sets up the environment and
# calls a target, so a run on a laptop matches a run on GitHub.
#
# diff-comment is not part of test-commit: it compares against BASE_REF and
# only feeds a PR comment. It writes out/comment.md.
#
# test-commit runs inside the kube-devenv image. test-integration also needs
# docker, kind, helm, kubectl, curl and python3 with pyyaml on PATH.
#   BASE_REF      commit the branch started from; empty skips commit-messages
#   GENESIS_REF   commit whose platform-versions the kind cluster installs
#                 first, so a version bump is tested as an upgrade; empty
#                 uses the checked-out versions

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

CHECKS   ?= /usr/share/kube-devenv/checks
BASE_REF ?= $(shell git rev-parse --verify --quiet origin/main)
export REQUIRE_SIGNOFF := 0

.PHONY: test-commit test-fast test-integration hooks lint-scripts lint-yaml \
	lint-pipelines lint-renovate test-scripts render schemas secrets commit-messages diff-comment

test-commit: test-fast lint-pipelines lint-renovate test-scripts render schemas commit-messages

test-fast: lint-scripts lint-yaml secrets

hooks:
	git config core.hooksPath .githooks

lint-scripts:
	bash -n ci/*.sh ci/e2e/*.sh tests/*.sh .githooks/pre-commit
	shellcheck -S warning ci/*.sh ci/e2e/*.sh tests/*.sh .githooks/pre-commit

lint-yaml:
	yamllint -d '{extends: relaxed, rules: {line-length: disable}}' ci/clusters ci/e2e bootstrap/values.yaml platform/platform-versions/values.yaml

lint-pipelines:
	$(CHECKS)/pipeline-lint.sh .

test-scripts:
	tests/preload-images.sh

lint-renovate:
	python3 -c "import json; json.load(open('renovate.json'))"

render:
	rm -rf out
	python3 ci/render.py . out/head

schemas: render
	ci/validate-schemas.sh out/head

secrets:
	$(CHECKS)/secrets.sh .

commit-messages:
	$(CHECKS)/commit-messages.sh "$(BASE_REF)"

diff-comment: render
	ci/render-base.sh "$(BASE_REF)"
	python3 ci/diff_comment.py out/base out/head out/comment.md
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then cat out/comment.md >> "$$GITHUB_STEP_SUMMARY"; fi

test-integration:
	ci/e2e/run.sh
