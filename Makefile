# Every check lives here. The CI workflow only sets up the environment and
# calls a target, so a run on a laptop matches a run on GitHub.
#
# diff-comment is not part of test-commit: it compares against BASE_REF and
# only feeds a PR comment. It writes out/comment.md.
#
# test-commit runs inside the kube-devenv image. test-integration also needs
# docker, kind, helm, kubectl, curl, jq and python3 with pyyaml on PATH.
#   BASE_REF      commit the branch started from; empty skips commit-messages
#   GENESIS_REF   commit whose platform-versions the kind cluster installs
#                 first, so a version bump is tested as an upgrade; empty
#                 uses the checked-out versions
#   RUNTIME_IMAGES_OUT  file where test-integration writes the images the
#                 containers report; empty writes nothing
#
# promotion-record is not part of test-commit: it needs the network, docker
# buildx and the file that test-integration writes. Run make render, put that
# file at RUNTIME_IMAGES, then run make promotion-record. It writes
# out/promotion-record.json.
RUNTIME_IMAGES ?= out/runtime-images.json

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

CHECKS   ?= /usr/share/kube-devenv/checks
BASE_REF ?= $(shell git rev-parse --verify --quiet origin/main)
export REQUIRE_SIGNOFF := 0

.PHONY: test-commit test-fast test-integration hooks lint-scripts lint-yaml \
	lint-pipelines lint-renovate test-scripts render app-finalizers schemas dropped-metrics secrets commit-messages diff-comment promotion-record

test-commit: test-fast lint-pipelines lint-renovate test-scripts render app-finalizers schemas dropped-metrics commit-messages

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
	tests/check-gitlab-ci.sh

test-scripts:
	tests/preload-images.sh
	tests/check-app-finalizers.sh
	tests/check-observability-values.sh
	tests/check-promotion-record.py

lint-renovate:
	python3 -c "import json; json.load(open('renovate.json'))"

render:
	rm -rf out
	python3 ci/render.py . out/head

# _root holds the cluster's own root Application, which a consumer owns.
app-finalizers: render
	find out/head -mindepth 2 -maxdepth 2 -type d ! -name _root -print0 | xargs -0 ci/check-app-finalizers.sh

schemas: render
	ci/validate-schemas.sh out/head

# Renders once more, with the preset on, and compares its regexes with the used metric names.
dropped-metrics: render
	tests/check-dropped-metrics.py out/head

secrets:
	$(CHECKS)/secrets.sh .

commit-messages:
	$(CHECKS)/commit-messages.sh "$(BASE_REF)"

# The delta security gate. See ci/README.md "Security gate". It is not part of
# test-commit: it scans images over the network. These two are checks:
#   test-security-gate   fixture tests of ci/security_gate.py (part of test-scripts)
#   check-trivyignore    expiry and reason of every ci/security-gate.trivyignore entry
# security-gate needs out/promotion-record.json and out/kev.json (make kev-catalog).
#   BASELINE_RECORD  the promotion record of the current stable; empty means
#                    the first promotion, where only a KEV finding blocks
.PHONY: test-security-gate check-trivyignore kev-catalog security-gate
test-commit: check-trivyignore
test-scripts: test-security-gate
KEV_URL ?= https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
BASELINE_RECORD ?=

test-security-gate:
	tests/check-security-gate.py

check-trivyignore:
	python3 ci/security_gate.py check-ignore ci/security-gate.trivyignore

kev-catalog:
	mkdir -p out
	curl -fsSL --retry 3 --retry-all-errors -o out/kev.json "$(KEV_URL)"

security-gate:
	python3 ci/security_gate.py scan --record out/promotion-record.json --out out/scan-results.json
	status=0; \
	python3 ci/security_gate.py decide --record out/promotion-record.json --scan out/scan-results.json \
		--kev out/kev.json --ignore ci/security-gate.trivyignore \
		$(if $(BASELINE_RECORD),--baseline "$(BASELINE_RECORD)",--no-baseline) \
		--out out/promotion-record-scanned.json --summary out/security-summary.md || status=$$?; \
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ] && [ -f out/security-summary.md ]; then cat out/security-summary.md >> "$$GITHUB_STEP_SUMMARY"; fi; \
	exit $$status

diff-comment: render
	ci/render-base.sh "$(BASE_REF)"
	python3 ci/diff_comment.py out/base out/head out/comment.md
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then cat out/comment.md >> "$$GITHUB_STEP_SUMMARY"; fi

promotion-record:
	python3 ci/promotion_record.py build --rendered out/head --runtime "$(RUNTIME_IMAGES)" \
		--out out/promotion-record.json --commit "$$(git rev-parse HEAD)"

test-integration:
	ci/e2e/run.sh
