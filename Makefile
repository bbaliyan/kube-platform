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
	tests/check-manifest-risk.py

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
#   BASELINE_RECORD  the promotion record of the current stable
#   FIRST_PROMOTION  set to 1 when no stable exists yet: the delta is skipped and
#                    only a KEV finding blocks. Set exactly one of the two;
#                    with neither, or both, the target fails.
.PHONY: test-security-gate check-trivyignore kev-catalog security-gate
test-commit: check-trivyignore
test-scripts: test-security-gate
KEV_URL ?= https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
BASELINE_RECORD ?=
FIRST_PROMOTION ?=

test-security-gate:
	tests/check-security-gate.py

check-trivyignore:
	python3 ci/security_gate.py check-ignore ci/security-gate.trivyignore

kev-catalog:
	mkdir -p out
	curl -fsSL --retry 3 --retry-all-errors -o out/kev.json "$(KEV_URL)"

security-gate:
	@if [ -n "$(BASELINE_RECORD)" ] && [ -n "$(FIRST_PROMOTION)" ]; then 		echo "set BASELINE_RECORD or FIRST_PROMOTION=1, not both" >&2; exit 1; fi
	@if [ -z "$(BASELINE_RECORD)" ] && [ -z "$(FIRST_PROMOTION)" ]; then 		echo "set BASELINE_RECORD=<the stable record>, or FIRST_PROMOTION=1 if no stable exists" >&2; exit 1; fi
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

# manifest-risk compares the checked-out commit (the candidate) with STABLE_REF
# and keeps only the risk classes. It writes manifest-risk.json and
# manifest-risk.md to out/manifest-risk. It is not part of test-commit: it
# needs the network.
STABLE_REF ?= origin/stable

.PHONY: manifest-risk
manifest-risk: render
	ci/render-base.sh "$(STABLE_REF)"
	test -d out/base || { echo "manifest-risk: $(STABLE_REF) did not render"; exit 1; }
	python3 ci/manifest_risk.py --stable out/base --candidate out/head \
		--allowlist ci/registry-allowlist.yaml --out-dir out/manifest-risk
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then cat out/manifest-risk/manifest-risk.md >> "$$GITHUB_STEP_SUMMARY"; fi

# The promote workflow (ci/README.md "Promote workflow") judges a candidate with
# the scripts of a trusted checkout (main HEAD), never with the candidate's own.
#   promote-overlay        run in the trusted checkout: replace ci/, tests/, the
#                          Makefile and the lint and secret-scan settings of the
#                          candidate checkout CANDIDATE (OVERLAY_PATHS) with the
#                          trusted ones, so the candidate is data only
#   promote-revert-check   run in the overlaid candidate checkout after
#                          manifest-risk: compare the charts and images of the
#                          candidate, main HEAD (MAIN_ROOT) and stable (STABLE_ROOT)
#   test-promote           fixture tests of ci/promote.py and of the two workflows
CANDIDATE ?= ../candidate
MAIN_ROOT ?= ../trusted
STABLE_ROOT ?= ../stable-src

.PHONY: promote-overlay promote-revert-check test-promote
test-scripts: test-promote

# Everything the commit tier reads as a rule, not as data under test. A path the
# trusted tree lacks is removed from the candidate. A symlink in the candidate
# is removed, never followed. Each copy is compared with the trusted one.
OVERLAY_PATHS = ci tests Makefile .githooks .gitleaks.toml .gitleaksignore .pipelinelintignore \
	.shellcheckrc .yamllint .yamllint.yaml .yamllint.yml renovate.json \
	.github/actionlint.yaml .github/actionlint.yml .github/zizmor.yml .github/zizmor.yaml

promote-overlay:
	test -d "$(CANDIDATE)"
	for p in $(OVERLAY_PATHS); do \
		parent="$$(dirname "$$p")"; \
		if [ "$$parent" != . ] && [ -L "$(CANDIDATE)/$$parent" ]; then rm "$(CANDIDATE)/$$parent"; fi; \
		rm -rf "$(CANDIDATE)/$$p"; \
		if [ -e "$$p" ] || [ -L "$$p" ]; then \
			mkdir -p "$(CANDIDATE)/$$parent"; \
			cp -a "$$p" "$(CANDIDATE)/$$p"; \
			diff -r --no-dereference "$$p" "$(CANDIDATE)/$$p" || exit 1; \
		elif [ -e "$(CANDIDATE)/$$p" ] || [ -L "$(CANDIDATE)/$$p" ]; then \
			echo "promote-overlay: $$p was not removed"; exit 1; \
		fi; \
	done

promote-revert-check:
	test -d out/head -a -d out/base
	python3 ci/render.py "$(MAIN_ROOT)" out/main-head
	python3 ci/promote.py deps --rendered out/head --repo-root . --out out/deps-candidate.json
	python3 ci/promote.py deps --rendered out/main-head --repo-root "$(MAIN_ROOT)" --out out/deps-head.json
	python3 ci/promote.py deps --rendered out/base --repo-root "$(STABLE_ROOT)" --out out/deps-stable.json
	python3 ci/promote.py revert-check --candidate out/deps-candidate.json --head out/deps-head.json \
		--stable out/deps-stable.json --out out/manifest-risk/revert.json

test-promote:
	tests/check-promote.py

# Clusters follow `stable` by default, and the kind run still tests the commit.
.PHONY: test-default-revision
test-scripts: test-default-revision

test-default-revision:
	tests/check-default-revision.py

# The daily watch of stable (.github/workflows/stable-watch.yaml). See
# ci/README.md "Stable watch". The two targets need the network and are not part
# of test-commit. Both read the verified record at WATCH_RECORD.
#   stable-watch-resolve  ask the registries for every image and chart digest
#                         (needs docker buildx and helm); writes out/resolved.json
#   stable-watch-scan     rescan the images by their registry digests; writes
#                         out/scan-results.json. Run make kev-catalog first.
#   stable-watch-report   decide from the downloaded results (out/stable, out/scan,
#                         out/resolved, out/lag.json); writes out/state.json and
#                         out/summary.md. It reads no network and writes no issue.
#   test-stable-watch     fixture tests of ci/stable_watch.py and of the workflow
WATCH_RECORD ?= out/stable/promotion-record.json

.PHONY: test-stable-watch stable-watch-resolve stable-watch-scan stable-watch-report
test-scripts: test-stable-watch

test-stable-watch:
	tests/check-stable-watch.py

stable-watch-resolve:
	python3 ci/stable_watch.py resolve --record "$(WATCH_RECORD)" --out out/resolved.json

stable-watch-scan:
	python3 ci/security_gate.py scan --record "$(WATCH_RECORD)" --out out/scan-results.json

stable-watch-report:
	python3 ci/stable_watch.py report --fetch out/stable/fetch.json --record "$(WATCH_RECORD)" \
		--scan out/scan/scan-results.json --kev out/scan/kev.json --resolved out/resolved/resolved.json \
		--lag out/lag.json --ignore ci/security-gate.trivyignore --out out/state.json --summary out/summary.md

# stable-watch-watchdog fails when the newest Stable watch run is older than 2
# days. tiers.yaml runs it on every push to main. It needs GH_TOKEN and
# GITHUB_REPOSITORY.
.PHONY: stable-watch-watchdog
stable-watch-watchdog:
	python3 ci/stable_watch.py watchdog --repo "$$GITHUB_REPOSITORY"
