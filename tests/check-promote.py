#!/usr/bin/env python3
"""Tests for the promote workflow: ci/promote.py, ci/promote-key.sh and the two workflow files.

A script is needed because the checks run the tools as programs on small
fixtures and read the workflow files as data; no declarative tool does that.
The cases cover the candidate rule (a candidate younger than 7 days is never
chosen on the weekly run), the revert check, the fallback to an older
candidate, the final re-validation, and the trust rules of the workflows
(pinned actions, no secret or write permission where candidate data is handled).

    tests/check-promote.py
"""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "ci/promote.py"
KEY_SCRIPT = ROOT / "ci/promote-key.sh"
WORKFLOWS = ROOT / ".github/workflows"
sys.path.insert(0, str(ROOT / "ci"))
import promote  # noqa: E402
import yaml  # noqa: E402

NOW = datetime(2026, 11, 15, 22, 0, tzinfo=timezone.utc)
STABLE = "5" * 40
CANDIDATE = "c" * 40


def sha(n):
    return f"{n:040x}"


def at(days):
    return promote.iso(NOW - timedelta(days=days))


def commits(*ages):
    """Newest first. An age is days before NOW, or None for an unknown time."""
    return [{"sha": sha(i + 1), "landedAt": None if a is None else at(a)} for i, a in enumerate(ages)]


class CandidateRule(unittest.TestCase):
    def pick(self, *ages, limit=3):
        return promote.decide_selection(commits(*ages), "behind", NOW, "", limit)

    def shas(self, result):
        return [c["sha"] for c in result["candidates"]]

    def test_picks_the_newest_commit_at_least_7_days_old(self):
        r = self.pick(0.5, 3, 6.9, 7.5, 9, 12)
        self.assertEqual(self.shas(r), [sha(4), sha(5), sha(6)])

    def test_exactly_7_days_is_old_enough_and_one_second_less_is_not(self):
        self.assertEqual(self.shas(self.pick(7)), [sha(1)])
        self.assertEqual(self.shas(self.pick(7 - 1 / 86400)), [])

    def test_a_commit_younger_than_7_days_is_never_chosen(self):
        for ages in [(0,), (1, 2, 3), (6.99, 8), (0.1, 6, 6.5, 30), (None, 9), (3, None, 20)]:
            r = self.pick(*ages)
            cutoff = NOW - timedelta(days=7)
            for c in r["candidates"]:
                self.assertLessEqual(promote.parse_time(c["landedAt"]), cutoff, ages)

    def test_nothing_is_old_enough(self):
        r = self.pick(1, 2, 6)
        self.assertEqual((r["action"], r["candidates"]), ("nothing", []))

    def test_an_unknown_landing_time_counts_as_now(self):
        r = self.pick(10, None, 20)
        self.assertEqual(self.shas(r), [sha(3)])

    def test_an_early_claim_cannot_hide_a_younger_change_below_it(self):
        # The newest commit claims 30 days, but the commit under it landed 2 days ago.
        r = self.pick(30, 2, 40)
        self.assertEqual(self.shas(r), [sha(3)])

    def test_at_most_the_limit_and_newest_first(self):
        r = self.pick(8, 9, 10, 11, 12)
        self.assertEqual(self.shas(r), [sha(1), sha(2), sha(3)])
        self.assertEqual(r["eligibleCount"], 5)

    def test_stable_at_or_ahead_of_main_does_nothing(self):
        r = promote.decide_selection(commits(9), "ahead", NOW)
        self.assertEqual(r["action"], "nothing")
        self.assertIn("ahead", r["nothingReason"])

    def test_no_commit_since_stable_does_nothing(self):
        self.assertEqual(promote.decide_selection([], "behind", NOW)["action"], "nothing")


class FastPath(unittest.TestCase):
    def test_a_reason_promotes_main_head_at_once(self):
        r = promote.decide_selection(commits(0.2, 8, 9), "behind", NOW, "fix CVE")
        self.assertEqual([c["sha"] for c in r["candidates"]], [sha(1)])
        self.assertEqual(r["mode"], "fast-path")
        self.assertFalse(r["aggregateApproval"])

    def test_a_young_commit_besides_the_fix_asks_for_the_aggregate_diff(self):
        r = promote.decide_selection(commits(0.2, 3, 9), "behind", NOW, "fix CVE")
        self.assertTrue(r["aggregateApproval"])
        self.assertEqual(r["youngerCommits"], [sha(2)])

    def test_the_fast_path_still_does_nothing_when_stable_is_current(self):
        self.assertEqual(promote.decide_selection(commits(0.2), "ahead", NOW, "fix")["action"], "nothing")

    def test_the_reason_is_cleaned(self):
        self.assertEqual(promote.clean_reason("a\nb\x00c" + "x" * 400)[:5], "a b c")
        self.assertEqual(len(promote.clean_reason("x" * 400)), promote.REASON_LIMIT)


class SelectProgram(unittest.TestCase):
    def run_select(self, data, reason=""):
        with tempfile.TemporaryDirectory() as d:
            f, out, gh = Path(d, "c.json"), Path(d, "select.json"), Path(d, "gh-output")
            f.write_text(json.dumps(data))
            env = {**os.environ, "GITHUB_OUTPUT": str(gh)}
            res = subprocess.run([sys.executable, str(TOOL), "select", "--commits-file", str(f), "--now", promote.iso(NOW),
                                  "--fast-path-reason", reason, "--out", str(out)],
                                 capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0, res.stderr)
            outputs = dict(line.split("=", 1) for line in gh.read_text().splitlines())
            return json.loads(out.read_text()), outputs

    def test_weekly_run_outputs_only_old_candidates(self):
        sel, out = self.run_select({"stable": STABLE, "head": sha(1), "commits": commits(1, 8, 9, 10, 11)})
        self.assertEqual((out["candidate_1"], out["candidate_2"], out["candidate_3"]), (sha(2), sha(3), sha(4)))
        self.assertEqual(out["nothing_to_do"], "false")
        self.assertEqual(sel["stableSha"], STABLE)

    def test_nothing_eligible_is_a_clean_run_with_no_candidate(self):
        _, out = self.run_select({"stable": STABLE, "head": sha(1), "commits": commits(1, 2)})
        self.assertEqual((out["nothing_to_do"], out["candidate_1"]), ("true", ""))

    def test_fast_path_outputs_main_head_only(self):
        _, out = self.run_select({"stable": STABLE, "head": sha(1), "commits": commits(0.1, 9)}, "fix")
        self.assertEqual((out["candidate_1"], out["candidate_2"], out["mode"]), (sha(1), "", "fast-path"))


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "no git")
class GitHistory(unittest.TestCase):
    """select against a real git history, with a stand-in `gh` that answers from a table."""

    def git(self, repo, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env).stdout.strip()

    def build(self, tmp, merged_days):
        """stable, then one commit per entry of merged_days (oldest first); a branch commit is merged
        into main by a merge commit whose pull request merged that many days ago (None: no pull request)."""
        repo = Path(tmp, "repo")
        repo.mkdir()
        self.git(repo, "init", "-q", "-b", "main")
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "stable")
        stable = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "update-ref", "refs/remotes/origin/stable", stable)
        table = {}
        for i, days in enumerate(merged_days):
            self.git(repo, "checkout", "-q", "-b", f"pr{i}")
            self.git(repo, "commit", "-q", "--allow-empty", "-m", f"change {i}")
            self.git(repo, "checkout", "-q", "main")
            self.git(repo, "merge", "-q", "--no-ff", "-m", f"Merge pr{i}", f"pr{i}")
            head = self.git(repo, "rev-parse", "HEAD")
            if days is None:
                table[head] = []
            elif days == "other-merge-commit":
                table[head] = [{"merged_at": at(20), "merge_commit_sha": "f" * 40, "base": {"ref": "main"}}]
            else:
                table[head] = [{"merged_at": at(days), "merge_commit_sha": head, "base": {"ref": "main"}}]
        fake = Path(tmp, "bin")
        fake.mkdir()
        Path(tmp, "table.json").write_text(json.dumps(table))
        (fake / "gh").write_text(
            "#!/usr/bin/env python3\n"
            "import json, re, sys\n"
            "sha = re.search(r'commits/([a-f0-9]+)/pulls', ' '.join(sys.argv)).group(1)\n"
            f"print(json.dumps(json.load(open('{tmp}/table.json'))[sha]))\n")
        (fake / "gh").chmod(0o755)
        return repo, stable, self.git(repo, "rev-parse", "HEAD"), fake

    def select(self, merged_days, reason=""):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, head, fake = self.build(tmp, merged_days)
            out = Path(tmp, "select.json")
            res = subprocess.run([sys.executable, str(TOOL), "select", "--repo-root", str(repo), "--head", head,
                                  "--repo", "o/r", "--now", promote.iso(NOW), "--fast-path-reason", reason, "--out", str(out)],
                                 capture_output=True, text=True, env={**os.environ, "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"})
            self.assertEqual(res.returncode, 0, res.stderr)
            return json.loads(out.read_text()), stable, head

    def test_the_candidate_is_a_merge_commit_that_landed_a_week_ago(self):
        sel, stable, head = self.select([12, 9, 8, 2, 0.5])
        self.assertEqual(sel["stableSha"], stable)
        self.assertEqual(len(sel["candidates"]), 3)
        for c in sel["candidates"]:
            self.assertLessEqual(promote.parse_time(c["landedAt"]), NOW - timedelta(days=7))
        self.assertNotEqual(sel["candidates"][0]["sha"], head)

    def test_a_merge_without_a_pull_request_is_not_old_enough(self):
        sel, _, _ = self.select([12, None, 9])
        self.assertEqual(sel["candidates"][0]["known"], True)
        self.assertEqual(len(sel["candidates"]), 1)

    def test_a_pull_request_whose_merge_commit_is_another_commit_does_not_count(self):
        sel, _, _ = self.select([12, "other-merge-commit", 9])
        self.assertEqual(len(sel["candidates"]), 1)
        self.assertEqual(promote.parse_time(sel["candidates"][0]["landedAt"]), promote.parse_time(at(12)))

    def test_nothing_old_enough_yet(self):
        sel, _, _ = self.select([3, 1])
        self.assertEqual(sel["action"], "nothing")

    def test_stable_at_main_head_does_nothing(self):
        sel, _, _ = self.select([])
        self.assertEqual(sel["action"], "nothing")

    def test_fast_path_takes_main_head(self):
        sel, _, head = self.select([12, 0.2], "fix")
        self.assertEqual([c["sha"] for c in sel["candidates"]], [head])
        self.assertFalse(sel["aggregateApproval"])


def needs(results, approvals=("", "", ""), shas=(sha(1), sha(2), sha(3)), jobs=None, failed=("", "", "")):
    """The shape of toJSON(needs) in the choose job. results: the inner result output of each
    candidate ('pass', 'fail' or None for a candidate that did not run)."""
    n = {"select": {"result": "success", "outputs": {f"candidate_{i + 1}": sha_ for i, sha_ in enumerate(shas)}}}
    for i, r in enumerate(results):
        if r is None:
            n[f"candidate-{i + 1}"] = {"result": "skipped", "outputs": {}}
            continue
        job = (jobs or {}).get(i, "success" if r == "pass" else "failure")
        outputs = {"result": r, "needs_approval": approvals[i], "failed": failed[i],
                   "scanned_digest": f"{i + 1}" * 64, "risk_digest": f"{i + 4}" * 64}
        n[f"candidate-{i + 1}"] = {"result": job, "outputs": outputs}
    return n


class Fallback(unittest.TestCase):
    def test_the_first_pass_wins(self):
        picked, _ = promote.choose(needs(["pass", None, None], ["false", "", ""]))
        self.assertEqual((picked["slot"], picked["sha"], picked["needs_approval"]), (1, sha(1), "false"))

    def test_a_failed_candidate_hands_over_to_the_next_older_one(self):
        picked, rows = promote.choose(needs(["fail", "pass", None], ["", "true", ""], failed=("tests(failure)", "", "")))
        self.assertEqual((picked["slot"], picked["sha"]), (2, sha(2)))
        self.assertEqual(picked["scanned_digest"], "2" * 64)
        self.assertEqual(picked["risk_digest"], "5" * 64)
        self.assertEqual(rows[0]["failed"], "tests(failure)")
        picked, _ = promote.choose(needs(["fail", "fail", "pass"], ["", "", "false"]))
        self.assertEqual(picked["slot"], 3)

    def test_nothing_passes(self):
        self.assertIsNone(promote.choose(needs(["fail", "fail", "fail"]))[0])
        self.assertIsNone(promote.choose(needs([None, None, None], shas=("", "", "")))[0])

    def test_a_missing_or_odd_approval_value_means_approval_is_needed(self):
        for value in ("", "FALSE", "no"):
            self.assertEqual(promote.choose(needs(["pass", None, None], [value, "", ""]))[0]["needs_approval"], "true")

    def test_a_job_that_did_not_succeed_is_never_chosen_even_if_its_output_says_pass(self):
        for outcome in ("failure", "cancelled", "skipped"):
            self.assertIsNone(promote.choose(needs(["pass", None, None], jobs={0: outcome}))[0], outcome)

    def test_a_candidate_without_a_selected_commit_is_never_chosen(self):
        self.assertIsNone(promote.choose(needs(["pass", None, None], shas=("", "", "")))[0])

    def test_the_program_reads_needs_from_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "o")
            res = subprocess.run([sys.executable, str(TOOL), "choose"], capture_output=True, text=True,
                                 env={**os.environ, "GITHUB_OUTPUT": str(out),
                                      "NEEDS_JSON": json.dumps(needs(["fail", "pass", None], ["", "false", ""]))})
            self.assertEqual(res.returncode, 0, res.stderr)
            values = dict(line.split("=", 1) for line in out.read_text().splitlines())
            self.assertEqual((values["slot"], values["sha"], values["needs_approval"]), ("2", sha(2), "false"))
            self.assertIn("failure", res.stdout)


def deps(images=(), charts=()):
    return {"images": list(images), "charts": [list(c) for c in charts]}


class RevertCheck(unittest.TestCase):
    def check(self, candidate, head, stable):
        return promote.revert_check(candidate, head, stable)

    def test_a_chart_main_dropped_is_a_revert(self):
        r = self.check(deps(charts=[("https://h", "grafana", "7.0.0")]), deps(), deps())
        self.assertTrue(r["blocked"])
        self.assertEqual(r["reverted"][0]["name"], "https://h grafana")

    def test_a_chart_main_downgraded_is_a_revert(self):
        r = self.check(deps(charts=[("https://h", "g", "7.1.0")]), deps(charts=[("https://h", "g", "7.0.0")]),
                       deps(charts=[("https://h", "g", "6.9.0")]))
        self.assertTrue(r["blocked"])

    def test_a_newer_chart_at_main_is_an_ordinary_update(self):
        r = self.check(deps(charts=[("https://h", "g", "7.1.0")]), deps(charts=[("https://h", "g", "7.2.0")]), deps())
        self.assertFalse(r["blocked"])

    def test_numbers_are_compared_not_text(self):
        r = self.check(deps(charts=[("https://h", "g", "9.0.0")]), deps(charts=[("https://h", "g", "10.0.0")]), deps())
        self.assertFalse(r["blocked"])

    def test_what_stable_has_is_not_a_revert(self):
        r = self.check(deps(charts=[("https://h", "g", "7.0.0")]), deps(), deps(charts=[("https://h", "g", "7.0.0")]))
        self.assertFalse(r["blocked"])

    def test_what_main_still_has_is_not_a_revert(self):
        r = self.check(deps(images=["quay.io/a/b:1.2.3"]), deps(images=["quay.io/a/b:1.2.3"]), deps())
        self.assertFalse(r["blocked"])

    def test_an_image_tag_main_dropped_is_a_revert(self):
        r = self.check(deps(images=["quay.io/a/b:1.2.3"]), deps(images=["quay.io/other/x:1"]), deps(images=["quay.io/a/b:1.0.0"]))
        self.assertTrue(r["blocked"])
        self.assertEqual(r["reverted"][0]["stableVersions"], ["1.0.0"])

    def test_an_image_with_a_newer_tag_at_main_is_fine(self):
        r = self.check(deps(images=["quay.io/a/b:v1.2.3"]), deps(images=["quay.io/a/b:v1.3.0"]), deps(images=["quay.io/a/b:v1.0.0"]))
        self.assertFalse(r["blocked"])

    def test_a_registry_port_is_not_read_as_a_tag(self):
        r = self.check(deps(images=["localhost:5000/a/b:1"]), deps(images=["localhost:5000/a/b:2"]), deps())
        self.assertFalse(r["blocked"])

    def test_a_digest_cannot_be_ordered_and_counts_as_a_revert(self):
        d1, d2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        r = self.check(deps(images=[f"quay.io/a/b@{d1}"]), deps(images=[f"quay.io/a/b@{d2}"]), deps())
        self.assertTrue(r["blocked"])

    def test_a_tag_without_numbers_counts_as_a_revert(self):
        r = self.check(deps(images=["quay.io/a/b:stable"]), deps(images=["quay.io/a/b:latest"]), deps())
        self.assertTrue(r["blocked"])

    def test_the_program_exits_1_when_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            for name, data in [("c", deps(charts=[("https://h", "g", "1.0.0")])), ("h", deps()), ("s", deps())]:
                Path(d, f"{name}.json").write_text(json.dumps(data))
            res = subprocess.run([sys.executable, str(TOOL), "revert-check", "--candidate", f"{d}/c.json",
                                  "--head", f"{d}/h.json", "--stable", f"{d}/s.json", "--out", f"{d}/r.json"],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)
            self.assertTrue(json.loads(Path(d, "r.json").read_text())["blocked"])


class Baseline(unittest.TestCase):
    def test_the_newest_published_stable_release_is_the_baseline(self):
        rel = [{"tagName": "stable-20261101"}, {"tagName": "stable-20261108-2"}, {"tagName": "stable-20261108"},
               {"tagName": "stable-20261115", "isDraft": True}, {"tagName": "v1"}, {"tagName": "stable-probe-1"},
               {"tagName": "stable-20261120", "isPrerelease": True}]
        self.assertEqual(promote.pick_baseline_tag(rel), "stable-20261108-2")
        self.assertEqual(promote.pick_baseline_tag([]), "")

    def run_baseline(self, releases, *flags):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "r.json").write_text(json.dumps(releases))
            out = Path(d, "out")
            res = subprocess.run([sys.executable, str(TOOL), "baseline", "--releases", f"{d}/r.json", *flags],
                                 capture_output=True, text=True, env={**os.environ, "GITHUB_OUTPUT": str(out)})
            return res.returncode, (out.read_text() if out.exists() else "")

    def test_no_release_without_the_flag_stops_the_run(self):
        self.assertNotEqual(self.run_baseline([])[0], 0)

    def first(self, stable, tags=""):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "t.txt").write_text(tags)
            return self.run_baseline([], "--first-promotion", "--stable-sha", stable, "--tags", f"{d}/t.txt")

    def test_the_first_promotion_flag_with_no_release_is_allowed_at_the_initial_commit(self):
        code, out = self.first(promote.INITIAL_STABLE)
        self.assertEqual(code, 0)
        self.assertIn("first_promotion=true", out)

    def test_the_first_promotion_is_refused_when_a_stable_tag_exists(self):
        code, _ = self.first(promote.INITIAL_STABLE, f"{'a' * 40}\trefs/tags/stable-20261101\n")
        self.assertNotEqual(code, 0)

    def test_the_first_promotion_is_refused_when_stable_has_moved(self):
        self.assertNotEqual(self.first("7" * 40)[0], 0)

    def test_the_first_promotion_is_refused_without_the_stable_commit_and_tag_list(self):
        self.assertNotEqual(self.run_baseline([], "--first-promotion")[0], 0)

    def test_the_initial_commit_is_the_documented_one(self):
        self.assertEqual(promote.INITIAL_STABLE, "26229cc6fb30845eb7b323d80e113ae5d83012ef")

    def test_the_first_promotion_flag_with_a_release_is_refused(self):
        self.assertNotEqual(self.run_baseline([{"tagName": "stable-20261101"}], "--first-promotion")[0], 0)

    def test_a_release_is_the_baseline(self):
        code, out = self.run_baseline([{"tagName": "stable-20261101"}])
        self.assertEqual(code, 0)
        self.assertIn("baseline_tag=stable-20261101", out)

    def test_the_baseline_record_must_be_for_the_stable_commit(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "r.json").write_text(json.dumps({"commit": STABLE}))
            ok = subprocess.run([sys.executable, str(TOOL), "check-baseline", "--record", f"{d}/r.json", "--stable-sha", STABLE])
            bad = subprocess.run([sys.executable, str(TOOL), "check-baseline", "--record", f"{d}/r.json", "--stable-sha", "6" * 40],
                                 capture_output=True)
            self.assertEqual((ok.returncode, bad.returncode != 0), (0, True))


def valid_record(commit=CANDIDATE, baseline=STABLE):
    digest = "sha256:" + "a" * 64
    return {
        "schemaVersion": 2, "commit": commit,
        "images": [{"reference": "docker.io/library/redis:7", "digest": digest, "digestSource": "registry", "sources": ["rendered"],
                    "runtimeDigests": [], "runtimeDiffers": False}],
        "charts": [{"name": "g", "version": "1.0.0", "repository": "https://h", "digest": digest}],
        "notScanned": [],
        "scanner": {"name": "trivy", "version": "0.60.0", "databaseUpdatedAt": at(0.2)},
        "scan": {"scannedAt": at(0.1), "verdict": "pass", "baselineCommit": baseline, "imagesListed": 1, "imagesScanned": 1,
                 "counts": {"blocking": 0, "known": 0, "ignored": 0, "kev": 0, "otherSeverities": 0},
                 "reasons": [], "exemptions": [], "findings": []},
    }


def valid_selection(mode="weekly", reason=""):
    return {"schemaVersion": 1, "action": "promote", "mode": mode, "fastPathReason": reason, "soakDays": 7,
            "stableSha": STABLE, "headSha": "d" * 40, "aggregateApproval": False, "youngerCommits": [],
            "candidates": [{"sha": CANDIDATE, "landedAt": at(8), "known": True}]}


RISK = {"schemaVersion": 1, "needsApproval": False, "additionCount": 0, "removalCount": 0, "additions": [], "removals": []}
REVERT = {"schemaVersion": 1, "blocked": False, "reverted": []}


class Verify(unittest.TestCase):
    def verify(self, sel=None, record=None, risk=None, revert=None, candidate=CANDIDATE, stable=STABLE, **kw):
        return promote.verify(valid_selection() if sel is None else sel, valid_record() if record is None else record,
                              RISK if risk is None else risk, REVERT if revert is None else revert,
                              candidate, stable, NOW, **kw)

    def test_a_clean_result_passes(self):
        self.assertEqual(self.verify(), [])

    def test_the_first_promotion_expects_no_baseline(self):
        self.assertEqual(self.verify(record=valid_record(baseline=None), first_promotion=True), [])
        self.assertTrue(self.verify(record=valid_record(baseline=None)))
        self.assertTrue(self.verify(first_promotion=True))

    def test_a_record_for_another_commit_fails(self):
        self.assertTrue(self.verify(record=valid_record(commit="e" * 40)))

    def test_a_block_verdict_fails(self):
        r = valid_record()
        r["scan"]["verdict"] = "block"
        r["scan"]["reasons"] = ["new HIGH"]
        self.assertTrue(self.verify(record=r))

    def test_a_record_without_a_scan_fails(self):
        r = valid_record()
        del r["scan"]
        self.assertTrue(self.verify(record=r))

    def test_a_record_that_breaks_the_schema_fails(self):
        r = valid_record()
        r["images"][0]["digest"] = "nope"
        self.assertTrue(self.verify(record=r))

    def test_fewer_images_scanned_than_listed_fails(self):
        r = valid_record()
        r["scan"]["imagesScanned"] = 0
        self.assertTrue(self.verify(record=r))

    def test_a_blocking_finding_fails_even_with_a_pass_verdict(self):
        r = valid_record()
        r["scan"]["findings"] = [{"image": "docker.io/library/redis", "id": "CVE-2026-1", "package": "p", "installedVersion": "1",
                                  "fixedVersion": "2", "severity": "HIGH", "kev": False, "status": "blocking"}]
        self.assertTrue(self.verify(record=r))

    def test_a_delta_against_another_baseline_fails(self):
        self.assertTrue(self.verify(record=valid_record(baseline="7" * 40)))

    def test_stable_moving_since_the_selection_fails(self):
        self.assertTrue(self.verify(stable="6" * 40))

    def test_a_stale_scan_fails(self):
        r = valid_record()
        r["scan"]["scannedAt"] = at(4)
        problems = self.verify(record=r)
        self.assertTrue(any("hours old" in p for p in problems))

    def test_a_candidate_the_selection_did_not_choose_fails(self):
        self.assertTrue(self.verify(candidate="e" * 40, record=valid_record(commit="e" * 40)))

    def test_a_weekly_candidate_younger_than_the_soak_fails(self):
        sel = valid_selection()
        sel["candidates"][0]["landedAt"] = at(6)
        self.assertTrue(any("younger" in p for p in self.verify(sel=sel)))

    def test_a_fast_path_candidate_may_be_young_but_needs_a_reason(self):
        sel = valid_selection("fast-path", "fix")
        sel["candidates"][0]["landedAt"] = at(0.1)
        self.assertEqual(self.verify(sel=sel), [])
        sel["fastPathReason"] = ""
        self.assertTrue(self.verify(sel=sel))

    def test_a_selection_that_says_nothing_to_do_fails(self):
        sel = valid_selection()
        sel["action"] = "nothing"
        self.assertTrue(self.verify(sel=sel))

    def test_a_blocked_revert_check_fails(self):
        self.assertTrue(self.verify(revert={"schemaVersion": 1, "blocked": True, "reverted": [{"name": "x"}]}))
        self.assertTrue(self.verify(revert={}))

    def test_a_manifest_risk_result_that_contradicts_itself_fails(self):
        self.assertTrue(self.verify(risk={**RISK, "needsApproval": False, "additionCount": 2}))
        self.assertTrue(self.verify(risk={**RISK, "needsApproval": "false"}))
        self.assertEqual(self.verify(risk={**RISK, "needsApproval": True, "additionCount": 2}), [])


class Texts(unittest.TestCase):
    def test_the_tag_name_takes_the_next_free_suffix(self):
        day = datetime(2026, 11, 15, tzinfo=timezone.utc)
        self.assertEqual(promote.next_tag(day, []), "stable-20261115")
        self.assertEqual(promote.next_tag(day, ["stable-20261115"]), "stable-20261115-2")
        self.assertEqual(promote.next_tag(day, ["stable-20261115", "stable-20261115-2"]), "stable-20261115-3")
        with self.assertRaises(SystemExit):
            promote.next_tag(day, ["stable-20261115"] + [f"stable-20261115-{n}" for n in range(2, 10)])

    def test_long_text_is_cut_on_a_line_end(self):
        text = "\n".join(f"row {i}" for i in range(1000))
        cut = promote.cut(text, 500)
        self.assertLess(len(cut), 700)
        self.assertIn("cut at 500", cut)
        self.assertEqual(promote.cut("short", 500), "short")

    def test_an_output_with_a_line_break_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["GITHUB_OUTPUT"] = f"{d}/o"
            try:
                with self.assertRaises(SystemExit):
                    promote.set_output(x="a\nb=c")
            finally:
                del os.environ["GITHUB_OUTPUT"]


@unittest.skipUnless(shutil.which("ssh-agent") and shutil.which("ssh-keygen") and shutil.which("ssh-add"), "no ssh tools")
class KeyScript(unittest.TestCase):
    def test_the_key_goes_into_an_agent_and_never_into_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp, "k_test")
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            private = key.read_text()
            runner, env_file = Path(tmp, "runner"), Path(tmp, "env")
            runner.mkdir()
            env = {**os.environ, "RUNNER_TEMP": str(runner), "GITHUB_ENV": str(env_file), "PROMOTE_DEPLOY_KEY": private}
            res = subprocess.run(["bash", str(KEY_SCRIPT), "load"], env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            exported = dict(line.split("=", 1) for line in env_file.read_text().splitlines())
            try:
                self.assertNotIn(private.splitlines()[1], env_file.read_text())
                for f in runner.rglob("*"):
                    if f.is_file():
                        self.assertNotIn("PRIVATE KEY", f.read_text(errors="ignore"), f)
                listed = subprocess.run(["ssh-add", "-l"], env={**os.environ, "SSH_AUTH_SOCK": exported["SSH_AUTH_SOCK"]},
                                        capture_output=True, text=True)
                self.assertEqual(listed.returncode, 0, listed.stderr)
                self.assertIn("StrictHostKeyChecking=yes", exported["GIT_SSH_COMMAND"])
                self.assertIn("HostKeyAlgorithms=ssh-ed25519", exported["GIT_SSH_COMMAND"])
            finally:
                subprocess.run(["bash", str(KEY_SCRIPT), "unload"], env={**env, "SSH_AGENT_PID": exported["SSH_AGENT_PID"]})
            self.assertFalse(Path(runner, "promote-ssh").exists())

    def test_the_script_has_the_published_github_host_key_form(self):
        text = KEY_SCRIPT.read_text()
        self.assertRegex(text, r"github\.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI")


def load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def steps_of(job):
    return job.get("steps", [])


def uses_of(doc):
    return [s["uses"] for j in doc["jobs"].values() for s in steps_of(j) if "uses" in s]


class WorkflowRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tiers = load("tiers.yaml")
        cls.promote = load("promote.yaml")
        cls.candidate = load("promote-candidate.yaml")
        cls.texts = {n: (WORKFLOWS / n).read_text(encoding="utf-8") for n in ("promote.yaml", "promote-candidate.yaml")}

    def test_every_action_is_pinned_and_matches_tiers(self):
        tier_pins = {u.split("@")[0]: u for u in uses_of(self.tiers)}
        for doc in (self.promote, self.candidate):
            for use in uses_of(doc):
                if use.startswith("./"):
                    continue
                name, _, ref = use.partition("@")
                self.assertRegex(ref, r"^[a-f0-9]{40}$", use)
                if name in tier_pins:
                    self.assertEqual(use, tier_pins[name])

    def test_the_container_image_is_the_one_tiers_pins(self):
        images = {j["container"] for j in self.tiers["jobs"].values() if "container" in j}
        images |= {j["container"] for j in self.candidate["jobs"].values() if "container" in j}
        images |= {j["container"] for j in self.promote["jobs"].values() if "container" in j}
        self.assertEqual(len(images), 1, images)

    def test_the_helm_version_matches_tiers(self):
        def helm(doc):
            return {s["with"]["version"] for u in doc["jobs"].values() for s in steps_of(u)
                    if s.get("uses", "").startswith("azure/setup-helm")}
        self.assertEqual(helm(self.candidate), helm(self.tiers))

    def test_the_schedule_is_sunday_22_utc(self):
        self.assertEqual(self.promote[True]["schedule"], [{"cron": "0 22 * * 0"}])
        inputs = self.promote[True]["workflow_dispatch"]["inputs"]
        self.assertEqual(set(inputs), {"dry_run", "fast_path_reason", "first_promotion", "prove_key"})

    def test_the_default_token_is_read_only_except_where_a_job_needs_more(self):
        for doc in (self.promote, self.candidate):
            self.assertEqual(doc["permissions"], {})
            for name, job in doc["jobs"].items():
                self.assertIn("permissions", job, name)
        for name, job in self.candidate["jobs"].items():
            self.assertNotIn("environment", job, name)
            self.assertLessEqual(set(job["permissions"].items()), {("contents", "read")}, name)
        writers = {n for n, j in self.promote["jobs"].items() if j.get("permissions", {}).get("contents") == "write"}
        self.assertEqual(writers, {"promote", "key-proof-outside"})

    def test_only_the_promote_environment_jobs_see_the_deploy_key(self):
        for name, text in self.texts.items():
            holders = [j for j, job in (yaml.safe_load(text)["jobs"]).items() if "PROMOTE_DEPLOY_KEY" in json.dumps(job)]
            if name == "promote-candidate.yaml":
                self.assertEqual(holders, [])
            else:
                self.assertEqual(sorted(holders), ["key-proof", "promote"])
        for job in ("promote", "key-proof"):
            self.assertEqual(self.promote["jobs"][job]["environment"], "promote")
        with_env = {n for n, j in self.promote["jobs"].items() if "environment" in j}
        self.assertEqual(with_env, {"promote", "key-proof"})

    def test_the_key_is_given_to_one_step_only(self):
        for job in ("promote", "key-proof"):
            holders = [s for s in steps_of(self.promote["jobs"][job]) if "PROMOTE_DEPLOY_KEY" in json.dumps(s)]
            self.assertEqual(len(holders), 1, job)
            self.assertEqual(holders[0]["run"], "ci/promote-key.sh load")
            self.assertNotIn("PROMOTE_DEPLOY_KEY", json.dumps(self.promote["jobs"][job].get("env", {})))

    def test_only_the_scan_step_gets_the_docker_hub_token(self):
        for name, job in self.candidate["jobs"].items():
            holders = [s.get("name", s.get("run", "")) for s in steps_of(job) if "DOCKERHUB_TOKEN" in json.dumps(s)]
            self.assertEqual(len(holders), 1 if name == "scan" else 0, name)
        for name, job in self.promote["jobs"].items():
            if not name.startswith("candidate-"):
                self.assertNotIn("DOCKERHUB", json.dumps(job), name)

    def test_no_final_job_checks_out_candidate_code(self):
        for name in ("select", "choose", "dry-run", "promote", "key-proof", "key-proof-outside"):
            for s in steps_of(self.promote["jobs"][name]):
                if s.get("uses", "").startswith("actions/checkout"):
                    self.assertNotIn("ref", s.get("with", {}), name)
                    self.assertIs(s["with"]["persist-credentials"], False, name)

    def test_candidate_jobs_check_out_the_candidate_beside_a_trusted_copy_and_overlay_it(self):
        for name, job in self.candidate["jobs"].items():
            checkouts = [s["with"] for s in steps_of(job) if s.get("uses", "").startswith("actions/checkout")]
            for c in checkouts:
                self.assertIs(c["persist-credentials"], False, name)
            with_candidate = [c for c in checkouts if "ref" in c]
            if with_candidate:
                self.assertEqual(with_candidate[0]["ref"], "${{ inputs.candidate }}", name)
                self.assertEqual(with_candidate[0]["path"], "candidate", name)
                self.assertTrue(any(c.get("path") == "trusted" and "ref" not in c for c in checkouts), name)
                self.assertTrue(any(s.get("run") == "make -C trusted promote-overlay" for s in steps_of(job)), name)

    def test_the_scan_job_never_checks_out_the_candidate(self):
        for s in steps_of(self.candidate["jobs"]["scan"]):
            self.assertNotIn("ref", s.get("with", {}) if s.get("uses", "").startswith("actions/checkout") else {})

    def test_the_candidate_chain_stops_after_a_pass(self):
        self.assertIn("candidate-1.outputs.result != 'pass'", self.promote["jobs"]["candidate-2"]["if"])
        three = self.promote["jobs"]["candidate-3"]["if"]
        self.assertIn("candidate-1.outputs.result != 'pass'", three)
        self.assertIn("candidate-2.outputs.result != 'pass'", three)

    def test_the_real_promotion_needs_the_chooser_and_is_not_a_dry_run(self):
        job = self.promote["jobs"]["promote"]
        self.assertIn("!inputs.dry_run", job["if"])
        self.assertIn("needs.choose.result == 'success'", job["if"])
        self.assertIn("inputs.dry_run", self.promote["jobs"]["dry-run"]["if"])
        self.assertEqual(self.promote["jobs"]["dry-run"]["permissions"], {"contents": "read"})
        self.assertNotIn("environment", self.promote["jobs"]["dry-run"])

    def test_the_promote_job_pushes_the_tag_before_the_branch_and_publishes_last(self):
        order = [s.get("id") for s in steps_of(self.promote["jobs"]["promote"]) if s.get("id")]
        self.assertEqual(order, ["prepare", "immutable", "load", "tag", "attest", "draft", "push", "publish",
                                 "undo_release", "undo_tag"])

    def test_the_trusted_jobs_run_only_on_main(self):
        self.assertIn("refs/heads/main", self.promote["jobs"]["select"]["if"])
        self.assertIn("refs/heads/main", self.promote["jobs"]["key-proof"]["if"])

    def test_no_run_step_puts_an_expression_in_the_script(self):
        for name, doc in (("promote", self.promote), ("candidate", self.candidate)):
            for job_name, job in doc["jobs"].items():
                for s in steps_of(job):
                    run = s.get("run", "")
                    for expr in re.findall(r"\$\{\{(.*?)\}\}", run):
                        self.assertRegex(expr.strip(), r"^(inputs\.(slot|candidate|stable_sha)|github\.run_id)$",
                                         f"{name}/{job_name}: {expr}")


    def test_no_pip_install_without_hashes(self):
        for name, text in self.texts.items():
            for line in text.splitlines():
                if "pip install" in line and not line.lstrip().startswith("#"):
                    self.assertIn("--require-hashes", line, f"{name}: {line.strip()}")
                    self.assertIn("-r trusted/ci/requirements-promote.txt", line, name)

    def test_the_requirements_file_pins_every_package_with_hashes(self):
        lines = (ROOT / "ci/requirements-promote.txt").read_text().splitlines()
        pins = [i for i, line in enumerate(lines) if re.match(r"^[A-Za-z0-9_.-]+==", line)]
        self.assertGreaterEqual(len(pins), 2)
        for i in pins:
            self.assertTrue(lines[i].endswith("\\"), lines[i])
            self.assertIn("--hash=sha256:", lines[i + 1])

    def test_the_jobs_after_select_run_in_the_pinned_image(self):
        for name in ("choose", "dry-run", "promote", "key-proof"):
            self.assertEqual(self.promote["jobs"][name]["container"], self.tiers["jobs"]["commit"]["container"], name)

    def test_attestation_verification_pins_the_source_and_the_issuer(self):
        run = next(s["run"] for s in steps_of(self.promote["jobs"]["select"]) if s.get("id") == "baseline")
        self.assertIn("--source-ref refs/heads/main", run)
        self.assertIn("--cert-oidc-issuer https://token.actions.githubusercontent.com", run)
        self.assertIn("--signer-workflow", run)

    def test_immutability_is_required_before_the_key_is_loaded(self):
        ids = [s.get("id") for s in steps_of(self.promote["jobs"]["promote"])]
        self.assertLess(ids.index("immutable"), ids.index("load"))
        step = next(s for s in steps_of(self.promote["jobs"]["promote"]) if s.get("id") == "immutable")
        self.assertIn("IMMUTABLE_RELEASES_CONFIRMED", json.dumps(step))
        self.assertIn("exit 1", step["run"])

    def test_the_download_of_every_artifact_checks_its_digest(self):
        for name, doc in (("promote", self.promote), ("candidate", self.candidate)):
            for job_name, job in doc["jobs"].items():
                for s in steps_of(job):
                    if s.get("uses", "").startswith("actions/download-artifact"):
                        self.assertEqual(s["with"].get("digest-mismatch"), "error", f"{name}/{job_name}")

    def test_the_jobs_that_make_results_report_digests_and_consumers_get_them(self):
        outs = self.candidate["on"]["workflow_call"]["outputs"] if "on" in self.candidate else self.candidate[True]["workflow_call"]["outputs"]
        self.assertIn("scanned_digest", outs)
        self.assertIn("risk_digest", outs)
        for job in ("choose", "dry-run", "promote"):
            env = " ".join(json.dumps(s.get("env", {})) for s in steps_of(self.promote["jobs"][job]))
            for name in ("SELECT_DIGEST", "SCANNED_DIGEST", "RISK_DIGEST"):
                self.assertIn(name, env, job)

    def test_key_proof_deletes_its_tag_in_an_always_step(self):
        steps = steps_of(self.promote["jobs"]["key-proof"])
        delete = next(s for s in steps if s.get("name") == "Delete the throwaway tag")
        self.assertIn("always()", delete["if"])
        create = next(s for s in steps if s.get("id") == "create")
        self.assertNotIn("--delete", create["run"])

    def test_renovate_never_automerges_a_change_to_the_promote_files(self):
        config = json.loads((ROOT / "renovate.json").read_text())
        rules = [r for r in config["packageRules"] if "matchFileNames" in r]
        self.assertEqual(len(rules), 1)
        self.assertIs(rules[0]["automerge"], False)
        for path in (".github/workflows/promote.yaml", ".github/workflows/promote-candidate.yaml",
                     ".github/workflows/stable-watch.yaml", "ci/stable_watch.py", "ci/security_gate.py",
                     "ci/security-gate.trivyignore", "ci/manifest_risk.py", "ci/registry-allowlist.yaml",
                     "ci/promotion_record.py", "ci/promotion-record.schema.json"):
            self.assertIn(path, rules[0]["matchFileNames"])
        self.assertIn("pip-compile", config["enabledManagers"])

    def test_the_risk_job_waits_for_the_commit_tier(self):
        self.assertEqual(self.candidate["jobs"]["risk"]["needs"], "tests")


def evaluate(expression, outcomes, failed, cancelled):
    """Evaluate a step condition of the promote job for a given run."""
    expr = expression.strip()
    expr = re.sub(r"^\$\{\{|\}\}$", "", expr).strip()
    expr = re.sub(r"steps\.(\w+)\.outcome", lambda m: repr(outcomes.get(m.group(1), "skipped")), expr)
    expr = expr.replace("failure()", repr(failed)).replace("cancelled()", repr(cancelled))
    expr = expr.replace("&&", " and ").replace("||", " or ")
    return eval(expr, {"__builtins__": {}}, {})  # noqa: S307


class UndoConditions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        steps = steps_of(load("promote.yaml")["jobs"]["promote"])
        cls.cond = {s["id"]: s["if"] for s in steps if s.get("id") in ("undo_release", "undo_tag")}

    def undo(self, **outcomes):
        failed = any(v == "failure" for v in outcomes.values())
        cancelled = any(v == "cancelled" for v in outcomes.values())
        base = {"load": "success", "tag": "success", "draft": "success", "push": "success", "publish": "success"}
        base.update(outcomes)
        return (evaluate(self.cond["undo_release"], base, failed, cancelled),
                evaluate(self.cond["undo_tag"], base, failed, cancelled))

    def test_success_undoes_nothing(self):
        self.assertEqual(self.undo(), (False, False))

    def test_a_failed_tag_step_deletes_neither(self):
        self.assertEqual(self.undo(tag="failure", draft="skipped", push="skipped", publish="skipped"), (False, False))

    def test_a_failed_draft_deletes_the_tag_only(self):
        self.assertEqual(self.undo(draft="failure", push="skipped", publish="skipped"), (False, True))

    def test_a_failed_push_deletes_both(self):
        self.assertEqual(self.undo(push="failure", publish="skipped"), (True, True))

    def test_a_cancel_before_the_push_deletes_both(self):
        self.assertEqual(self.undo(push="cancelled", publish="skipped"), (True, True))
        self.assertEqual(self.undo(draft="cancelled", push="skipped", publish="skipped"), (False, True))

    def test_a_failed_publish_after_the_push_deletes_nothing(self):
        self.assertEqual(self.undo(publish="failure"), (False, False))

    def test_the_tag_is_not_deleted_if_the_key_never_loaded(self):
        self.assertEqual(self.undo(load="failure", tag="skipped", draft="skipped", push="skipped", publish="skipped"), (False, False))


class Escaping(unittest.TestCase):
    def test_markdown_html_and_mentions_are_escaped(self):
        out = promote.escape_text("fix <img src=x onerror=1> [a](http://x) @owner `c` | *b* _i_ #1 ![i] \\ &amp;\nnew")
        bare = re.sub(r"&(#\d+|amp|lt|gt);", "", out)
        for bad in ("<", ">", "[", "]", "`", "|", "*", "_", "#", "!", "\\", "&"):
            self.assertNotIn(bad, bare)
        self.assertNotIn("@owner", out)
        self.assertNotIn("\n", out)
        self.assertIn("&amp;amp;", out)

    def test_the_stored_reason_is_cut(self):
        self.assertEqual(len(promote.clean_reason("x" * 1000)), promote.REASON_LIMIT)

    def test_the_summary_and_release_text_use_the_escaped_reason(self):
        sel = valid_selection("fast-path", "fix @owner <b>x</b>")
        self.assertNotIn("@owner", promote.markdown_selection({**sel, "headSha": "a" * 40, "action": "promote",
                                                              "candidates": [], "stableSha": STABLE}))
        with tempfile.TemporaryDirectory() as d:
            for name, data in (("s.json", sel), ("r.json", valid_record())):
                Path(d, name).write_text(json.dumps(data))
            Path(d, "m.md").write_text("md")
            res = subprocess.run([sys.executable, str(TOOL), "notes", "--select", f"{d}/s.json", "--record", f"{d}/r.json",
                                  "--risk-md", f"{d}/m.md", "--candidate", CANDIDATE, "--tag", "stable-20261115",
                                  "--repo", "o/r"], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn("<b>", res.stdout)
            self.assertNotIn("@owner", res.stdout)


class Digests(unittest.TestCase):
    def run_check(self, path, expected):
        return subprocess.run([sys.executable, str(TOOL), "check-digest", "--path", str(path), "--expected", expected],
                              capture_output=True, text=True).returncode

    def test_a_file_and_a_directory_match_their_own_digest_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "a.json")
            f.write_text("one")
            tree = Path(d, "tree")
            tree.mkdir()
            Path(tree, "x.md").write_text("x")
            Path(tree, "y.json").write_text("y")
            fd, td = promote.tree_digest(f), promote.tree_digest(tree)
            self.assertEqual((self.run_check(f, fd), self.run_check(tree, td)), (0, 0))
            self.assertNotEqual(self.run_check(f, td), 0)
            self.assertNotEqual(self.run_check(f, ""), 0)
            self.assertNotEqual(self.run_check(f, "not-a-digest"), 0)
            f.write_text("two")
            self.assertNotEqual(self.run_check(f, fd), 0)
            Path(tree, "y.json").write_text("changed")
            self.assertNotEqual(self.run_check(tree, td), 0)
            Path(tree, "y.json").write_text("y")
            Path(tree, "extra").write_text("e")
            self.assertNotEqual(self.run_check(tree, td), 0)

    def test_a_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "real").write_text("r")
            try:
                os.symlink(Path(d, "real"), Path(d, "link"))
            except OSError:
                self.skipTest("no symlinks")
            with self.assertRaises(SystemExit):
                promote.tree_digest(Path(d, "link"))


@unittest.skipUnless(shutil.which("make") and shutil.which("git"), "no make")
class Overlay(unittest.TestCase):
    def test_the_candidate_gets_the_trusted_rules_and_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            trusted, candidate, outside = Path(tmp, "trusted"), Path(tmp, "candidate"), Path(tmp, "outside")
            for d in (trusted, candidate, outside):
                d.mkdir()
            shutil.copy(ROOT / "Makefile", trusted / "Makefile")
            for d in ("ci", "tests", ".githooks"):
                (trusted / d).mkdir()
                (trusted / d / "rule").write_text("trusted")
            (trusted / ".gitleaks.toml").write_text("trusted")
            (trusted / "renovate.json").write_text("{}")
            # The candidate has its own versions of everything, a file the trusted tree lacks,
            # a symlinked directory and a symlinked file, and a symlinked .github.
            (outside / "rule").write_text("outside")
            (candidate / "Makefile").write_text("evil")
            (candidate / "tests").mkdir()
            (candidate / "tests" / "rule").write_text("evil")
            (candidate / "tests" / "extra").write_text("evil")
            (candidate / ".yamllint").write_text("evil")
            (candidate / ".shellcheckrc").write_text("evil")
            try:
                os.symlink(outside, candidate / "ci")
                os.symlink(outside / "rule", candidate / ".gitleaks.toml")
                os.symlink(outside, candidate / ".githooks")
                os.symlink(outside, candidate / ".github")
            except OSError:
                self.skipTest("no symlinks")
            res = subprocess.run(["make", "-C", str(trusted), "promote-overlay", f"CANDIDATE={candidate}"],
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            for rel in ("ci/rule", "tests/rule", ".githooks/rule"):
                self.assertEqual((candidate / rel).read_text(), "trusted", rel)
            self.assertEqual((candidate / ".gitleaks.toml").read_text(), "trusted")
            self.assertEqual((candidate / "Makefile").read_text(), (trusted / "Makefile").read_text())
            self.assertFalse((candidate / "tests" / "extra").exists())
            self.assertFalse((candidate / ".yamllint").exists())
            self.assertFalse((candidate / ".shellcheckrc").exists())
            for rel in ("ci", ".githooks", ".gitleaks.toml", ".github"):
                self.assertFalse((candidate / rel).is_symlink(), rel)
            self.assertEqual((outside / "rule").read_text(), "outside")
            self.assertEqual(sorted(p.name for p in outside.iterdir()), ["rule"])


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "no git")
class PrepareScript(unittest.TestCase):
    """ci/promote-prepare.sh against a real git repository with a bare origin."""

    def git(self, repo, *args):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env).stdout.strip()

    def build(self, tmp, existing_tags=(), diverge=False):
        origin, repo = Path(tmp, "origin.git"), Path(tmp, "repo")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
        subprocess.run(["git", "clone", "-q", str(origin), str(repo)], check=True, capture_output=True)
        self.git(repo, "commit", "-q", "--allow-empty", "-m", "base")
        stable = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "push", "-q", "origin", "HEAD:refs/heads/main", f"{stable}:refs/heads/stable")
        if diverge:
            self.git(repo, "checkout", "-q", "-b", "side", stable)
            self.git(repo, "commit", "-q", "--allow-empty", "-m", "side")
            candidate = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "checkout", "-q", "main")
            self.git(repo, "commit", "-q", "--allow-empty", "-m", "main moves")
            self.git(repo, "push", "-q", "origin", "main", f"{candidate}:refs/heads/side")
            self.git(repo, "push", "-q", "origin", f"{self.git(repo, 'rev-parse', 'main')}:refs/heads/stable", "-f")
        else:
            self.git(repo, "commit", "-q", "--allow-empty", "-m", "change")
            candidate = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "push", "-q", "origin", "main")
        for tag in existing_tags:
            self.git(repo, "push", "-q", "origin", f"{stable}:refs/tags/{tag}")
        return repo, stable, candidate

    def inputs(self, tmp, stable, candidate):
        now = datetime.now(timezone.utc)
        record = valid_record(commit=candidate, baseline=stable)
        record["scan"]["scannedAt"] = promote.iso(now - timedelta(hours=1))
        record["scanner"]["databaseUpdatedAt"] = promote.iso(now - timedelta(hours=3))
        sel = valid_selection()
        sel.update(stableSha=stable)
        sel["candidates"] = [{"sha": candidate, "landedAt": promote.iso(now - timedelta(days=8)), "known": True}]
        base = Path(tmp, "inputs")
        for sub in ("select", "scanned", "risk"):
            (base / sub).mkdir(parents=True)
        files = {base / "select/select.json": sel, base / "scanned/promotion-record-scanned.json": record,
                 base / "risk/manifest-risk.json": RISK, base / "risk/revert.json": REVERT}
        for path, data in files.items():
            path.write_text(json.dumps(data))
        (base / "risk/manifest-risk.md").write_text("no additions")
        digests = {"SELECT_DIGEST": promote.tree_digest(base / "select/select.json"),
                   "SCANNED_DIGEST": promote.tree_digest(base / "scanned/promotion-record-scanned.json"),
                   "RISK_DIGEST": promote.tree_digest(base / "risk")}
        return base, digests

    def run_prepare(self, repo, candidate, base, digests, first="false"):
        out = Path(repo, "gh-output")
        out.unlink(missing_ok=True)
        env = {**os.environ, "CANDIDATE": candidate, "FIRST_PROMOTION": first, "GITHUB_REPOSITORY": "o/r",
               "GITHUB_OUTPUT": str(out), **digests}
        # ci/ comes from the real repository; the work tree is the temporary clone.
        shutil.copytree(ROOT / "ci", repo / "ci", dirs_exist_ok=True)
        res = subprocess.run(["bash", str(ROOT / "ci/promote-prepare.sh"), str(base)], cwd=repo, env=env, capture_output=True, text=True)
        return res, (dict(line.split("=", 1) for line in out.read_text().splitlines()) if out.exists() else {})

    def test_a_valid_candidate_gets_the_next_free_tag_and_release_files(self):
        today = f"stable-{datetime.now(timezone.utc):%Y%m%d}"
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp, [today])
            base, digests = self.inputs(tmp, stable, candidate)
            res, out = self.run_prepare(repo, candidate, base, digests)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(out["tag"], f"{today}-2")
            self.assertEqual(out["stable_sha"], stable)
            for f in ("promotion-record.json", "manifest-risk.json", "manifest-risk.md", "notes.md"):
                self.assertTrue(Path(repo, "release", f).exists(), f)

    def test_the_first_tag_of_the_day_has_no_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp)
            base, digests = self.inputs(tmp, stable, candidate)
            res, out = self.run_prepare(repo, candidate, base, digests)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(out["tag"], f"stable-{datetime.now(timezone.utc):%Y%m%d}")

    def test_a_candidate_that_does_not_descend_from_stable_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp, diverge=True)
            new_stable = self.git(repo, "ls-remote", "origin", "refs/heads/stable").split()[0]
            base, digests = self.inputs(tmp, new_stable, candidate)
            res, _ = self.run_prepare(repo, candidate, base, digests)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("ancestor", res.stderr)

    def test_an_artifact_that_differs_from_its_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp)
            base, digests = self.inputs(tmp, stable, candidate)
            for key in digests:
                bad = {**digests, key: "0" * 64}
                res, _ = self.run_prepare(repo, candidate, base, bad)
                self.assertNotEqual(res.returncode, 0, key)
            Path(base, "risk/manifest-risk.md").write_text("changed after the digest")
            res, _ = self.run_prepare(repo, candidate, base, digests)
            self.assertNotEqual(res.returncode, 0)

    def test_a_missing_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp)
            base, digests = self.inputs(tmp, stable, candidate)
            res, _ = self.run_prepare(repo, candidate, base, {k: v for k, v in digests.items() if k != "RISK_DIGEST"})
            self.assertNotEqual(res.returncode, 0)

    def test_stable_having_moved_since_the_selection_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, stable, candidate = self.build(tmp)
            base, digests = self.inputs(tmp, "9" * 40, candidate)
            res, _ = self.run_prepare(repo, candidate, base, digests)
            self.assertNotEqual(res.returncode, 0)


if __name__ == "__main__":
    unittest.main()
