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
        self.assertEqual(len(promote.clean_reason("x" * 400)), 300)


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
            table[head] = [] if days is None else [{"merged_at": at(days), "base": {"ref": "main"}}]
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


class Fallback(unittest.TestCase):
    SHAS = [sha(1), sha(2), sha(3)]

    def test_the_first_pass_wins(self):
        self.assertEqual(promote.choose(self.SHAS, ["pass", "pass", "skipped"], ["false", "true", ""]), (1, sha(1), "false"))

    def test_a_failed_candidate_hands_over_to_the_next_older_one(self):
        self.assertEqual(promote.choose(self.SHAS, ["fail", "pass", "skipped"], ["", "true", ""]), (2, sha(2), "true"))
        self.assertEqual(promote.choose(self.SHAS, ["fail", "fail", "pass"], ["", "", "false"]), (3, sha(3), "false"))

    def test_nothing_passes(self):
        self.assertEqual(promote.choose(self.SHAS, ["fail", "fail", "fail"], ["", "", ""]), (0, "", ""))
        self.assertEqual(promote.choose(["", "", ""], ["skipped"] * 3, [""] * 3), (0, "", ""))

    def test_a_missing_approval_value_means_approval_is_needed(self):
        self.assertEqual(promote.choose(self.SHAS, ["pass", "", ""], ["", "", ""])[2], "true")
        self.assertEqual(promote.choose(self.SHAS, ["pass", "", ""], [])[2], "true")
        self.assertEqual(promote.choose(self.SHAS, ["pass", "", ""], ["FALSE", "", ""])[2], "true")

    def test_a_skipped_or_unknown_result_is_never_chosen(self):
        self.assertEqual(promote.choose(self.SHAS, ["skipped", "cancelled", "pass"], ["", "", ""])[0], 3)
        self.assertEqual(promote.choose(self.SHAS, ["success", "", ""], ["", "", ""])[0], 0)


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

    def test_the_first_promotion_flag_with_no_release_is_allowed(self):
        code, out = self.run_baseline([], "--first-promotion")
        self.assertEqual(code, 0)
        self.assertIn("first_promotion=true", out)

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
        "schemaVersion": 1, "commit": commit,
        "images": [{"reference": "docker.io/library/redis:7", "digest": digest, "digestSource": "registry", "sources": ["rendered"]}],
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
            self.assertEqual(doc["permissions"], {"contents": "read"})
        for name, job in self.candidate["jobs"].items():
            self.assertNotIn("permissions", job, name)
            self.assertNotIn("environment", job, name)
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
        self.assertNotIn("permissions", self.promote["jobs"]["dry-run"])

    def test_the_promote_job_pushes_the_tag_before_the_branch_and_publishes_last(self):
        order = [s.get("id") for s in steps_of(self.promote["jobs"]["promote"]) if s.get("id")]
        self.assertEqual(order, ["prepare", "load", "tag", "draft", "push", "publish"])

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


if __name__ == "__main__":
    unittest.main()
