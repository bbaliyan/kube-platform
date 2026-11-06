#!/usr/bin/env python3
"""Tests for the daily stable watch: ci/stable_watch.py and .github/workflows/stable-watch.yaml.

A script is needed because the checks run the tool as a program against a
stand-in gh, docker and helm, and read the workflow file as data; no
declarative tool does that. The cases: a changed digest is drift; a registry
outage is incomplete and never "no drift"; the rolling issue is updated and not
duplicated; the stale alarm opens at 21 days and closes after a promotion; the
fail-closed cases of the gate; the case without a release; and the rules of the
workflow file (permissions, pinned actions, no outside data in run blocks).

    tests/check-stable-watch.py
"""

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "ci/stable_watch.py"
WORKFLOW = ROOT / ".github/workflows/stable-watch.yaml"
STUBS = ROOT / "tests/fixtures/stable-watch/bin"
BUILD_STUBS = ROOT / "tests/fixtures/promotion-record/bin"
sys.path.insert(0, str(ROOT / "ci"))
import stable_watch as watch  # noqa: E402

NOW = datetime(2026, 11, 16, 20, 0, tzinfo=timezone.utc)
FRESH_DB = "2026-11-16T10:00:00Z"
OLD_DB = "2026-11-12T10:00:00Z"
D1, D2, D3, D4, D5 = ("sha256:" + c * 64 for c in "12345")
APP, LIB = "quay.io/example/app", "docker.io/library/lib"
REPO = "example/repo"
TAG = "stable-20261115"
STABLE = "a" * 40
HEAD = "b" * 40
KEV_ID = "CVE-2026-9999"


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def make_record(commit=STABLE):
    def image(ref, digest, source):
        return {"reference": ref, "digest": digest, "digestSource": source, "sources": ["rendered"],
                "runtimeDigests": [], "runtimeDiffers": False}
    return {
        "schemaVersion": 2, "commit": commit,
        "images": [image(f"{APP}:1.0", D1, "registry"), image(f"{LIB}@{D2}", D2, "pinned")],
        "charts": [{"name": "web", "version": "1.2.3", "repository": "https://charts.example.test", "digest": D3},
                   {"name": "oci", "version": "2.0.0", "repository": "oci://registry.example.test/charts", "digest": D4}],
        "notScanned": [{"type": "grafana-plugin", "name": "example-plugin", "reason": "downloaded at start"}],
        "scanner": {"name": "trivy", "version": "0.76.1", "databaseUpdatedAt": "2026-11-15T01:00:00Z"},
        "scan": {"scannedAt": "2026-11-15T22:00:00Z", "verdict": "pass", "baselineCommit": None,
                 "imagesListed": 2, "imagesScanned": 2,
                 "counts": {"blocking": 0, "known": 1, "ignored": 0, "kev": 0, "otherSeverities": 3},
                 "reasons": [], "exemptions": [],
                 "findings": [{"image": APP, "id": "CVE-2026-0001", "package": "libc", "installedVersion": "1.0",
                               "fixedVersion": "2.0", "severity": "HIGH", "kev": False, "status": "known"}]},
    }


def finding(vuln_id, package="libc", severity="HIGH", fixed="2.0"):
    return {"id": vuln_id, "package": package, "installedVersion": "1.0", "fixedVersion": fixed, "severity": severity}


def scan_of(record, per_image=None, db=FRESH_DB, scanner=True, errors=None):
    """A scan result of the record's images. per_image: {digest: [findings]}."""
    per_image, errors = per_image or {}, errors or {}
    results = [{"reference": i["reference"], "digest": i["digest"], "error": errors.get(i["digest"]),
                "findings": per_image.get(i["digest"], [])} for i in record["images"]
               if i["digest"] not in errors or errors[i["digest"]] != "absent"]
    return {"scanner": {"name": "trivy", "version": "0.76.1", "databaseUpdatedAt": db} if scanner else None,
            "scannerError": None if scanner else "trivy: command not found", "results": results}


def kev_of(*ids, released="2026-11-15T00:00:00Z"):
    return {"dateReleased": released, "vulnerabilities": [{"cveID": i} for i in (ids or ("CVE-2000-0001",))]}


def resolved_of(record, changes=None, errors=None):
    """What the registries return: the record's digests, with changes {name: digest} and errors {name: text}."""
    changes, errors = changes or {}, errors or {}
    out = {"images": [], "charts": []}
    for i in record["images"]:
        out["images"].append({"reference": i["reference"], "digest": None if i["reference"] in errors else changes.get(i["reference"], i["digest"]),
                              "error": errors.get(i["reference"])})
    for c in record["charts"]:
        out["charts"].append({"name": c["name"], "version": c["version"], "repository": c["repository"],
                              "digest": None if c["name"] in errors else changes.get(c["name"], c["digest"]),
                              "error": errors.get(c["name"])})
    return out


def lag_of(days):
    if days is None:
        return {"state": "current", "days": 0.0, "stableSha": STABLE, "headSha": STABLE}
    landed = (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"state": "behind", "days": days, "stableSha": STABLE, "headSha": HEAD, "oldestCommit": "c" * 40,
            "landedAt": landed, "landedSource": "pull request merge", "error": None}


FETCH_OK = {"status": "ok", "reason": "", "tag": TAG, "publishedAt": "2026-11-15T22:30:00Z"}
IGNORE = Path(tempfile.mkdtemp()) / "ignore"
IGNORE.write_text("# no entries\n", encoding="utf-8")


def evaluate(record=None, scan="default", kev="default", resolved="default", lag="default", fetch=FETCH_OK, ignore=IGNORE):
    record = record or make_record()
    scan = scan_of(record) if scan == "default" else scan
    kev = kev_of() if kev == "default" else kev
    resolved = resolved_of(record) if resolved == "default" else resolved
    lag = lag_of(None) if lag == "default" else lag
    return watch.evaluate(fetch, record, scan, None if scan else "no file", kev, resolved,
                          None if resolved else "no file", lag, None if lag else "no file", ignore, NOW)


def states(result):
    return {k: c["state"] for k, c in result["conditions"].items()}


class Drift(unittest.TestCase):
    def test_nothing_changed_is_clear(self):
        r = evaluate()
        self.assertEqual(states(r)["drift"], "clear")
        self.assertEqual(r["problems"], [])
        self.assertEqual(states(r)["incomplete"], "clear")

    def test_a_changed_image_digest_is_drift(self):
        r = evaluate(resolved=resolved_of(make_record(), changes={f"{APP}:1.0": D5}))
        self.assertEqual(states(r)["drift"], "active")
        body = "\n".join(r["conditions"]["drift"]["body"])
        self.assertIn(f"{APP}:1.0", body)
        self.assertIn(D1, body)
        self.assertIn(D5, body)
        self.assertIn("digestSource: pinned", body)
        self.assertIn("drift", r["priority"])

    def test_a_changed_chart_digest_is_drift(self):
        r = evaluate(resolved=resolved_of(make_record(), changes={"web": D5}))
        self.assertEqual(states(r)["drift"], "active")
        self.assertIn("web 1.2.3", "\n".join(r["conditions"]["drift"]["body"]))

    def test_a_changed_pinned_digest_is_also_reported(self):
        r = evaluate(resolved=resolved_of(make_record(), changes={f"{LIB}@{D2}": D5}))
        self.assertEqual(states(r)["drift"], "active")

    def test_a_registry_error_is_incomplete_and_never_clear(self):
        r = evaluate(resolved=resolved_of(make_record(), errors={f"{APP}:1.0": "registry unreachable"}))
        self.assertEqual(states(r)["drift"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")
        self.assertIn("could not be resolved", "\n".join(r["problems"]))
        self.assertIn("incomplete", r["priority"])

    def test_a_chart_error_is_incomplete(self):
        r = evaluate(resolved=resolved_of(make_record(), errors={"oci": "timeout"}))
        self.assertEqual(states(r)["drift"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_drift_and_an_error_report_both(self):
        r = evaluate(resolved=resolved_of(make_record(), changes={"web": D5}, errors={f"{APP}:1.0": "boom"}))
        self.assertEqual(states(r)["drift"], "active")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_a_missing_resolve_result_is_incomplete(self):
        r = evaluate(resolved=None)
        self.assertEqual(states(r)["drift"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_an_image_the_lookup_left_out_is_not_a_pass(self):
        resolved = resolved_of(make_record())
        resolved["images"].pop()
        r = evaluate(resolved=resolved)
        self.assertEqual(states(r)["drift"], "unknown")

    def test_outside_text_is_escaped_and_cut(self):
        nasty = "<img src=x onerror=1> @owner [click](http://x) #12 `code` " + "A" * 500
        r = evaluate(resolved=resolved_of(make_record(), errors={f"{APP}:1.0": nasty}))
        text = "\n".join(r["conditions"]["incomplete"]["body"])
        for raw in ("<img", "@owner", "[click]", "#12", "`code`"):
            self.assertNotIn(raw, text)
        self.assertLess(len(text), 2000)


class Scan(unittest.TestCase):
    def test_a_complete_scan_fills_the_rolling_issue(self):
        record = make_record()
        scan = scan_of(record, {D1: [finding("CVE-2026-0001"), finding("CVE-2026-0002", fixed="3.1.4"),
                                     finding("CVE-2026-0003", fixed=None, severity="CRITICAL")]})
        r = evaluate(record, scan=scan)
        body = "\n".join(r["conditions"]["rolling"]["body"])
        self.assertEqual(states(r)["rolling"], "active")
        self.assertEqual(states(r)["incomplete"], "clear")
        self.assertIn("Status: complete", body)
        self.assertIn("CVE-2026-0002", body)
        self.assertIn("3.1.4", body)
        self.assertIn("database updated 2026-11-16T10:00:00Z", body)
        self.assertIn("2 of 2", body)
        self.assertEqual(r["priority"], [])

    def test_new_findings_since_the_record_are_listed(self):
        record = make_record()
        scan = scan_of(record, {D1: [finding("CVE-2026-0001"), finding("CVE-2026-0002")]})
        body = "\n".join(evaluate(record, scan=scan)["conditions"]["rolling"]["body"])
        section = body.split("### New since the record")[1].split("###")[0]
        self.assertIn("CVE-2026-0002", section)
        self.assertNotIn("CVE-2026-0001", section)

    def test_a_kev_finding_is_a_priority(self):
        record = make_record()
        scan = scan_of(record, {D1: [finding(KEV_ID, severity="LOW", fixed=None)]})
        r = evaluate(record, scan=scan, kev=kev_of(KEV_ID))
        self.assertEqual(states(r)["kev"], "active")
        self.assertIn(KEV_ID, "\n".join(r["conditions"]["kev"]["body"]))
        self.assertIn("kev", r["priority"])
        self.assertEqual(states(r)["incomplete"], "clear", "a KEV finding is a finding, not a failed scan")

    def test_an_ignored_kev_finding_does_not_open_the_issue(self):
        record = make_record()
        ignore = Path(tempfile.mkdtemp(), "ignore")
        expiry = (NOW + timedelta(days=30)).strftime("%Y-%m-%d")
        ignore.write_text(f"{KEV_ID} exp:{expiry} reason:not reachable\n", encoding="utf-8")
        scan = scan_of(record, {D1: [finding(KEV_ID, severity="LOW", fixed=None)]})
        r = evaluate(record, scan=scan, kev=kev_of(KEV_ID), ignore=ignore)
        self.assertEqual(states(r)["kev"], "clear")

    def test_no_kev_finding_is_clear(self):
        self.assertEqual(states(evaluate())["kev"], "clear")

    def assert_incomplete(self, r, text):
        self.assertEqual(states(r)["incomplete"], "active")
        self.assertIn(text, "\n".join(r["problems"]))
        self.assertIn("INCOMPLETE", "\n".join(r["conditions"]["rolling"]["body"]))
        self.assertEqual(states(r)["kev"], "unknown", "an incomplete scan must not close the KEV issue")

    def test_an_old_database_is_incomplete(self):
        r = evaluate(scan=scan_of(make_record(), db=OLD_DB))
        self.assert_incomplete(r, "database is")

    def test_a_missing_image_result_is_incomplete(self):
        record = make_record()
        r = evaluate(record, scan=scan_of(record, errors={D2: "absent"}))
        self.assert_incomplete(r, "no scan result for")

    def test_a_failed_image_scan_is_incomplete(self):
        record = make_record()
        r = evaluate(record, scan=scan_of(record, errors={D1: "pull failed"}))
        self.assert_incomplete(r, "scan failed for")

    def test_a_missing_scanner_is_incomplete(self):
        r = evaluate(scan=scan_of(make_record(), scanner=False))
        self.assert_incomplete(r, "trivy: command not found")

    def test_nothing_detected_is_incomplete(self):
        record = make_record()
        scan = scan_of(record)
        scan["results"][0]["noPackages"] = True
        self.assert_incomplete(evaluate(record, scan=scan), "no packages detected")

    def test_a_missing_kev_file_is_incomplete(self):
        self.assert_incomplete(evaluate(kev=None), "KEV file")

    def test_an_old_kev_file_is_incomplete(self):
        self.assert_incomplete(evaluate(kev=kev_of(released="2026-10-01T00:00:00Z")), "older than")

    def test_an_expired_ignore_entry_is_incomplete(self):
        ignore = Path(tempfile.mkdtemp(), "ignore")
        ignore.write_text("CVE-2026-0001 exp:2026-01-01 reason:old\n", encoding="utf-8")
        self.assert_incomplete(evaluate(ignore=ignore), "expired")

    def test_a_missing_scan_file_is_incomplete_and_leaves_the_rolling_issue_alone(self):
        r = evaluate(scan=None)
        self.assertEqual(states(r)["rolling"], "unknown")
        self.assertEqual(states(r)["kev"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_finding_text_is_escaped(self):
        record = make_record()
        bad = finding("CVE-2026-0007", package="<b>@owner</b> [x](y)", fixed="1`2`")
        scan = scan_of(record, {D1: [bad]})
        body = "\n".join(evaluate(record, scan=scan)["conditions"]["rolling"]["body"])
        for raw in ("<b>", "@owner", "[x](y)", "1`2`"):
            self.assertNotIn(raw, body)


class Stale(unittest.TestCase):
    def test_it_opens_above_21_days(self):
        r = evaluate(lag=lag_of(21.5))
        self.assertEqual(states(r)["stale"], "active")
        self.assertIn("stale", r["priority"])
        self.assertIn("21.5 days", "\n".join(r["conditions"]["stale"]["body"]))

    def test_it_stays_clear_up_to_21_days(self):
        self.assertEqual(states(evaluate(lag=lag_of(21.0)))["stale"], "clear")
        self.assertEqual(states(evaluate(lag=lag_of(20.9)))["stale"], "clear")

    def test_it_is_clear_when_stable_is_current(self):
        self.assertEqual(states(evaluate(lag=lag_of(None)))["stale"], "clear")

    def test_an_unknown_lag_is_incomplete(self):
        r = evaluate(lag={"state": "unknown", "days": None, "error": "gh failed"})
        self.assertEqual(states(r)["stale"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_a_failed_fetch_still_reports_a_stale_stable(self):
        fetch = {"status": "failed", "reason": "the attestation did not verify", "tag": "", "publishedAt": None}
        r = watch.evaluate(fetch, None, None, "x", None, None, "x", lag_of(30), None, IGNORE, NOW)
        self.assertEqual(states(r)["stale"], "active")
        self.assertEqual(states(r)["incomplete"], "active")
        for kind in ("rolling", "drift", "kev"):
            self.assertEqual(states(r)[kind], "unknown")


def run_tool(*args, env=None, cwd=None):
    full = dict(os.environ)
    full.update(env or {})
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True,
                          env=full, cwd=cwd)


class Sync(unittest.TestCase):
    """The issues, through a stand-in gh."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.env = {"PATH": f"{STUBS}{os.pathsep}{os.environ['PATH']}", "STUB_GH_STATE": str(self.dir)}
        self.day = 0

    def tearDown(self):
        self.tmp.cleanup()

    def issues(self):
        path = self.dir / "state.json"
        return json.loads(path.read_text())["issues"] if path.exists() else []

    def calls(self):
        path = self.dir / "calls.log"
        return path.read_text().splitlines() if path.exists() else []

    def sync(self, result):
        """Run one daily sync of an evaluate() result. Returns the exit code."""
        state = self.dir / "watch-state.json"
        state.write_text(json.dumps(result))
        self.day += 1
        now = (NOW + timedelta(days=self.day)).strftime("%Y-%m-%dT%H:%M:%SZ")
        res = run_tool("sync", "--state", state, "--repo", REPO, "--now", now, env=self.env)
        self.last = res
        return res.returncode

    def by_kind(self, kind):
        title = watch.KINDS[kind][0]
        return [i for i in self.issues() if i["title"] == title]

    def test_the_rolling_issue_is_updated_not_duplicated(self):
        record = make_record()
        self.assertEqual(self.sync(evaluate(record, scan=scan_of(record, {D1: [finding("CVE-2026-0001")]}))), 0)
        first = self.by_kind("rolling")
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["labels"], ["stable-watch"])
        scan = scan_of(record, {D1: [finding("CVE-2026-0001"), finding("CVE-2026-0042", fixed="9.9")]})
        self.assertEqual(self.sync(evaluate(record, scan=scan)), 0)
        self.assertEqual(self.sync(evaluate(record, scan=scan)), 0)
        rolling = self.by_kind("rolling")
        self.assertEqual(len(rolling), 1)
        self.assertEqual(rolling[0]["number"], first[0]["number"])
        self.assertIn("CVE-2026-0042", rolling[0]["body"])
        self.assertEqual(sum(c.startswith("issue create") for c in self.calls()), 1)
        self.assertEqual(rolling[0]["state"], "OPEN")

    def test_a_closed_rolling_issue_is_reopened_not_replaced(self):
        self.sync(evaluate())
        state = json.loads((self.dir / "state.json").read_text())
        state["issues"][0]["state"] = "CLOSED"
        (self.dir / "state.json").write_text(json.dumps(state))
        self.sync(evaluate())
        self.assertEqual(len(self.by_kind("rolling")), 1)
        self.assertEqual(self.by_kind("rolling")[0]["state"], "OPEN")

    def test_an_issue_of_someone_else_with_the_same_title_is_ignored(self):
        self.sync(evaluate())
        state = json.loads((self.dir / "state.json").read_text())
        state["issues"].insert(0, dict(state["issues"][0], number=99, author={"login": "mallory"},
                                       body="<!-- stable-watch:rolling -->\nfake"))
        (self.dir / "state.json").write_text(json.dumps(state))
        self.sync(evaluate())
        fake = next(i for i in self.issues() if i["number"] == 99)
        self.assertEqual(fake["body"], "<!-- stable-watch:rolling -->\nfake")
        self.assertEqual(len([i for i in self.by_kind("rolling") if i["author"]["login"] != "mallory"]), 1)

    def test_the_stale_alarm_opens_at_21_days_and_closes_after_a_promotion(self):
        self.assertEqual(self.sync(evaluate(lag=lag_of(20.5))), 0)
        self.assertEqual(self.by_kind("stale"), [])
        self.assertEqual(self.sync(evaluate(lag=lag_of(21.5))), 1, "a priority condition makes the run red")
        stale = self.by_kind("stale")
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["state"], "OPEN")
        self.assertEqual(stale[0]["labels"], ["stable-watch", "priority"])
        self.sync(evaluate(lag=lag_of(22.5)))
        self.assertEqual(len(self.by_kind("stale")), 1, "no second issue while the first is open")
        self.assertEqual(self.sync(evaluate(lag=lag_of(1.0))), 0)
        closed = self.by_kind("stale")[0]
        self.assertEqual(closed["state"], "CLOSED")
        self.assertIn("Cleared on", closed["comments"][-1])

    def test_an_unknown_result_does_not_close_an_issue(self):
        self.sync(evaluate(lag=lag_of(30)))
        self.sync(evaluate(lag={"state": "unknown", "days": None, "error": "gh failed"}))
        self.assertEqual(self.by_kind("stale")[0]["state"], "OPEN")
        incomplete = self.by_kind("incomplete")
        self.assertEqual(len(incomplete), 1)
        self.sync(evaluate(lag=lag_of(None)))
        self.assertEqual(self.by_kind("stale")[0]["state"], "CLOSED")
        self.assertEqual(self.by_kind("incomplete")[0]["state"], "CLOSED")

    def test_a_kev_issue_opens_and_closes_with_a_comment(self):
        record = make_record()
        hit = scan_of(record, {D1: [finding(KEV_ID, severity="LOW", fixed=None)]})
        self.assertEqual(self.sync(evaluate(record, scan=hit, kev=kev_of(KEV_ID))), 1)
        self.assertEqual(self.by_kind("kev")[0]["state"], "OPEN")
        self.assertEqual(self.sync(evaluate(record)), 0)
        kev = self.by_kind("kev")[0]
        self.assertEqual(kev["state"], "CLOSED")
        self.assertTrue(kev["comments"])

    def test_a_drift_issue_gets_a_comment_when_its_details_change(self):
        record = make_record()
        self.sync(evaluate(record, resolved=resolved_of(record, changes={"web": D5})))
        self.sync(evaluate(record, resolved=resolved_of(record, changes={"web": D5})))
        self.assertEqual(self.by_kind("drift")[0]["comments"], [], "a new day alone is no change")
        self.sync(evaluate(record, resolved=resolved_of(record, changes={"web": D5, f"{APP}:1.0": D4})))
        drift = self.by_kind("drift")
        self.assertEqual(len(drift), 1)
        self.assertEqual(len(drift[0]["comments"]), 1)
        self.assertIn(D4, drift[0]["body"])

    def test_a_duplicate_open_issue_is_closed(self):
        self.sync(evaluate(lag=lag_of(30)))
        state = json.loads((self.dir / "state.json").read_text())
        state["issues"].append(dict(state["issues"][0], number=7, comments=[]))
        (self.dir / "state.json").write_text(json.dumps(state))
        self.sync(evaluate(lag=lag_of(30)))
        open_ones = [i for i in self.by_kind("stale") if i["state"] == "OPEN"]
        self.assertEqual([i["number"] for i in open_ones], [state["issues"][0]["number"]])

    def test_no_release_touches_nothing(self):
        state = self.dir / "none.json"
        fetch = self.dir / "fetch.json"
        fetch.write_text(json.dumps({"status": "none", "reason": "stable has not been promoted yet", "tag": ""}))
        res = run_tool("report", "--fetch", fetch, "--ignore", IGNORE, "--out", state, env=self.env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("not been promoted", res.stdout)
        self.assertEqual(self.sync_state(state), 0)
        self.assertEqual(self.calls(), [])

    def sync_state(self, path):
        return run_tool("sync", "--state", path, "--repo", REPO, env=self.env).returncode


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.files = self.dir / "release-files"
        (self.files / TAG).mkdir(parents=True)
        self.releases = self.dir / "releases.json"
        self.env = {"PATH": f"{STUBS}{os.pathsep}{os.environ['PATH']}", "STUB_GH_STATE": str(self.dir),
                    "STUB_RELEASES": str(self.releases), "STUB_RELEASE_FILES": str(self.files)}

    def tearDown(self):
        self.tmp.cleanup()

    def release(self, tag=TAG, **extra):
        return {"tagName": tag, "isDraft": False, "isPrerelease": False, "publishedAt": "2026-11-15T22:30:00Z", **extra}

    def fetch(self, releases, record=None, stable=STABLE, env=None):
        self.releases.write_text(json.dumps(releases))
        if record is not None:
            (self.files / TAG / "promotion-record.json").write_text(json.dumps(record))
        out = self.dir / "out"
        res = run_tool("fetch", "--repo", REPO, "--out-dir", out, "--stable-sha", stable, env={**self.env, **(env or {})})
        meta = json.loads((out / "fetch.json").read_text())
        return res, meta, out

    def test_no_release_stops_cleanly(self):
        res, meta, _ = self.fetch([])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(meta["status"], "none")
        self.assertIn("::notice::", res.stdout)
        self.assertIn("not been promoted", meta["reason"])

    def test_a_draft_and_a_prerelease_are_not_a_release(self):
        _, meta, _ = self.fetch([self.release(isDraft=True), self.release("stable-20261116", isPrerelease=True),
                                 self.release("v1.0")])
        self.assertEqual(meta["status"], "none")

    def test_a_verified_record_is_ok(self):
        res, meta, out = self.fetch([self.release("stable-20261101"), self.release()], make_record())
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual((meta["status"], meta["tag"]), ("ok", TAG))
        self.assertTrue((out / "promotion-record.json").exists())
        verify = next(l for l in (self.dir / "calls.log").read_text().splitlines() if l.startswith("attestation verify"))
        for part in (f"--repo {REPO}", f"--signer-workflow {REPO}/.github/workflows/promote.yaml",
                     "--source-ref refs/heads/main", "--cert-oidc-issuer https://token.actions.githubusercontent.com"):
            self.assertIn(part, verify)

    def test_a_failed_attestation_is_failed_and_leaves_no_record(self):
        res, meta, out = self.fetch([self.release()], make_record(), env={"STUB_ATTEST": "fail"})
        self.assertEqual(res.returncode, 0)
        self.assertEqual(meta["status"], "failed")
        self.assertIn("verification failed", meta["reason"])
        self.assertFalse((out / "promotion-record.json").exists())

    def test_a_record_for_another_commit_is_failed(self):
        _, meta, _ = self.fetch([self.release()], make_record(commit="e" * 40))
        self.assertEqual(meta["status"], "failed")
        self.assertIn("stable moved without a release", meta["reason"])

    def test_an_invalid_record_is_failed(self):
        record = make_record()
        del record["charts"]
        _, meta, _ = self.fetch([self.release()], record)
        self.assertEqual(meta["status"], "failed")
        self.assertIn("schema", meta["reason"])

    def test_gh_failing_is_failed(self):
        self.releases.write_text("[]")
        out = self.dir / "out"
        env = {**self.env, "STUB_RELEASES": str(self.dir / "missing.json")}
        res = run_tool("fetch", "--repo", REPO, "--out-dir", out, "--stable-sha", STABLE, env=env)
        self.assertEqual(json.loads((out / "fetch.json").read_text())["status"], "failed", res.stderr)


class Lag(unittest.TestCase):
    """The age of the oldest commit that stable lacks, in a real git repository."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.env = {"PATH": f"{STUBS}{os.pathsep}{os.environ['PATH']}", "STUB_GH_STATE": str(self.dir)}

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args, date=None):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test"}
        if date:
            env["GIT_COMMITTER_DATE"] = env["GIT_AUTHOR_DATE"] = date
        res = subprocess.run(["git", "-C", str(self.repo), "-c", "commit.gpgsign=false", *args], capture_output=True,
                             text=True, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.strip()

    def commit(self, name, days_ago):
        (self.repo / name).write_text(name)
        self.git("add", name)
        self.git("commit", "-m", name, date=(NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        return self.git("rev-parse", "HEAD")

    def lag(self, head, merged_at=None, merge_sha=None):
        pulls = [{"merged_at": merged_at, "merge_commit_sha": merge_sha, "base": {"ref": "main"}}] if merged_at else []
        (self.dir / "pulls.json").write_text(json.dumps(pulls))
        out = self.dir / "lag.json"
        res = run_tool("lag", "--repo", REPO, "--head", head, "--out", out, "--repo-root", self.repo,
                       "--now", NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), env={**self.env, "STUB_PULLS": str(self.dir / "pulls.json")})
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text())

    def test_the_lag_is_the_age_of_the_oldest_missing_commit(self):
        self.git("init", "-b", "main")
        stable = self.commit("a", 40)
        self.git("update-ref", "refs/remotes/origin/stable", stable)
        oldest = self.commit("b", 30)
        head = self.commit("c", 1)
        merged = (NOW - timedelta(days=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = self.lag(head, merged, oldest)
        self.assertEqual(result["state"], "behind")
        self.assertEqual(result["oldestCommit"], oldest)
        self.assertAlmostEqual(result["days"], 25.0, places=1)
        self.assertEqual(result["landedSource"], "pull request merge")

    def test_a_commit_without_a_pull_request_uses_its_commit_date(self):
        self.git("init", "-b", "main")
        stable = self.commit("a", 40)
        self.git("update-ref", "refs/remotes/origin/stable", stable)
        head = self.commit("b", 30)
        result = self.lag(head)
        self.assertAlmostEqual(result["days"], 30.0, places=1)
        self.assertEqual(result["landedSource"], "commit date")

    def test_a_stable_at_main_is_current(self):
        self.git("init", "-b", "main")
        head = self.commit("a", 40)
        self.git("update-ref", "refs/remotes/origin/stable", head)
        self.assertEqual(self.lag(head)["state"], "current")

    def test_diverged_histories_are_unknown(self):
        self.git("init", "-b", "main")
        base = self.commit("a", 40)
        self.git("checkout", "-q", "-b", "other")
        other = self.commit("x", 30)
        self.git("update-ref", "refs/remotes/origin/stable", other)
        self.git("checkout", "-q", "main")
        self.git("reset", "-q", "--hard", base)
        head = self.commit("b", 20)
        result = self.lag(head)
        self.assertEqual(result["state"], "unknown")
        self.assertIn("diverged", result["error"])

    def test_a_missing_stable_ref_is_unknown_not_a_crash(self):
        self.git("init", "-b", "main")
        head = self.commit("a", 1)
        result = self.lag(head)
        self.assertEqual(result["state"], "unknown")


class Resolve(unittest.TestCase):
    """The registry lookups, through the stand-in docker and helm of the record tests. PyYAML is blocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        blocked = self.dir / "blocked"
        blocked.mkdir()
        for module in ("yaml", "jsonschema"):
            (blocked / f"{module}.py").write_text("raise ImportError('blocked in this test')\n")
        self.digests = self.dir / "digests"
        self.app = sha("app")
        self.web = sha("web 1.2.3 https://charts.example.test")
        self.oci = sha("oci")
        self.record = make_record()
        self.record["images"][0]["digest"] = self.app
        self.record["charts"][0]["digest"] = self.web
        self.record["charts"][1]["digest"] = self.oci
        self.set_registry()
        self.env = {"PATH": f"{BUILD_STUBS}{os.pathsep}{os.environ['PATH']}", "STUB_DIGESTS": str(self.digests),
                    "PROMOTION_RECORD_PAUSE": "0", "PYTHONPATH": str(blocked)}

    def tearDown(self):
        self.tmp.cleanup()

    def set_registry(self, skip=()):
        lines = {f"{APP}:1.0": self.app, "registry.example.test/charts/oci:2.0.0": self.oci}
        self.digests.write_text("".join(f"{k} {v}\n" for k, v in lines.items() if k not in skip))

    def resolve(self, record):
        path = self.dir / "record.json"
        path.write_text(json.dumps(record))
        out = self.dir / "resolved.json"
        res = run_tool("resolve", "--record", path, "--out", out, env=self.env)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text())

    def test_matching_registries_show_no_drift(self):
        resolved = self.resolve(self.record)
        r = evaluate(self.record, resolved=resolved)
        self.assertEqual(states(r)["drift"], "clear", r["problems"])

    def test_a_changed_digest_in_a_copy_of_the_record_is_reported(self):
        changed = copy.deepcopy(self.record)
        changed["images"][0]["digest"] = D5
        changed["charts"][0]["digest"] = D5
        r = evaluate(changed, resolved=self.resolve(changed))
        self.assertEqual(states(r)["drift"], "active")
        body = "\n".join(r["conditions"]["drift"]["body"])
        self.assertIn(self.app, body)
        self.assertIn(self.web, body)

    def test_a_registry_outage_is_incomplete_not_clean(self):
        self.set_registry(skip=[f"{APP}:1.0"])
        resolved = self.resolve(self.record)
        self.assertIsNotNone(resolved["images"][0]["error"])
        r = evaluate(self.record, resolved=resolved)
        self.assertEqual(states(r)["drift"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")

    def test_a_chart_outage_is_incomplete_not_clean(self):
        self.set_registry(skip=["registry.example.test/charts/oci:2.0.0"])
        r = evaluate(self.record, resolved=self.resolve(self.record))
        self.assertEqual(states(r)["drift"], "unknown")
        self.assertEqual(states(r)["incomplete"], "active")


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.doc = yaml.safe_load(cls.text)
        cls.tiers = (ROOT / ".github/workflows/tiers.yaml").read_text(encoding="utf-8")
        cls.jobs = cls.doc["jobs"]

    def runs(self):
        for name, job in self.jobs.items():
            for step in job.get("steps", []):
                if "run" in step:
                    yield name, step["run"]

    def test_the_triggers_are_the_daily_schedule_and_a_manual_run(self):
        on = self.doc.get("on", self.doc.get(True))
        self.assertEqual(on["schedule"], [{"cron": "0 20 * * *"}])
        self.assertIn("workflow_dispatch", on)
        self.assertEqual(set(on), {"schedule", "workflow_dispatch"})

    def test_the_top_level_permissions_are_empty(self):
        self.assertEqual(self.doc["permissions"], {})

    def test_every_job_has_only_the_permissions_it_needs(self):
        allowed = {"fetch": {"contents": "read"}, "resolve": {"contents": "read"}, "scan": {"contents": "read"},
                   "report": {"contents": "read", "issues": "write"}, "keepalive": {"actions": "write"}}
        self.assertEqual(set(self.jobs), set(allowed))
        for name, job in self.jobs.items():
            self.assertEqual(job["permissions"], allowed[name], name)

    def test_no_run_block_installs_a_package(self):
        for name, run in self.runs():
            self.assertNotRegex(run, r"pip3? +install|python3? +-m +pip|apt(-get)? +install|npm +install|curl[^\n]*\| *(ba)?sh", name)

    def test_no_run_block_holds_an_expression(self):
        for name, run in self.runs():
            self.assertNotIn("${{", run, name)
            self.assertNotIn("github.event", run, name)

    def test_the_file_never_reads_the_event_payload(self):
        self.assertNotIn("${{ github.event.", self.text)
        self.assertNotIn("github.head_ref", self.text)

    def test_every_action_is_pinned_to_a_sha_that_tiers_uses(self):
        pinned = set(re.findall(r"uses: (\S+@[0-9a-f]{40})", self.text))
        self.assertTrue(pinned)
        self.assertEqual(len(re.findall(r"uses: ", self.text)), len(re.findall(r"uses: \S+@[0-9a-f]{40} #", self.text)))
        promote = (ROOT / ".github/workflows/promote.yaml").read_text(encoding="utf-8")
        for action in pinned:
            self.assertTrue(action in self.tiers or action in promote, action)
        for action in pinned & set(re.findall(r"uses: (\S+@[0-9a-f]{40})", self.tiers)):
            name = action.split("@")[0]
            self.assertEqual({a for a in re.findall(r"uses: (\S+@[0-9a-f]{40})", self.tiers) if a.startswith(name + "@")},
                             {action}, name)

    def test_checkouts_keep_no_credentials(self):
        for name, job in self.jobs.items():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False, name)

    def test_the_container_is_the_devenv_tag_of_tiers(self):
        tier_tags = set(re.findall(r"container: (ghcr\.io/bbaliyan/kube-devenv:\S+)", self.tiers))
        self.assertEqual(len(tier_tags), 1)
        for name in ("fetch", "scan", "report"):
            self.assertIn(self.jobs[name]["container"], tier_tags, name)

    def test_the_host_job_runs_no_python_of_its_own(self):
        self.assertNotIn("container", self.jobs["resolve"])
        for run in (s["run"] for s in self.jobs["resolve"]["steps"] if "run" in s):
            self.assertNotIn("python", run)

    def test_the_docker_hub_token_is_only_in_the_login_steps(self):
        for name, job in self.jobs.items():
            for step in job.get("steps", []):
                blob = json.dumps(step)
                if "secrets." in blob:
                    self.assertEqual(step["name"], "Docker Hub login for pulls", name)
                    self.assertIn(name, ("resolve", "scan"))
                    self.assertEqual(set(step["env"]), {"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"})
        self.assertEqual(sorted(set(re.findall(r"secrets\.(\w+)", self.text))), ["DOCKERHUB_TOKEN", "DOCKERHUB_USERNAME"])

    def test_only_the_report_job_can_write_issues_and_it_has_no_registry_login(self):
        report = json.dumps(self.jobs["report"])
        self.assertNotIn("DOCKERHUB", report)
        self.assertNotIn("PROMOTE_DEPLOY_KEY", self.text)
        self.assertNotIn("id-token", self.text)

    def test_the_keepalive_enables_this_workflow_with_no_checkout(self):
        steps = self.jobs["keepalive"]["steps"]
        self.assertEqual(len(steps), 1)
        self.assertIn("--method PUT", steps[0]["run"])
        self.assertIn("actions/workflows/stable-watch.yaml/enable", steps[0]["run"])
        self.assertNotIn("checkout", json.dumps(self.jobs["keepalive"]))
        self.assertNotIn("needs", self.jobs["keepalive"])

    def test_the_report_waits_for_every_result_and_runs_after_a_failure(self):
        self.assertEqual(set(self.jobs["report"]["needs"]), {"fetch", "resolve", "scan"})
        self.assertIn("!cancelled()", self.jobs["report"]["if"])

    def test_the_workflow_runs_only_one_at_a_time(self):
        self.assertEqual(self.doc["concurrency"], {"group": "stable-watch", "cancel-in-progress": False})

    def test_the_makefile_targets_exist(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for target in ("stable-watch-resolve", "stable-watch-scan", "test-stable-watch"):
            self.assertRegex(makefile, rf"(?m)^{target}:", target)
        self.assertIn("test-scripts: test-stable-watch", makefile)
        for make_target in re.findall(r"make (\S+)", " ".join(r for _, r in self.runs())):
            self.assertRegex(makefile, rf"(?m)^{re.escape(make_target)}:", make_target)

    def test_the_script_is_standard_library_at_module_level(self):
        import ast
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        names = {n.module if isinstance(n, ast.ImportFrom) else a.name for n in tree.body
                 if isinstance(n, (ast.Import, ast.ImportFrom)) for a in getattr(n, "names", [None])}
        local = {"promote"}
        self.assertTrue(all(m.split(".")[0] in sys.stdlib_module_names or m in local for m in names), names)


if __name__ == "__main__":
    unittest.main()
