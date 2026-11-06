#!/usr/bin/env python3
"""Tests for ci/security_gate.py, with synthetic scan results and a stand-in trivy command.

A script is needed because the checks run the gate as a program and compare its
verdict with a list of cases; no declarative tool does that. The decision cases
use scan results written in the test. tests/fixtures/security-gate holds a
trimmed Trivy report (real output for redis:6.0.0) that checks the parsing, and
a stand-in `trivy` for the scan command.

    tests/check-security-gate.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures/security-gate"
GATE = ROOT / "ci/security_gate.py"
sys.path.insert(0, str(ROOT / "ci"))
import promotion_record  # noqa: E402
import security_gate  # noqa: E402

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
TODAY = date(2026, 11, 6)
FRESH_DB = "2026-11-06T01:07:43.832840315Z"
OLD_DB = "2026-11-03T01:07:43Z"
D1, D2, D3 = ("sha256:" + c * 64 for c in "123")
APP, LIB = "quay.io/example/app", "docker.io/library/lib"


def image(repo, digest):
    return {"reference": f"{repo}:1.0", "digest": digest, "digestSource": "registry", "sources": ["rendered"]}


def record(*images, commit="a" * 40):
    return {"schemaVersion": 1, "commit": commit, "images": list(images), "charts": [], "notScanned": [],
            "scanner": {"name": None, "version": None, "databaseUpdatedAt": None}}


def finding(vuln_id, package="libc", severity="HIGH", fixed="2.0"):
    return {"id": vuln_id, "package": package, "installedVersion": "1.0", "fixedVersion": fixed, "severity": severity}


def result(img, *findings, error=None):
    return {"reference": img["reference"], "digest": img["digest"], "error": error, "findings": list(findings)}


def scan_of(*results, db=FRESH_DB, scanner=True):
    return {"scanner": {"name": "trivy", "version": "0.76.1", "databaseUpdatedAt": db} if scanner else None,
            "scannerError": None if scanner else "trivy: command not found",
            "results": list(results)}


def kev_of(*ids, released="2026-11-05T00:00:00Z"):
    return {"dateReleased": released, "count": len(ids), "vulnerabilities": [{"cveID": i} for i in ids]}


def decide(rec, scan, kev=None, ignored=None, problems=(), baseline=None):
    return security_gate.decide(rec, scan, kev if kev is not None else kev_of("CVE-2000-0001"),
                                ignored or {}, list(problems), baseline, NOW)


class Decision(unittest.TestCase):
    def baseline(self, *findings):
        """The record of the current stable: APP at D1 with the given findings."""
        old = image(APP, D1)
        out, reasons = decide(record(old, commit="b" * 40), scan_of(result(old, *findings)))
        self.assertEqual(reasons, [])
        return out

    def test_a_new_fixable_finding_blocks(self):
        base = self.baseline(finding("CVE-2026-0001"))
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0001"), finding("CVE-2026-0002"))),
                              baseline=base)
        self.assertEqual(len(reasons), 1)
        self.assertIn("CVE-2026-0002", reasons[0])
        self.assertEqual(out["scan"]["verdict"], "block")
        self.assertEqual({f["id"]: f["status"] for f in out["scan"]["findings"]},
                         {"CVE-2026-0001": "known", "CVE-2026-0002": "blocking"})

    def test_an_unchanged_set_passes(self):
        base = self.baseline(finding("CVE-2026-0001"))
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0001"))), baseline=base)
        self.assertEqual(reasons, [])
        self.assertEqual(out["scan"]["verdict"], "pass")
        self.assertEqual(out["scan"]["baselineCommit"], "b" * 40)

    def test_a_new_finding_without_a_fix_is_known_and_does_not_block(self):
        base = self.baseline()
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0003", fixed=None))), baseline=base)
        self.assertEqual(reasons, [])
        self.assertEqual(out["scan"]["findings"][0]["status"], "known")

    def test_a_new_medium_finding_is_counted_and_does_not_block(self):
        base = self.baseline()
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0004", severity="MEDIUM"))),
                              baseline=base)
        self.assertEqual(reasons, [])
        self.assertEqual((out["scan"]["findings"], out["scan"]["counts"]["otherSeverities"]), ([], 1))

    def test_a_kev_finding_blocks_even_without_a_fix(self):
        base = self.baseline()
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2020-1111", fixed=None))),
                              kev=kev_of("CVE-2020-1111"), baseline=base)
        self.assertEqual(len(reasons), 1)
        self.assertIn("KEV", reasons[0])
        self.assertEqual(out["scan"]["counts"]["kev"], 1)

    def test_a_kev_finding_of_low_severity_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2020-1111", severity="LOW"))),
                            kev=kev_of("CVE-2020-1111"), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)

    def test_a_kev_finding_blocks_an_unchanged_image(self):
        base = self.baseline(finding("CVE-2020-1111"))
        old = image(APP, D1)
        _, reasons = decide(record(old), scan_of(result(old, finding("CVE-2020-1111"))),
                            kev=kev_of("CVE-2020-1111"), baseline=base)
        self.assertEqual(len(reasons), 1)

    def test_a_promotion_with_no_change_is_not_blocked_by_an_old_finding(self):
        base = self.baseline(finding("CVE-2026-0001"))
        old = image(APP, D1)
        # The database learned of a fixable CRITICAL after the baseline was scanned.
        out, reasons = decide(record(old), scan_of(result(
            old, finding("CVE-2026-0001"), finding("CVE-2026-0099", severity="CRITICAL"))), baseline=base)
        self.assertEqual(reasons, [])
        self.assertEqual({f["id"]: f["status"] for f in out["scan"]["findings"]}["CVE-2026-0099"], "known")

    def test_a_new_image_with_a_fixable_finding_blocks(self):
        base = self.baseline()
        cand = image(LIB, D3)
        _, reasons = decide(record(image(APP, D1), cand),
                            scan_of(result(image(APP, D1)), result(cand, finding("CVE-2026-0005"))), baseline=base)
        self.assertEqual(len(reasons), 1)
        self.assertIn(LIB, reasons[0])

    def test_an_ignored_finding_does_not_block_and_stays_in_the_record(self):
        base = self.baseline()
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0002"))),
                              ignored={"CVE-2026-0002": "no fix reachable"}, baseline=base)
        self.assertEqual(reasons, [])
        self.assertEqual([f["status"] for f in out["scan"]["findings"]], ["ignored"])

    def test_an_ignore_problem_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand)), problems=["ignore: CVE-2026-0002 expired on 2026-10-01"],
                            baseline=self.baseline())
        self.assertEqual(reasons, ["ignore: CVE-2026-0002 expired on 2026-10-01"])

    def test_a_scanner_error_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand, error="FATAL: unable to pull"), ), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)
        self.assertIn("scan failed", reasons[0])

    def test_a_missing_scanner_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand), scanner=False), baseline=self.baseline())
        self.assertEqual(reasons, ["trivy: command not found"])

    def test_a_stale_database_blocks(self):
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand), db=OLD_DB), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)
        self.assertIn("database", reasons[0])
        self.assertEqual(out["scanner"]["databaseUpdatedAt"], OLD_DB)

    def test_a_database_just_inside_the_limit_passes(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand), db="2026-11-04T13:00:00Z"), baseline=self.baseline())
        self.assertEqual(reasons, [])

    def test_a_missing_image_blocks(self):
        a, b = image(APP, D2), image(LIB, D3)
        out, reasons = decide(record(a, b), scan_of(result(a)), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)
        self.assertIn(LIB, reasons[0])
        self.assertEqual((out["scan"]["imagesListed"], out["scan"]["imagesScanned"]), (2, 1))

    def test_a_missing_or_old_kev_file_blocks(self):
        cand = image(APP, D2)
        for kev in (None, {}, kev_of(), kev_of("CVE-2000-0001", released="2026-09-01T00:00:00Z")):
            _, reasons = security_gate.decide(record(cand), scan_of(result(cand)), kev, {}, [], self.baseline(), NOW)
            self.assertEqual(len(reasons), 1, kev)
            self.assertIn("KEV", reasons[0])

    def test_a_baseline_without_a_scan_summary_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand)), baseline=record(image(APP, D1)))
        self.assertEqual(len(reasons), 1)

    def test_the_first_promotion_has_no_baseline_and_only_kev_blocks(self):
        cand = image(APP, D2)
        out, reasons = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0002"))))
        self.assertEqual(reasons, [])
        self.assertIsNone(out["scan"]["baselineCommit"])

    def test_the_output_matches_the_schema_and_fills_the_scanner(self):
        base = self.baseline(finding("CVE-2026-0001"))
        cand = image(APP, D2)
        out, _ = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0002"))), baseline=base)
        self.assertEqual(promotion_record.validate_record(out), [])
        self.assertEqual(out["scanner"], {"name": "trivy", "version": "0.76.1", "databaseUpdatedAt": FRESH_DB})
        self.assertIn("blocking", security_gate.summary_of(out))

    def test_a_negative_database_age_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand), db="2026-11-07T00:00:00Z"), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)
        self.assertIn("future", reasons[0])

    def test_a_kev_file_dated_in_the_future_blocks(self):
        cand = image(APP, D2)
        _, reasons = decide(record(cand), scan_of(result(cand)),
                            kev=kev_of("CVE-2000-0001", released="2026-12-01T00:00:00Z"), baseline=self.baseline())
        self.assertEqual(len(reasons), 1)
        self.assertIn("future", reasons[0])

    def test_a_baseline_that_is_not_usable_blocks(self):
        cand = image(APP, D2)
        good = self.baseline()
        blocked = json.loads(json.dumps(good))
        blocked["scan"]["verdict"] = "block"
        partial = json.loads(json.dumps(good))
        partial["scan"]["imagesScanned"] = 0
        broken = json.loads(json.dumps(good))
        del broken["commit"]
        for name, baseline in (("blocked", blocked), ("partial", partial), ("invalid", broken)):
            _, reasons = decide(record(cand), scan_of(result(cand)), baseline=baseline)
            self.assertEqual(len(reasons), 1, name)
            self.assertIn("baseline is not usable", reasons[0])

    def test_the_schema_still_accepts_a_record_without_a_scan(self):
        self.assertEqual(promotion_record.validate_record(record(image(APP, D1))), [])

    def test_the_schema_rejects_a_bad_scan(self):
        cand = image(APP, D2)
        out, _ = decide(record(cand), scan_of(result(cand, finding("CVE-2026-0002"))), baseline=self.baseline())
        out["scan"]["verdict"] = "maybe"
        del out["scan"]["counts"]
        problems = " ".join(promotion_record.validate_record(out))
        self.assertIn("verdict", problems)
        self.assertIn("counts", problems)


class IgnoreFile(unittest.TestCase):
    def load(self, text, today=TODAY):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "ignore")
            path.write_text(text, encoding="utf-8")
            return security_gate.load_ignore(path, today)

    def test_a_valid_entry_is_accepted(self):
        entries, problems = self.load("# note\n\nCVE-2026-0001 exp:2026-12-01 reason:no fix, not reachable\n")
        self.assertEqual((entries, problems), ({"CVE-2026-0001": "no fix, not reachable"}, []))

    def test_an_entry_that_expires_today_is_accepted(self):
        self.assertEqual(self.load("CVE-2026-0001 exp:2026-11-06 reason:x\n")[1], [])

    def test_an_expired_entry_is_a_problem_and_is_not_applied(self):
        entries, problems = self.load("CVE-2026-0001 exp:2026-11-05 reason:x\n")
        self.assertEqual(entries, {})
        self.assertEqual(len(problems), 1)
        self.assertIn("expired on 2026-11-05", problems[0])

    def test_an_entry_without_a_date_or_a_reason_is_a_problem(self):
        _, problems = self.load("CVE-2026-0001 reason:x\nCVE-2026-0002 exp:2026-12-01\nCVE-2026-0003 exp:soon reason:x\n")
        self.assertEqual(len(problems), 3)

    def run_check(self, text, now="2026-11-06T00:00:00Z"):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "ignore")
            path.write_text(text, encoding="utf-8")
            return subprocess.run([sys.executable, "-I", str(GATE), "check-ignore", str(path), "--now", now],
                                  capture_output=True, text=True)

    def test_the_check_fails_on_an_expired_entry(self):
        res = self.run_check("CVE-2026-0001 exp:2026-10-01 reason:x\n")
        self.assertEqual(res.returncode, 1)
        self.assertIn("expired", res.stderr)

    def test_the_check_passes_on_a_valid_file(self):
        self.assertEqual(self.run_check("CVE-2026-0001 exp:2026-12-01 reason:x\n").returncode, 0)

    def test_a_bad_id_is_a_problem(self):
        entries, problems = self.load("everything exp:2026-12-01 reason:x\nCVE-26-1 exp:2026-12-01 reason:x\n")
        self.assertEqual((entries, len(problems)), ({}, 2))

    def test_a_ghsa_id_is_accepted(self):
        self.assertEqual(self.load("GHSA-hrxh-6v49-42gf exp:2026-12-01 reason:x\n")[1], [])

    def test_an_expiry_more_than_90_days_away_is_a_problem(self):
        self.assertEqual(self.load("CVE-2026-0001 exp:2027-02-04 reason:x\n")[1], [])
        entries, problems = self.load("CVE-2026-0001 exp:2027-02-05 reason:x\n")
        self.assertEqual(entries, {})
        self.assertIn("more than 90 days", problems[0])

    def test_the_ignore_file_of_the_repo_passes(self):
        res = subprocess.run([sys.executable, "-I", str(GATE), "check-ignore", str(ROOT / "ci/security-gate.trivyignore")],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)


class TrivyReport(unittest.TestCase):
    def test_parses_a_real_report(self):
        report = json.loads((FIXTURES / "trivy-report.json").read_text(encoding="utf-8"))
        self.assertEqual(security_gate.findings_of(report), [
            {"id": "CVE-2022-1664", "package": "dpkg", "installedVersion": "1.19.7", "fixedVersion": "1.19.8",
             "severity": "CRITICAL"},
            {"id": "CVE-2022-23806", "package": "stdlib", "installedVersion": "v1.13.10",
             "fixedVersion": "1.16.14, 1.17.7", "severity": "CRITICAL"},
        ])

    def test_a_clean_report_with_an_operating_system_has_no_findings(self):
        self.assertEqual(security_gate.findings_of(
            {"SchemaVersion": 2, "ArtifactName": "x", "Metadata": {"OS": {"Family": "alpine"}}}), [])

    def test_a_report_with_no_results_and_no_operating_system_is_an_error(self):
        report = json.loads((FIXTURES / "trivy-empty.json").read_text(encoding="utf-8"))
        with self.assertRaisesRegex(RuntimeError, "no packages detected"):
            security_gate.findings_of(report)

    def test_a_duplicate_finding_keeps_the_fix_and_the_highest_severity(self):
        def target(**v):
            return {"Vulnerabilities": [dict({"VulnerabilityID": "CVE-2026-0001", "PkgName": "stdlib",
                                              "InstalledVersion": "1.0"}, **v)]}
        for order in (({"Severity": "HIGH"}, {"Severity": "CRITICAL", "FixedVersion": "2.0"}),
                      ({"Severity": "CRITICAL", "FixedVersion": "2.0"}, {"Severity": "HIGH"})):
            report = {"SchemaVersion": 2, "ArtifactName": "x", "Results": [target(**v) for v in order]}
            self.assertEqual(security_gate.findings_of(report), [
                {"id": "CVE-2026-0001", "package": "stdlib", "installedVersion": "1.0", "fixedVersion": "2.0",
                 "severity": "CRITICAL"}])

    def test_output_that_is_not_a_report_is_an_error(self):
        with self.assertRaises(RuntimeError):
            security_gate.findings_of({"error": "boom"})


class Commands(unittest.TestCase):
    """The scan and decide commands, with the stand-in trivy."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def gate(self, *args, db=FRESH_DB, report="trivy-report.json", db_fail=False):
        env = dict(os.environ, PATH=f"{FIXTURES / 'bin'}{os.pathsep}{os.environ['PATH']}",
                   STUB_DB_UPDATED_AT=db, STUB_REPORT=str(FIXTURES / report), STUB_DB_FAIL="1" if db_fail else "0")
        return subprocess.run([sys.executable, "-I", str(GATE), *map(str, args)],
                              capture_output=True, text=True, env=env)

    def write(self, name, data):
        path = self.dir / name
        path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
        return path

    def scan_and_decide(self, rec, db=FRESH_DB, kev=None, **options):
        rec_path = self.write("record.json", rec)
        scan = self.gate("scan", "--record", rec_path, "--out", self.dir / "scan.json", "--attempts", 1, db=db,
                         **options)
        self.assertEqual(scan.returncode, 0, scan.stderr)
        ignore = self.write("ignore", "")
        return self.gate("decide", "--record", rec_path, "--scan", self.dir / "scan.json",
                         "--kev", self.write("kev.json", kev or kev_of("CVE-2000-0001", released="2026-11-05T00:00:00Z")),
                         "--ignore", ignore, "--no-baseline", "--out", self.dir / "out.json",
                         "--summary", self.dir / "summary.md", "--now", "2026-11-06T12:00:00Z")

    def test_scan_then_decide_passes_and_writes_the_record(self):
        res = self.scan_and_decide(record(image(APP, D1), image(LIB, D2)))
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads((self.dir / "out.json").read_text(encoding="utf-8"))
        self.assertEqual(out["scan"]["counts"]["known"], 4)
        self.assertEqual(out["scanner"]["version"], "0.76.1")
        self.assertIn("Verdict: **pass**", (self.dir / "summary.md").read_text(encoding="utf-8"))

    def test_a_scanner_failure_blocks_the_run(self):
        broken = {**image("quay.io/example/broken", D3)}
        res = self.scan_and_decide(record(image(APP, D1), broken))
        self.assertEqual(res.returncode, 1)
        self.assertIn("unable to find the specified image", res.stdout)
        out = json.loads((self.dir / "out.json").read_text(encoding="utf-8"))
        self.assertEqual((out["scan"]["verdict"], out["scan"]["imagesScanned"]), ("block", 1))

    def test_a_stale_database_blocks_the_run(self):
        res = self.scan_and_decide(record(image(APP, D1)), db=OLD_DB)
        self.assertEqual(res.returncode, 1)
        self.assertIn("database is", res.stdout)

    def test_a_scanner_that_reports_no_database_blocks_the_run(self):
        res = self.scan_and_decide(record(image(APP, D1)), db="none")
        self.assertEqual(res.returncode, 1)
        self.assertIn("cannot read the Trivy version", res.stdout)

    def test_a_kev_hit_in_a_real_report_blocks_the_run(self):
        res = self.scan_and_decide(record(image(APP, D1)), kev=kev_of("CVE-2022-23806", released="2026-11-05T00:00:00Z"))
        self.assertEqual(res.returncode, 1)
        self.assertIn("CVE-2022-23806", res.stdout)

    def test_an_image_with_no_packages_detected_blocks_the_run(self):
        res = self.scan_and_decide(record(image(APP, D1)), report="trivy-empty.json")
        self.assertEqual(res.returncode, 1)
        self.assertIn("no packages detected", res.stdout)

    def test_a_database_download_failure_blocks_the_run(self):
        res = self.scan_and_decide(record(image(APP, D1)), db_fail=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("failed to download the database", res.stdout)

    def test_a_scan_file_with_a_missing_image_blocks_the_run(self):
        rec = record(image(APP, D1), image(LIB, D2))
        self.scan_and_decide(record(image(APP, D1)))
        res = self.gate("decide", "--record", self.write("record.json", rec), "--scan", self.dir / "scan.json",
                        "--kev", self.write("kev.json", kev_of("CVE-2000-0001", released="2026-11-05T00:00:00Z")),
                        "--ignore", self.write("ignore", ""), "--no-baseline",
                        "--out", self.dir / "out.json", "--now", "2026-11-06T12:00:00Z")
        self.assertEqual(res.returncode, 1)
        self.assertIn("no scan result for", res.stdout)

    def test_an_expired_ignore_entry_blocks_the_run(self):
        rec_path = self.write("record.json", record(image(APP, D1)))
        self.gate("scan", "--record", rec_path, "--out", self.dir / "scan.json", "--attempts", 1)
        res = self.gate("decide", "--record", rec_path, "--scan", self.dir / "scan.json",
                        "--kev", self.write("kev.json", kev_of("CVE-2000-0001", released="2026-11-05T00:00:00Z")),
                        "--ignore", self.write("expired", "CVE-2022-1664 exp:2026-10-01 reason:x\n"),
                        "--no-baseline", "--out", self.dir / "out.json", "--now", "2026-11-06T12:00:00Z")
        self.assertEqual(res.returncode, 1)
        self.assertIn("expired on 2026-10-01", res.stdout)


class MakeTarget(unittest.TestCase):
    """The baseline is explicit: the Makefile refuses to run the gate without a choice."""

    def setUp(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")

    def make(self, *args):
        return subprocess.run(["make", "-C", str(ROOT), *args], capture_output=True, text=True)

    def test_neither_a_baseline_nor_a_first_promotion_fails(self):
        res = self.make("security-gate")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("BASELINE_RECORD", res.stderr)
        self.assertNotIn("security_gate.py scan", res.stdout)

    def test_both_fails(self):
        res = self.make("security-gate", "BASELINE_RECORD=x.json", "FIRST_PROMOTION=1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not both", res.stderr)

    def test_a_baseline_is_passed_on(self):
        res = self.make("-n", "security-gate", "BASELINE_RECORD=x.json")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('--baseline "x.json"', res.stdout)
        self.assertNotIn("--no-baseline", res.stdout)

    def test_a_first_promotion_passes_no_baseline(self):
        res = self.make("-n", "security-gate", "FIRST_PROMOTION=1")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("--no-baseline", res.stdout)


if __name__ == "__main__":
    unittest.main()
