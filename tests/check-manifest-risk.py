#!/usr/bin/env python3
"""Tests for ci/manifest_risk.py, with fixtures.

A script is needed because the checks run the tool as a program on small
rendered trees and compare its JSON result; no declarative tool does that.
tests/fixtures/manifest-risk/stable is a render of `stable`. Each directory in
cases/ holds files that replace or add to a copy of it (remove.txt lists files
to delete) and so makes a candidate.

    tests/check-manifest-risk.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests/fixtures/manifest-risk"
TOOL = ROOT / "ci/manifest_risk.py"
ALLOWLIST = FIX / "allowlist.yaml"


def candidate(case, dest):
    shutil.copytree(FIX / "stable", dest)
    case_dir = FIX / "cases" / case
    for f in case_dir.rglob("*.yaml"):
        target = dest / f.relative_to(case_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(f, target)
    remove = case_dir / "remove.txt"
    if remove.exists():
        for line in remove.read_text().split():
            (dest / line).unlink()


class ManifestRisk(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_tool(self, stable, cand, allowlist=ALLOWLIST, env=None):
        out = self.tmp / "out"
        res = subprocess.run(
            [sys.executable, str(TOOL), "--stable", str(stable), "--candidate", str(cand),
             "--allowlist", str(allowlist), "--out-dir", str(out)],
            capture_output=True, text=True, env={**os.environ, **(env or {})})
        return res, out

    def case(self, name, **kw):
        cand = self.tmp / f"cand-{name}"
        candidate(name, cand)
        res, out = self.run_tool(FIX / "stable", cand, **kw)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads((out / "manifest-risk.json").read_text()), (out / "manifest-risk.md").read_text()

    def classes(self, result, key="additions"):
        return sorted({r["class"] for r in result[key]})

    def test_unrelated_change_gives_an_empty_diff(self):
        result, text = self.case("unrelated")
        self.assertEqual(result["additions"], [])
        self.assertEqual(result["removals"], [])
        self.assertFalse(result["needsApproval"])
        self.assertIn("No change in the risk classes", text)

    def test_identical_renders_give_an_empty_diff(self):
        res, out = self.run_tool(FIX / "stable", FIX / "stable")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(json.loads((out / "manifest-risk.json").read_text())["needsApproval"])

    def test_rbac_is_detected(self):
        result, _ = self.case("rbac")
        self.assertEqual(self.classes(result), ["rbac"])
        details = [r["detail"] for r in result["additions"]]
        self.assertTrue(any('"verbs":["*"]' in d for d in details), details)
        self.assertTrue(any(d.startswith("binds") for d in details), details)
        self.assertTrue(result["needsApproval"])

    def test_webhook_is_detected(self):
        result, _ = self.case("webhook")
        self.assertEqual(self.classes(result), ["webhook"])
        self.assertTrue(result["needsApproval"])

    def test_hook_is_detected(self):
        result, _ = self.case("hook")
        self.assertEqual(self.classes(result), ["hook"])
        self.assertIn("helm.sh/hook=pre-install,pre-upgrade", result["additions"][0]["detail"])

    def test_privileged_hostpath_and_hostnetwork_are_detected(self):
        result, _ = self.case("privileged")
        self.assertEqual(self.classes(result), ["privileged"])
        details = sorted(r["detail"] for r in result["additions"])
        self.assertEqual(details, ["hostNetwork", "hostPath /", "privileged container agent"])

    def test_new_repository_inside_the_allowlist_needs_approval_but_is_not_flagged_as_outside(self):
        result, _ = self.case("image-allowed")
        self.assertEqual(self.classes(result), ["image"])
        self.assertEqual(result["additions"][0]["object"], "docker.io/grafana/loki")
        self.assertTrue(result["needsApproval"])

    def test_typosquat_repository_is_flagged_as_outside_the_allowlist(self):
        result, text = self.case("typosquat")
        self.assertEqual(self.classes(result), ["image", "registry"])
        self.assertEqual({r["object"] for r in result["additions"]}, {"docker.io/grafanna/grafana"})
        self.assertEqual([r["object"] for r in result["removals"]], ["docker.io/grafana/grafana"])
        self.assertIn("outside the allowlist", text)
        self.assertTrue(result["needsApproval"])

    def test_removal_alone_needs_no_approval(self):
        result, text = self.case("removal")
        self.assertEqual(result["additions"], [])
        self.assertEqual(len(result["removals"]), 1)
        self.assertFalse(result["needsApproval"])
        self.assertIn("No approval is needed", text)

    def test_github_output_carries_the_decision(self):
        gh = self.tmp / "github-output"
        self.case("rbac", env={"GITHUB_OUTPUT": str(gh)})
        self.assertIn("needs_approval=true", gh.read_text())
        gh.unlink()
        self.case("unrelated", env={"GITHUB_OUTPUT": str(gh)})
        self.assertIn("needs_approval=false", gh.read_text())

    def test_missing_or_empty_render_fails(self):
        res, _ = self.run_tool(self.tmp / "nowhere", FIX / "stable")
        self.assertEqual(res.returncode, 2)
        (self.tmp / "empty").mkdir()
        res, _ = self.run_tool(FIX / "stable", self.tmp / "empty")
        self.assertEqual(res.returncode, 2)

    def test_allowlist_entry_needs_a_reason_and_one_entry_per_registry(self):
        bad = self.tmp / "bad.yaml"
        bad.write_text("- registry: docker.io\n")
        res, _ = self.run_tool(FIX / "stable", FIX / "stable", allowlist=bad)
        self.assertEqual(res.returncode, 2)
        bad.write_text("- {registry: docker.io, reason: a}\n- {registry: docker.io, reason: b}\n")
        res, _ = self.run_tool(FIX / "stable", FIX / "stable", allowlist=bad)
        self.assertEqual(res.returncode, 2)

    def test_the_real_allowlist_loads(self):
        sys.path.insert(0, str(ROOT / "ci"))
        import manifest_risk
        allowed = manifest_risk.load_allowlist(ROOT / "ci/registry-allowlist.yaml")
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
