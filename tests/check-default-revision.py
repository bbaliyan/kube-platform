#!/usr/bin/env python3
"""Tests that clusters follow `stable` by default and the kind run still tests the commit.

A script is needed because the checks read rendered Helm output and the
example cluster files together; no declarative tool compares them. It needs
helm, as `make render` does.

    tests/check-default-revision.py
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def load(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def helm_bootstrap(*extra):
    out = subprocess.run(
        ["helm", "template", "bootstrap", str(ROOT / "bootstrap"),
         "-f", str(ROOT / "platform/platform-versions/values.yaml"), *extra],
        check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if isinstance(d, dict)]


def own_repo_sources(apps):
    """Sources of this repo: those that name a path or a ref and no chart."""
    for app in apps:
        spec = app.get("spec") or {}
        for source in spec.get("sources") or [spec.get("source") or {}]:
            if "chart" not in source and ("path" in source or "ref" in source):
                yield app["metadata"]["name"], source


class DefaultRevision(unittest.TestCase):
    def test_values_default_to_stable(self):
        self.assertEqual(load("bootstrap/values.yaml")["platformRevision"], "stable")
        self.assertEqual(load("platform/observability/values.yaml")["platformRevision"], "stable")

    def test_default_render_uses_stable(self):
        apps = [d for d in helm_bootstrap(
            "--set", "clusterFqdnSuffix=kind.test",
            "--set-json", 'storageProvisioners=[{"name":"local-path","type":"local-path"}]')
            if d.get("kind") == "Application"]
        own = list(own_repo_sources(apps))
        self.assertGreater(len(own), 8, "too few sources of this repo found")
        for name, source in own:
            self.assertEqual(source["targetRevision"], "stable", name)
        observability = next(a for a in apps if a["metadata"]["name"] == "observability")
        params = {p["name"]: p["value"] for p in observability["spec"]["source"]["helm"]["parameters"]}
        self.assertEqual(params["platformRevision"], "stable")

    def test_revision_can_be_overridden(self):
        apps = [d for d in helm_bootstrap("--set", "platformRevision=main") if d.get("kind") == "Application"]
        revisions = {s["targetRevision"] for _, s in own_repo_sources(apps)}
        self.assertEqual(revisions, {"main"})

    def test_example_clusters_follow_stable(self):
        files = sorted((ROOT / "ci/clusters").glob("*.yaml"))
        self.assertGreaterEqual(len(files), 5)
        for f in files:
            app = yaml.safe_load(f.read_text(encoding="utf-8"))
            for source in app["spec"]["sources"]:
                self.assertEqual(source["targetRevision"], "stable", f.name)
                for p in source.get("helm", {}).get("parameters", []):
                    if p["name"] == "platformRevision":
                        self.assertEqual(p["value"], "stable", f.name)
            names = [p["name"] for s in app["spec"]["sources"] for p in s.get("helm", {}).get("parameters", [])]
            self.assertIn("platformRevision", names, f.name)

    def test_kind_run_still_tests_the_commit(self):
        out = subprocess.run(
            [sys.executable, str(ROOT / "ci/e2e/point-at-commit.py"), str(ROOT / "ci/clusters/kind.yaml"), COMMIT],
            check=True, capture_output=True, text=True).stdout
        app = yaml.safe_load(out)
        for source in app["spec"]["sources"]:
            self.assertEqual(source["targetRevision"], COMMIT)
        values = [p["value"] for s in app["spec"]["sources"] for p in s.get("helm", {}).get("parameters", [])
                  if p["name"] == "platformRevision"]
        self.assertEqual(values, [COMMIT])
        self.assertNotIn("stable", out)

    def test_no_text_says_clusters_follow_main(self):
        pattern = re.compile(r"(clusters?|argo cd)[^.\n]{0,40}(follow|sync|track)[^.\n]{0,20}`?main\b"
                             r"|syncs this repo's `?main", re.I)
        files = [ROOT / "README.md", ROOT / "ci/README.md", ROOT / "renovate.json", ROOT / "bootstrap/values.yaml"]
        for f in files:
            for number, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                self.assertIsNone(pattern.search(line), f"{f.name}:{number}: {line}")


if __name__ == "__main__":
    unittest.main()
