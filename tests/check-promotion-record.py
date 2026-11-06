#!/usr/bin/env python3
"""Tests for ci/promotion_record.py, with fixtures and stand-in docker and helm commands.

A script is needed because the checks run the builder as a program and compare
its JSON with a list; no declarative tool does that. The fixtures hold a small
rendered tree (tests/fixtures/promotion-record) with the cases a grep of
`image:` misses, and a runtime image list like the one the kind run writes.

    tests/check-promotion-record.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures/promotion-record"
BUILDER = ROOT / "ci/promotion_record.py"
sys.path.insert(0, str(ROOT / "ci"))
import promotion_record  # noqa: E402


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


# What a grep of `image:` finds in the fixtures, and so what the builder must beat.
def grep_image_lines():
    found = set()
    for f in (FIXTURES / "rendered").rglob("*.yaml"):
        for line in f.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*-?\s*image:\s*(\S+)\s*$", line)
            if m:
                found.add(m[1])
    return found


REGISTRY_ONLY = [  # images the fixtures hold, with a digest from the registry stand-in
    "docker.io/grafana/grafana:13.2.0",
    "docker.io/library/busybox:1.37",
    "nvcr.io/nvidia/k8s-device-plugin:v0.20.1",
    "nvcr.io/nvidia/k8s/dcgm-exporter:4.6.1-4.8.4-distroless",
    "nvcr.io/nvidia/cloud-native/k8s-driver-manager:v0.12.1",
    "quay.io/jetstack/cert-manager-acmesolver:v1.21.3",
    "quay.io/prometheus-operator/prometheus-config-reloader:v0.94.2",
    "quay.io/prometheus-operator/prometheus-operator:v0.94.2",
    "docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1",
]
DRIVER = "nvcr.io/nvidia/driver:595.91.07"
CILIUM = "quay.io/cilium/cilium@sha256:" + "b" * 64
TOOLKIT = "nvcr.io/nvidia/k8s/container-toolkit@sha256:" + "1" * 64
ECR = "ecr-public.aws.com/docker/library/redis:8.6.4-alpine"
MIRROR_ONLY = "mirror.gcr.io/library/redis:8.6.4-alpine"
OCI_CHART = "registry.example.test/charts/oci-chart:2.0.0_build1"


class Record(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.digests = Path(cls.tmp.name, "digests")
        refs = REGISTRY_ONLY + [OCI_CHART, MIRROR_ONLY]
        # Stand-ins see names as docker prints them: the reference as built.
        cls.digests.write_text("".join(f"{r} {sha(r)}\n" for r in refs), encoding="utf-8")
        cls.result = cls.run_builder(cls.digests)
        if cls.result.returncode:
            raise RuntimeError(cls.result.stderr)
        cls.record = json.loads(Path(cls.tmp.name, "record.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_builder(cls, digests, runtime="runtime-images.json", out="record.json"):
        env = dict(os.environ, PATH=f"{FIXTURES / 'bin'}{os.pathsep}{os.environ['PATH']}",
                   STUB_DIGESTS=str(digests), PROMOTION_RECORD_PAUSE="0")
        return subprocess.run(
            [sys.executable, "-I", str(BUILDER), "build", "--rendered", str(FIXTURES / "rendered"),
             "--runtime", str(FIXTURES / runtime), "--repo-root", str(FIXTURES / "repo"),
             "--out", str(Path(cls.tmp.name, out)), "--commit", "0" * 40],
            capture_output=True, text=True, env=env)

    def images(self):
        return {i["reference"]: i for i in self.record["images"]}

    def test_builds(self):
        self.assertEqual(self.result.returncode, 0, self.result.stderr)

    def test_record_matches_schema(self):
        self.assertEqual(promotion_record.validate_record(self.record), [])

    def test_lists_images_a_grep_of_image_misses(self):
        grepped = {promotion_record.reference(promotion_record.parse_ref(r)) for r in grep_image_lines()}
        for ref in (
            "quay.io/jetstack/cert-manager-acmesolver:v1.21.3",
            "quay.io/prometheus-operator/prometheus-config-reloader:v0.94.2",
                    "nvcr.io/nvidia/k8s/dcgm-exporter:4.6.1-4.8.4-distroless",
            "nvcr.io/nvidia/cloud-native/k8s-driver-manager:v0.12.1",
            TOOLKIT,
            "docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1",
        ):
            self.assertNotIn(ref, grepped, f"the grep finds {ref}, so the case proves nothing")
            self.assertIn(ref, self.images())

    def test_ignores_text_that_is_not_an_image(self):
        listed = " ".join(self.images())
        for text in ("never/listed", "not.an.image", "not-an-image-in-an-application"):
            self.assertNotIn(text, listed)

    def test_registry_digest_for_rendered_images(self):
        self.assertEqual(self.images()["docker.io/library/busybox:1.37"]["digest"],
                         sha("docker.io/library/busybox:1.37"))
        self.assertEqual(self.images()["docker.io/library/busybox:1.37"]["sources"], ["rendered", "runtime"])

    def test_runtime_digest_wins_and_runtime_only_images_are_listed(self):
        controller = self.images()["quay.io/jetstack/cert-manager-controller:v1.21.3"]
        self.assertEqual(controller["digest"], "sha256:" + "a" * 64)
        self.assertEqual(controller["sources"], ["rendered", "runtime"])

    def test_one_entry_per_repository_and_digest(self):
        cilium = self.images()[CILIUM]
        self.assertEqual((cilium["digest"], cilium["sources"], cilium["digestSource"]),
                         ("sha256:" + "b" * 64, ["rendered", "runtime"], "runtime"))
        self.assertEqual([i for i in self.images() if "cilium" in i], [CILIUM])
        digests = [(i["reference"].split("@")[0].split(":")[0], i["digest"]) for i in self.record["images"]]
        self.assertEqual(len(digests), len(set(digests)))

    def test_an_official_image_falls_back_to_a_mirror(self):
        self.assertEqual(self.images()[ECR]["digest"], sha(MIRROR_ONLY))

    def test_digest_source(self):
        by = {r: i["digestSource"] for r, i in self.images().items()}
        self.assertEqual(by["docker.io/library/busybox:1.37"], "registry")
        self.assertEqual(by["quay.io/jetstack/cert-manager-controller:v1.21.3"], "runtime")
        self.assertEqual(by[TOOLKIT], "registry")

    def test_a_disabled_gpu_component_is_skipped(self):
        listed = " ".join(self.images()) + json.dumps(self.record["notScanned"])
        for text in ("vgpu-manager", "sandbox-device-plugin", "helper"):
            self.assertNotIn(text, listed)

    def test_a_gpu_driver_tag_the_registry_lacks_is_not_scanned_and_not_fatal(self):
        self.assertNotIn(DRIVER, self.images())
        self.assertIn({"type": "unresolved-image", "name": DRIVER,
                       "reason": "the registry has no such tag; the operator builds the tag on the node"},
                      self.record["notScanned"])

    def test_text_that_looks_like_an_image_is_not_one(self):
        f = promotion_record.image_from_text
        self.assertIsNone(f("--selector=app.kubernetes.io/name:foo"))
        self.assertIsNone(f("app.kubernetes.io/name:foo"))
        self.assertIsNone(f("--listen=:8080"))
        self.assertEqual(f("--img=quay.io/x/y:foo"), "quay.io/x/y:foo")
        self.assertEqual(f("registry.example.test/x:1.2"), "registry.example.test/x:1.2")
        self.assertEqual(f("registry.example.test/x@sha256:" + "c" * 64), "registry.example.test/x@sha256:" + "c" * 64)

    def test_pinned_digest_is_kept(self):
        self.assertEqual(self.images()[TOOLKIT]["digest"], "sha256:" + "1" * 64)

    def test_charts(self):
        charts = {(c["name"], c["version"]): c for c in self.record["charts"]}
        self.assertEqual(set(charts), {("cert-manager", "v1.21.3"), ("oci-chart", "2.0.0+build1"),
                                       ("longhorn", "1.13.0")})
        self.assertEqual(len(self.record["charts"]), 3, "a trailing slash in the repository must not add a chart")
        self.assertEqual(charts[("cert-manager", "v1.21.3")]["repository"], "https://charts.jetstack.io")
        longhorn = charts[("longhorn", "1.13.0")]
        self.assertEqual(longhorn["repository"], "https://charts.longhorn.example.test")
        self.assertEqual(longhorn["digest"], sha("longhorn 1.13.0 https://charts.longhorn.example.test"))
        self.assertEqual(charts[("oci-chart", "2.0.0+build1")]["repository"], "oci://registry.example.test/charts")
        self.assertEqual(charts[("oci-chart", "2.0.0+build1")]["digest"], sha(OCI_CHART))

    def test_not_scanned_names_the_grafana_plugins(self):
        self.assertEqual([(n["type"], n["name"]) for n in self.record["notScanned"] if n["type"] == "grafana-plugin"],
                         [("grafana-plugin", "grafana-clock-panel"), ("grafana-plugin", "mssql")])

    def test_scanner_fields_are_left_for_the_gate(self):
        self.assertEqual(self.record["scanner"], {"name": None, "version": None, "databaseUpdatedAt": None})

    def test_fails_when_a_digest_cannot_be_resolved(self):
        short = Path(self.tmp.name, "short")
        short.write_text(self.digests.read_text(encoding="utf-8").replace(
            "docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1", "rancher/other:1"), encoding="utf-8")
        res = self.run_builder(short, out="short.json")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1", res.stderr)
        self.assertFalse(Path(self.tmp.name, "short.json").exists())

    def test_schema_rejects_a_bad_record(self):
        bad = json.loads(json.dumps(self.record))
        bad["images"][0]["digest"] = "latest"
        del bad["scanner"]
        problems = " ".join(promotion_record.validate_record(bad))
        self.assertIn("images/0/digest", problems)
        self.assertIn("scanner", problems)

    def test_schema_requires_commit_and_digest_source(self):
        bad = json.loads(json.dumps(self.record))
        del bad["commit"]
        del bad["images"][0]["digestSource"]
        problems = " ".join(promotion_record.validate_record(bad))
        self.assertIn("commit", problems)
        self.assertIn("digestSource", problems)

    def test_schema_checks_the_scanner_date(self):
        record = json.loads(json.dumps(self.record))
        record["scanner"]["databaseUpdatedAt"] = "2026-11-06T01:02:03Z"
        self.assertEqual(promotion_record.validate_record(record), [])
        record["scanner"]["databaseUpdatedAt"] = "yesterday"
        self.assertTrue(promotion_record.validate_record(record))


if __name__ == "__main__":
    unittest.main(verbosity=1)
