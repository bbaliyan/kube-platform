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
import threading
import types
import time
import unittest
import unittest.mock
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
    "quay.io/jetstack/cert-manager-controller:v1.21.3",
    "quay.io/argoproj/argocd:v3.6.0",
    "docker.io/library/alpine:3.23",
    "docker.io/library/nginx:1.29",
    "docker.io/grafana/grafana:13.2.0",
    "docker.io/library/busybox:1.37",
    "quay.io/jetstack/cert-manager-acmesolver:v1.21.3",
    "quay.io/prometheus-operator/prometheus-config-reloader:v0.94.2",
    "quay.io/prometheus-operator/prometheus-operator:v0.94.2",
    "docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1",
]
CILIUM = "quay.io/cilium/cilium@sha256:" + "b" * 64
PINNED = "registry.example.test/tools/pinned@sha256:" + "1" * 64
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
        # The tag of a pinned image resolves to the pinned digest, as it does when the pin is the index.
        cls.digests.write_text("".join(f"{r} {sha(r)}\n" for r in refs)
                               + f"quay.io/cilium/cilium:v1.20.4 {CILIUM.split('@')[1]}\n", encoding="utf-8")
        cls.result = cls.run_builder(cls.digests)
        if cls.result.returncode:
            raise RuntimeError(cls.result.stderr)
        cls.record = json.loads(Path(cls.tmp.name, "record.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def run_builder(cls, digests, runtime="runtime-images.json", out="record.json", missing=None, extra_env=None):
        env = dict(os.environ, PATH=f"{FIXTURES / 'bin'}{os.pathsep}{os.environ['PATH']}",
                   STUB_DIGESTS=str(digests), PROMOTION_RECORD_PAUSE="0")
        if missing:
            env["STUB_MISSING"] = str(missing)
        env.update(extra_env or {})
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

    def test_the_registry_digest_is_the_digest_and_the_runtime_digest_is_kept_apart(self):
        controller = self.images()["quay.io/jetstack/cert-manager-controller:v1.21.3"]
        self.assertEqual(controller["digest"], sha("quay.io/jetstack/cert-manager-controller:v1.21.3"))
        self.assertEqual(controller["runtimeDigests"], ["sha256:" + "a" * 64])
        self.assertTrue(controller["runtimeDiffers"])
        self.assertEqual(controller["sources"], ["rendered", "runtime"])

    def test_a_preloaded_archive_digest_is_never_the_digest(self):
        argocd = self.images()["quay.io/argoproj/argocd:v3.6.0"]
        self.assertEqual(argocd["digest"], sha("quay.io/argoproj/argocd:v3.6.0"))
        self.assertEqual((argocd["runtimeDigests"], argocd["runtimeDiffers"], argocd["sources"], argocd["digestSource"]),
                         (["sha256:" + "d" * 64], True, ["runtime"], "registry"))

    def test_the_flag_is_false_when_the_digests_agree_or_no_container_used_the_image(self):
        by = self.images()
        self.assertFalse(by[CILIUM]["runtimeDiffers"])
        self.assertEqual(by[CILIUM]["runtimeDigests"], ["sha256:" + "b" * 64])
        self.assertEqual((by[PINNED]["runtimeDigests"], by[PINNED]["runtimeDiffers"]), ([], False))

    def test_an_image_id_is_named_by_the_repository_of_its_image_id(self):
        hubble = self.images()["quay.io/cilium/hubble-ui@sha256:" + "f" * 64]
        self.assertEqual((hubble["digest"], hubble["digestSource"], hubble["runtimeDiffers"]),
                         ("sha256:" + "f" * 64, "pinned", False))
        listed = " ".join(self.images())
        self.assertNotIn("library/sha256", listed)
        self.assertNotIn("import-", listed)

    def test_one_entry_per_repository_and_digest(self):
        cilium = self.images()[CILIUM]
        self.assertEqual((cilium["digest"], cilium["sources"], cilium["digestSource"]),
                         ("sha256:" + "b" * 64, ["rendered", "runtime"], "pinned"))
        self.assertEqual([i for i in self.images() if "cilium/cilium" in i], [CILIUM])
        digests = [(i["reference"].split("@")[0].split(":")[0], i["digest"]) for i in self.record["images"]]
        self.assertEqual(len(digests), len(set(digests)))

    def test_an_official_image_falls_back_to_a_mirror(self):
        self.assertEqual(self.images()[ECR]["digest"], sha(MIRROR_ONLY))

    def test_digest_source(self):
        by = {r: i["digestSource"] for r, i in self.images().items()}
        self.assertEqual(by["docker.io/library/busybox:1.37"], "registry")
        self.assertEqual(by["quay.io/jetstack/cert-manager-controller:v1.21.3"], "registry")
        self.assertEqual(by[PINNED], "pinned")
        self.assertEqual(set(by.values()), {"registry", "pinned"})

    def test_a_pinned_digest_that_the_registry_does_not_serve_fails_the_build(self):
        missing = Path(self.tmp.name, "missing")
        missing.write_text(PINNED + "\n", encoding="utf-8")
        res = self.run_builder(self.digests, out="missing.json", missing=missing)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn(PINNED, res.stderr)
        self.assertFalse(Path(self.tmp.name, "missing.json").exists())

    def test_helm_test_images_are_not_scanned_and_are_listed(self):
        self.assertNotIn("bats/bats", " ".join(self.images()))
        self.assertIn({"type": "test-only", "name": "docker.io/bats/bats:1.12.0",
                       "reason": "only an object with helm.sh/hook: test uses it; it runs only when someone runs helm test"},
                      self.record["notScanned"])

    def test_an_image_that_a_test_pod_shares_with_a_workload_is_scanned(self):
        self.assertIn("docker.io/library/busybox:1.37", self.images())
        self.assertNotIn("docker.io/library/busybox:1.37", [n["name"] for n in self.record["notScanned"]])

    def test_an_image_in_a_hook_that_is_not_only_a_test_hook_is_scanned(self):
        self.assertIn("docker.io/library/alpine:3.23", self.images())
        self.assertIn("docker.io/library/nginx:1.29", self.images())
        self.assertEqual([n["name"] for n in self.record["notScanned"] if n["type"] == "test-only"],
                         ["docker.io/bats/bats:1.12.0"])

    def test_an_image_a_container_used_is_scanned_with_its_runtime_digest_kept(self):
        self.assertEqual(self.images()["docker.io/library/alpine:3.23"]["runtimeDigests"], ["sha256:" + "7" * 64])

    def test_version_1_records_are_rejected(self):
        old = json.loads(json.dumps(self.record))
        old["schemaVersion"] = 1
        self.assertIn("schemaVersion", " ".join(promotion_record.validate_record(old)))

    def test_the_runtime_fields_are_required(self):
        bad = json.loads(json.dumps(self.record))
        del bad["images"][0]["runtimeDiffers"]
        del bad["images"][0]["runtimeDigests"]
        problems = " ".join(promotion_record.validate_record(bad))
        self.assertIn("runtimeDiffers", problems)
        self.assertIn("runtimeDigests", problems)

    def test_digest_source_runtime_is_rejected(self):
        bad = json.loads(json.dumps(self.record))
        bad["images"][0]["digestSource"] = "runtime"
        self.assertIn("digestSource", " ".join(promotion_record.validate_record(bad)))

    def test_text_that_looks_like_an_image_is_not_one(self):
        f = promotion_record.image_from_text
        self.assertIsNone(f("--selector=app.kubernetes.io/name:foo"))
        self.assertIsNone(f("app.kubernetes.io/name:foo"))
        self.assertIsNone(f("--listen=:8080"))
        self.assertEqual(f("--img=quay.io/x/y:foo"), "quay.io/x/y:foo")
        self.assertEqual(f("registry.example.test/x:1.2"), "registry.example.test/x:1.2")
        self.assertEqual(f("registry.example.test/x@sha256:" + "c" * 64), "registry.example.test/x@sha256:" + "c" * 64)

    def test_pinned_digest_is_kept(self):
        self.assertEqual(self.images()[PINNED]["digest"], "sha256:" + "1" * 64)

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


class Resilience(unittest.TestCase):
    def transient(self, message="429 Too Many Requests", retry_after=0):
        return promotion_record.Transient(message, retry_after)

    def attempts(self, failures, jitter, pause="2"):
        """Run retry() against `failures` transient errors; return (result, waits)."""
        calls, waits = [], []

        def fn():
            calls.append(1)
            if len(calls) <= failures:
                raise self.transient()
            return "ok"
        with unittest.mock.patch.dict(os.environ, PROMOTION_RECORD_PAUSE=pause):
            return promotion_record.retry(fn, "ref", sleep=waits.append, jitter=lambda: jitter), waits

    def test_run_classifies_errors(self):
        def failure(text):
            done = subprocess.CompletedProcess([], 1, "", text)
            with unittest.mock.patch.object(subprocess, "run", return_value=done):
                try:
                    promotion_record.run(["x"])
                except RuntimeError as e:
                    return e
        for text in ("429 Too Many Requests", "toomanyrequests: rate limit", "503 Service Unavailable",
                     "i/o timeout", "connection reset by peer", "502 Bad Gateway"):
            self.assertIsInstance(failure(text), promotion_record.Transient, text)
        for text in ("MANIFEST_UNKNOWN: x", "404 Not Found", "unauthorized: authentication required",
                     "no such image: sha256:" + "1500" * 16):
            self.assertNotIsInstance(failure(text), promotion_record.Transient, text)

    def test_run_reads_retry_after(self):
        done = subprocess.CompletedProcess([], 1, "", "429 Too Many Requests\nRetry-After: 30")
        with unittest.mock.patch.object(subprocess, "run", return_value=done):
            with self.assertRaises(promotion_record.Transient) as raised:
                promotion_record.run(["x"])
        self.assertEqual(raised.exception.retry_after, 30)

    def test_a_transient_error_is_retried(self):
        result, waits = self.attempts(3, jitter=1)
        self.assertEqual((result, waits), ("ok", [2, 4, 8]))

    def test_a_permanent_error_is_not_retried(self):
        calls, waits = [], []

        def fn():
            calls.append(1)
            raise RuntimeError("MANIFEST_UNKNOWN")
        with self.assertRaisesRegex(RuntimeError, "ref: MANIFEST_UNKNOWN"):
            promotion_record.retry(fn, "ref", sleep=waits.append)
        self.assertEqual((len(calls), waits), (1, []))

    def test_jitter_keeps_the_wait_between_half_and_all_of_the_backoff(self):
        for jitter, expected in ((0, [1, 2, 4]), (1, [2, 4, 8])):
            self.assertEqual(self.attempts(3, jitter)[1], expected)

    def test_total_wait_stays_under_the_budget_and_one_wait_under_the_cap(self):
        def always_limited():
            raise self.transient()
        waits = []
        with unittest.mock.patch.dict(os.environ, PROMOTION_RECORD_PAUSE="2"):
            with self.assertRaises(RuntimeError):
                promotion_record.retry(always_limited, "ref", sleep=waits.append, jitter=lambda: 1)
        self.assertLessEqual(sum(waits), promotion_record.WAIT_BUDGET)
        self.assertLessEqual(max(waits), promotion_record.MAX_WAIT)
        self.assertGreater(sum(waits), 60)

    def test_retry_after_is_a_floor_for_the_wait(self):
        calls, waits = [], []

        def fn():
            calls.append(1)
            if len(calls) == 1:
                raise self.transient(retry_after=45)
            return "ok"
        with unittest.mock.patch.dict(os.environ, PROMOTION_RECORD_PAUSE="2"):
            promotion_record.retry(fn, "ref", sleep=waits.append, jitter=lambda: 0)
        self.assertEqual(waits, [45])

    def test_a_host_gets_its_own_limit(self):
        limits = promotion_record.HostLimits()
        ecr = limits.slot("public.ecr.aws")
        self.assertTrue(ecr.acquire(blocking=False))
        self.assertFalse(ecr.acquire(blocking=False))
        self.assertIs(limits.slot("public.ecr.aws"), ecr)
        other = limits.slot("quay.io")
        self.assertEqual(sum(other.acquire(blocking=False) for _ in range(10)), promotion_record.HostLimits.DEFAULT)

    def test_lookups_of_one_host_never_overlap_beyond_its_limit(self):
        limits, running, peak, lock = promotion_record.HostLimits(), [0], [0], threading.Lock()

        def lookup():
            with limits.slot("public.ecr.aws"):
                with lock:
                    running[0] += 1
                    peak[0] = max(peak[0], running[0])
                time.sleep(0.01)
                with lock:
                    running[0] -= 1
        threads = [threading.Thread(target=lookup) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(peak[0], promotion_record.HostLimits.LIMITS["public.ecr.aws"])

    def test_only_a_full_version_or_a_digest_is_immutable(self):
        for ref in ("quay.io/a/b:v1.2.3", "docker.io/library/redis:8.6.4-alpine", "x.io/a:1.2.3-r1",
                    "docker.io/rancher/rke2-upgrade:v1.37.1-rke2r1", "x.io/a@sha256:" + "1" * 64,
                    "x.io/a:latest@sha256:" + "1" * 64):
            self.assertTrue(promotion_record.immutable_image(ref), ref)
        for ref in ("x.io/a", "x.io/a:latest", "x.io/a:3.23", "x.io/a:1", "x.io/a:stable", "x.io/a:main",
                    "x.io/a:v1.2.3-latest", "x.io/a:1.2.3-nightly", "x.io/a:1.2.3-dev", "x.io/a:edge"):
            self.assertFalse(promotion_record.immutable_image(ref), ref)


class Cache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name, "digests.json"))

    def test_miss_hit_and_save(self):
        cache = promotion_record.DigestCache(self.path)
        self.assertIsNone(cache.get("k", True))
        cache.put("k", sha("a"), True)
        cache.save()
        self.assertEqual(promotion_record.DigestCache(self.path).get("k", True), sha("a"))

    def test_a_mutable_entry_is_neither_stored_nor_served(self):
        cache = promotion_record.DigestCache(self.path)
        cache.put("mutable", sha("a"), False)
        cache.save()
        self.assertFalse(Path(self.path).exists())
        Path(self.path).write_text(json.dumps({"mutable": sha("a")}), encoding="utf-8")
        self.assertIsNone(promotion_record.DigestCache(self.path).get("mutable", False))

    def test_a_corrupt_file_is_an_empty_cache(self):
        for text in ("{not json", "[1, 2]", "null", ""):
            Path(self.path).write_text(text, encoding="utf-8")
            self.assertEqual(promotion_record.DigestCache(self.path).entries, {}, text)

    def test_a_bad_entry_is_dropped_and_a_good_one_kept(self):
        Path(self.path).write_text(json.dumps({"a": "latest", "b": 5, "c": sha("c"), "d": "sha256:" + "G" * 64}),
                                   encoding="utf-8")
        self.assertEqual(promotion_record.DigestCache(self.path).entries, {"c": sha("c")})

    def test_no_path_means_no_cache(self):
        cache = promotion_record.DigestCache(None)
        cache.put("k", sha("a"), True)
        cache.save()
        self.assertIsNone(cache.get("k", True))

    def build(self, **env):
        digests = Path(self.tmp.name, "stub-digests")
        refs = REGISTRY_ONLY + [OCI_CHART, MIRROR_ONLY]
        digests.write_text("".join(f"{r} {sha(r)}\n" for r in refs)
                           + f"quay.io/cilium/cilium:v1.20.4 {CILIUM.split('@')[1]}\n", encoding="utf-8")
        res = Record.run_builder.__func__(types.SimpleNamespace(tmp=self.tmp), digests, extra_env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        record = json.loads(Path(self.tmp.name, "record.json").read_text(encoding="utf-8"))
        return {i["reference"]: i for i in record["images"]}

    def test_the_builder_caches_only_immutable_references(self):
        self.build(PROMOTION_RECORD_CACHE=self.path)
        cached = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertIn("quay.io/argoproj/argocd:v3.6.0", cached)
        for mutable in ("docker.io/library/alpine:3.23", "docker.io/library/nginx:1.29"):
            self.assertNotIn(mutable, cached)

    def test_the_cache_is_used_only_when_asked_for(self):
        ref = "quay.io/argoproj/argocd:v3.6.0"
        poisoned = "sha256:" + "f" * 64
        Path(self.path).write_text(json.dumps({ref: poisoned}), encoding="utf-8")
        self.assertEqual(self.build(PROMOTION_RECORD_CACHE=self.path)[ref]["digest"], poisoned)
        # The promotion path sets no cache variable, so the poisoned entry never reaches it.
        self.assertEqual(self.build()[ref]["digest"], sha(ref))


if __name__ == "__main__":
    unittest.main(verbosity=1)
