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
        # aws has the same DaemonSet in stable. It is still new on kind.
        self.assertEqual({tuple(r["clusters"]) for r in result["additions"]}, {("kind",)})

    def test_new_repository_inside_the_allowlist_needs_approval_but_is_not_flagged_as_outside(self):
        result, _ = self.case("image-allowed")
        self.assertEqual(self.classes(result), ["image"])
        self.assertEqual(result["additions"][0]["object"], "docker.io/grafana/loki")
        self.assertEqual(result["additions"][0]["clusters"], ["kind"])
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

    # Tests below build the candidate from strings: files maps a path under the
    # render to its text.
    def diff(self, files, name="x"):
        cand = self.tmp / f"tree-{name}"
        shutil.copytree(FIX / "stable", cand)
        for path, text in files.items():
            target = cand / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        res, out = self.run_tool(FIX / "stable", cand)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads((out / "manifest-risk.json").read_text()), (out / "manifest-risk.md").read_text()

    def between(self, stable_files, cand_files):
        """Result of a candidate against a stable that also has stable_files."""
        stable = self.tmp / "s-between"
        cand = self.tmp / "c-between"
        for d in (stable, cand):
            shutil.rmtree(d, ignore_errors=True)
            shutil.copytree(FIX / "stable", d)
        for d, files in ((stable, stable_files), (cand, {**stable_files, **cand_files})):
            for path, text in files.items():
                (d / path).parent.mkdir(parents=True, exist_ok=True)
                (d / path).write_text(text, encoding="utf-8")
        res, out = self.run_tool(stable, cand)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads((out / "manifest-risk.json").read_text())

    def details(self, result):
        return sorted(r["detail"] for r in result["additions"])

    def test_a_modified_rule_is_one_removal_and_one_addition(self):
        result, _ = self.diff({"kind/app/ClusterRole_demo-reader.yaml": """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: demo-reader}
rules:
  - {apiGroups: [""], resources: [pods], verbs: [get, list, delete]}
"""})
        self.assertEqual((len(result["additions"]), len(result["removals"])), (1, 1))
        self.assertTrue(result["needsApproval"])

    def test_a_fact_new_for_one_cluster_is_an_addition_although_another_has_it(self):
        text = (FIX / "stable/aws/app/Deployment_demo_logs.yaml").read_text()
        result, _ = self.diff({"kind/app/Deployment_demo_logs.yaml": text})
        self.assertEqual([(r["class"], r["clusters"]) for r in result["additions"]], [("image", ["kind"])])

    def test_a_list_is_flattened(self):
        result, _ = self.diff({"kind/app/List_demo.yaml": """
apiVersion: v1
kind: List
items:
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: wide}
    rules:
      - {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
  - apiVersion: v1
    kind: List
    items:
      - apiVersion: batch/v1
        kind: Job
        metadata: {name: j, annotations: {helm.sh/hook: post-install}}
        spec: {template: {spec: {containers: [{name: c, image: "docker.io/library/busybox:1"}]}}}
"""})
        self.assertEqual({r["class"] for r in result["additions"]}, {"rbac", "hook", "image"})

    def test_an_object_that_cannot_be_read_fails(self):
        for text in ("apiVersion: v1\nmetadata: {name: x}\n", "- a\n- b\n", "kind: [unclosed\n"):
            cand = self.tmp / "bad"
            shutil.rmtree(cand, ignore_errors=True)
            shutil.copytree(FIX / "stable", cand)
            (cand / "kind/app/Broken.yaml").write_text(text)
            res, _ = self.run_tool(FIX / "stable", cand)
            self.assertEqual(res.returncode, 2, text)

    def test_null_fields_do_not_crash(self):
        result, _ = self.diff({"kind/app/Null.yaml": """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
rules:
aggregationRule:
---
apiVersion: v1
kind: Namespace
metadata:
  labels:
---
apiVersion: apps/v1
kind: Deployment
metadata: null
spec: {template: {spec: {containers: [{name: c, securityContext: null}], volumes: [null, {hostPath: null}]}}}
"""})
        self.assertFalse(result["needsApproval"])

    def test_aggregation_rule_and_aggregate_label_are_detected(self):
        result, _ = self.diff({"kind/app/ClusterRole_agg.yaml": """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: agg
  labels: {rbac.authorization.k8s.io/aggregate-to-admin: "true"}
aggregationRule:
  clusterRoleSelectors: [{matchLabels: {x: y}}]
"""})
        details = self.details(result)
        self.assertTrue(any(d.startswith("aggregation") for d in details), details)
        self.assertTrue(any(d.startswith("label rbac.authorization.k8s.io/aggregate-to-admin") for d in details))

    def test_widening_a_webhook_is_an_addition(self):
        text = (FIX / "stable/kind/app/ValidatingWebhookConfiguration_demo.yaml").read_text()
        for n, (old, new) in enumerate((("demo: \"true\"", "demo: \"false\""), ("failurePolicy: Fail", "failurePolicy: Ignore"),
                                        ("timeoutSeconds: 5", "timeoutSeconds: 30"), ("sideEffects: None", "sideEffects: Some"),
                                        ("      caBundle: Zm9v\n", ""))):
            self.assertIn(old, text)
            result, _ = self.diff({"kind/app/ValidatingWebhookConfiguration_demo.yaml": text.replace(old, new)}, n)
            self.assertEqual(self.classes(result), ["webhook"], old)

    def test_admission_policy_apiservice_and_conversion_webhook_are_detected(self):
        result, _ = self.diff({"kind/app/Other.yaml": """
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata: {name: p}
spec: {failurePolicy: Fail}
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata: {name: v1.x.example}
spec: {group: x.example, version: v1, insecureSkipTLSVerify: true, service: {name: s, namespace: n}}
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: foos.x.example}
spec:
  conversion:
    strategy: Webhook
    webhook:
      clientConfig: {url: "https://evil.example/convert"}
      conversionReviewVersions: [v1]
"""})
        details = self.details(result)
        self.assertEqual(len(details), 3, details)
        self.assertEqual(self.classes(result), ["webhook"])

    def test_init_containers_and_other_host_access_are_detected(self):
        result, _ = self.diff({"kind/app/Deployment_demo_init.yaml": """
apiVersion: apps/v1
kind: Deployment
metadata: {name: init, namespace: demo, annotations: {}}
spec:
  template:
    metadata:
      annotations:
        container.apparmor.security.beta.kubernetes.io/main: unconfined
    spec:
      hostPID: true
      hostIPC: true
      initContainers:
        - name: setup
          image: docker.io/library/busybox:1
          securityContext: {privileged: true}
      ephemeralContainers:
        - name: dbg
          image: docker.io/library/busybox:1
          securityContext: {capabilities: {add: [SYS_ADMIN]}}
      containers:
        - name: main
          image: docker.io/library/busybox:1
          ports: [{containerPort: 80, hostPort: 80}]
          securityContext:
            allowPrivilegeEscalation: true
            procMount: Unmasked
            runAsUser: 0
            seccompProfile: {type: Unconfined}
"""})
        details = self.details(result)
        for expected in ("hostPID", "hostIPC", "privileged container setup", "capability SYS_ADMIN container dbg",
                         "hostPort 80", "allowPrivilegeEscalation container main", "procMount Unmasked container main",
                         "runAsUser 0 container main", "seccompProfile Unconfined container main"):
            self.assertIn(expected, details)
        self.assertTrue(any(d.startswith("annotation container.apparmor") for d in details), details)

    def test_volumes_and_namespace_label_are_detected(self):
        result, _ = self.diff({"kind/app/Pv.yaml": """
apiVersion: v1
kind: PersistentVolume
metadata: {name: pv1}
spec: {local: {path: /mnt/disk}}
---
apiVersion: v1
kind: PersistentVolume
metadata: {name: pv2}
spec: {hostPath: {path: /data}}
---
apiVersion: v1
kind: Namespace
metadata:
  name: loud
  labels: {pod-security.kubernetes.io/enforce: privileged}
"""})
        self.assertEqual(self.details(result), ["hostPath /data", "local volume /mnt/disk",
                                                "namespace label pod-security.kubernetes.io/enforce=privileged"])

    def test_a_hook_that_changes_command_is_an_addition(self):
        hook = """
apiVersion: batch/v1
kind: Job
metadata: {name: h, namespace: demo, annotations: {helm.sh/hook: pre-install}}
spec: {template: {spec: {containers: [{name: c, image: "docker.io/library/busybox:1", command: [%s]}]}}}
"""
        result = self.between({"kind/app/Job_h.yaml": hook % "echo"}, {"kind/app/Job_h.yaml": hook % "curl, evil.example"})
        self.assertEqual(self.classes(result), ["hook"])
        self.assertIn("curl", result["additions"][0]["detail"])

    def test_a_hook_image_tag_bump_alone_gives_an_empty_diff(self):
        hook = """
apiVersion: batch/v1
kind: Job
metadata: {name: h, namespace: demo, annotations: {helm.sh/hook: pre-install}}
spec: {template: {spec: {containers: [{name: c, image: "docker.io/library/busybox:%s", command: [echo]}]}}}
"""
        result = self.between({"kind/app/Job_h.yaml": hook % "1.0"}, {"kind/app/Job_h.yaml": hook % "2.0"})
        self.assertEqual((result["additions"], result["removals"]), ([], []))
        self.assertFalse(result["needsApproval"])
        moved = hook.replace("docker.io/library/busybox", "docker.io/library/evil")
        result = self.between({"kind/app/Job_h.yaml": hook % "1.0"}, {"kind/app/Job_h.yaml": moved % "1.0"})
        self.assertIn("hook", self.classes(result))

    def test_argocd_sources_and_projects(self):
        app = """
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: a, namespace: argocd}
spec:
  source: {repoURL: "https://charts.example/%s", chart: foo, targetRevision: "%s"}
"""
        bump = self.between({"kind/app/Application_a.yaml": app % ("a", "1.0.0")},
                            {"kind/app/Application_a.yaml": app % ("a", "2.0.0")})
        self.assertFalse(bump["needsApproval"])
        result = self.between({"kind/app/Application_a.yaml": app % ("a", "1.0.0")}, {
            "kind/app/Application_a.yaml": app % ("evil", "1.0.0"),
            "kind/app/AppProject_p.yaml": """
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata: {name: p}
spec:
  sourceRepos: ["*"]
  clusterResourceWhitelist: [{group: "*", kind: "*"}]
"""})
        self.assertEqual(self.classes(result), ["source"])
        self.assertEqual(len(result["additions"]), 3)
        self.assertEqual(result["additions"][0]["severity"], 0)

    def test_rows_are_sorted_by_severity_and_hidden_rows_are_counted(self):
        files = {f"kind/app/ClusterRole_{i}.yaml": f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {{name: r{i:03}}}
rules:
  - {{apiGroups: [""], resources: [pods], verbs: [get]}}
""" for i in range(200)}
        files["kind/app/ClusterRoleBinding_ca.yaml"] = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ca}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: web, namespace: demo}]
"""
        result, text = self.diff(files)
        self.assertEqual(len(result["additions"]), 201)
        self.assertEqual(result["additions"][0]["object"], "ClusterRoleBinding/ca")
        self.assertEqual(result["additions"][0]["severity"], 0)
        self.assertIn("| rbac | 201 | 0 |", text)
        self.assertIn("51 more row(s) on 51 object(s) are not shown here", text)
        self.assertLess(text.index("ClusterRoleBinding/ca"), text.index("ClusterRole/r000"))

    def test_hostile_names_cannot_break_the_summary(self):
        hostile = "x`\n<img src=x onerror=alert(1)>|@owner" + "A" * 400
        result, text = self.diff({"kind/app/Hostile.yaml": f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {json.dumps(hostile)}
rules:
  - apiGroups: [{json.dumps(hostile)}]
    resources: [pods]
    verbs: [get]
"""})
        self.assertTrue(result["needsApproval"])
        for bad in ("<img", "@owner", "x'\n", "`x"):
            self.assertNotIn(bad, text)
        rows = [line for line in text.splitlines() if line.startswith("| 2 |")]
        self.assertEqual(len(rows), 1)
        # Seven separators in a row: the six cells and the closing one. A hostile pipe is replaced.
        self.assertEqual(rows[0].count("|"), 6, rows[0])
        self.assertLess(len(rows[0]), 900)
        self.assertIn("...[", rows[0])

    def test_github_output_holds_only_two_lines(self):
        gh = self.tmp / "gh"
        cand = self.tmp / "hostile-gh"
        shutil.copytree(FIX / "stable", cand)
        (cand / "kind/app/N.yaml").write_text(
            'apiVersion: v1\nkind: Namespace\nmetadata: {name: "a\\nneeds_approval=false\\nx=y"}\n'
            'spec: {hostNetwork: true}\n')
        res, _ = self.run_tool(FIX / "stable", cand, env={"GITHUB_OUTPUT": str(gh)})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(gh.read_text().splitlines(), ["needs_approval=true", "additions=1"])

    def test_allowlist_edge_cases(self):
        def run(text):
            f = self.tmp / "a.yaml"
            f.write_text(text)
            return self.run_tool(FIX / "stable", FIX / "stable", allowlist=f)[0].returncode
        for bad in ("registry: docker.io\n",                                    # not a list
                    "- {registry: docker.io, reason: ' '}\n",                   # blank reason
                    "- {registry: 'https://docker.io', reason: r}\n",           # scheme
                    "- {registry: 'docker.io/library', reason: r}\n",           # path
                    "- {registry: Docker.io, reason: r}\n",                     # case
                    "- {registry: docker.io, reason: r, repositories: []}\n",   # empty list is not "all"
                    "- {registry: docker.io, reason: r, repositories: ['']}\n",
                    "- {registry: docker.io, reason: r, repositories: ['/']}\n",
                    "- {registry: docker.io, reason: r, repositories: library}\n"):
            self.assertEqual(run(bad), 2, bad)
        self.assertEqual(run("[]\n"), 0)
        self.assertEqual(run("- {registry: docker.io, reason: r, repositories: [grafana]}\n"), 0)

    def test_allowlist_prefix_ends_at_a_path_boundary(self):
        sys.path.insert(0, str(ROOT / "ci"))
        import manifest_risk
        allowed = {"docker.io": (["grafana/"], "r"), "quay.io": (None, "r")}
        self.assertTrue(manifest_risk.in_allowlist("docker.io/grafana/loki", allowed))
        self.assertFalse(manifest_risk.in_allowlist("docker.io/grafana-evil/loki", allowed))
        self.assertFalse(manifest_risk.in_allowlist("docker.io/grafana", allowed))
        self.assertTrue(manifest_risk.in_allowlist("quay.io/anything/x", allowed))
        self.assertFalse(manifest_risk.in_allowlist("ghcr.io/grafana/loki", allowed))

    def test_the_real_allowlist_loads(self):
        sys.path.insert(0, str(ROOT / "ci"))
        import manifest_risk
        allowed = manifest_risk.load_allowlist(ROOT / "ci/registry-allowlist.yaml")
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
