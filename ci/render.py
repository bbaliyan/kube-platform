#!/usr/bin/env python3
"""Render the platform for each cluster in ci/clusters/ the way Argo CD would.

Each file in ci/clusters/ is a cluster's root `platform` Application. It is
expanded into the manifests its sources produce, and every Application those
contain (bootstrap's children, observability's children, ...) is expanded in
turn, so the output is everything Argo CD would end up applying. Sources in
this repo are rendered from the checkout being tested, whatever revision they
name, so a PR's changes show up; upstream Helm charts are fetched at their
pinned targetRevision. Secret values are redacted so the output is safe to
post in a PR comment.

Output is one file per Kubernetes object: <out>/<cluster>/<app>/<object>.yaml

    python ci/render.py <repo-root> <out-dir>
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import yaml

CLUSTERS_DIR = "ci/clusters"
THIS_REPO = re.compile(r"github\.com[/:]bbaliyan/kube-platform(\.git)?/?$", re.I)
OPENAPI = "https://raw.githubusercontent.com/kubernetes/kubernetes/v{}/api/openapi-spec/swagger.json"

# API groups a platform cluster serves that no rendered CRD declares: RKE2's
# own, and those whose controllers install their CRDs at runtime.
RUNTIME_APIS = [
    "cilium.io/v2", "cilium.io/v2alpha1",
    "helm.cattle.io/v1", "helm.cattle.io/v1/HelmChart", "helm.cattle.io/v1/HelmChartConfig",
    "k3s.cattle.io/v1", "k3s.cattle.io/v1/Addon", "k3s.cattle.io/v1/ETCDSnapshotFile",
    "metrics.k8s.io/v1beta1", "metrics.k8s.io/v1beta1/NodeMetrics", "metrics.k8s.io/v1beta1/PodMetrics",
    "upgrade.cattle.io/v1", "upgrade.cattle.io/v1/Plan",
]

# Fields of an Application source this renderer implements. Anything else
# fails the render rather than being silently ignored.
SOURCE_KEYS = {"repoURL", "targetRevision", "path", "chart", "ref", "helm", "name"}
HELM_KEYS = {"releaseName", "valueFiles", "values", "valuesObject", "parameters"}


def kube_version(root):
    """The Kubernetes version the clusters run: KUBE_VERSION, else k8sVersion
    from platform-versions (v1.37.1+rke2r1 -> 1.37.1)."""
    if os.environ.get("KUBE_VERSION"):
        return os.environ["KUBE_VERSION"]
    values = yaml.safe_load(Path(root, "platform/platform-versions/values.yaml").read_text(encoding="utf-8"))
    return values["k8sVersion"].lstrip("v").split("+")[0]


class Loader(yaml.SafeLoader):
    """SafeLoader that reads a bare `=` (an enum value in the Prometheus
    operator CRDs) as the string it is, not YAML 1.1's obsolete value tag."""


Loader.add_constructor("tag:yaml.org,2002:value", Loader.construct_yaml_str)


def load_docs(text):
    return [d for d in yaml.load_all(text, Loader=Loader) if isinstance(d, dict)]


def run(cmd, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", **kw)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{res.stderr.strip()}")
    return res.stdout


def builtin_apis(version):
    """group/version and group/version/Kind for every resource Kubernetes
    serves, from its published OpenAPI: what Argo CD passes as --api-versions."""
    with urllib.request.urlopen(OPENAPI.format(version)) as resp:
        spec = json.load(resp)
    apis = set()
    for path, ops in spec["paths"].items():
        # Top-level resources only: no subresources, no watch endpoints.
        if "/watch/" in path or not path.endswith("}") or re.search(r"\{name\}/", path):
            continue
        for op in ops.values():
            gvk = isinstance(op, dict) and op.get("x-kubernetes-group-version-kind")
            if gvk:
                gv = f"{gvk['group']}/{gvk['version']}" if gvk["group"] else gvk["version"]
                apis |= {gv, f"{gv}/{gvk['kind']}"}
    return apis


def crd_apis(docs):
    apis = set()
    for d in docs:
        if d.get("kind") == "CustomResourceDefinition":
            spec = d["spec"]
            for v in spec.get("versions", []):
                if v.get("served", True):
                    gv = f"{spec['group']}/{v['name']}"
                    apis |= {gv, f"{gv}/{spec['names']['kind']}"}
    return apis


def drop_nulls(v):
    """The API server drops null fields when it stores an Application, so a
    valuesObject key templated to null never reaches Helm (where a null would
    delete the chart's default instead)."""
    if isinstance(v, dict):
        return {k: drop_nulls(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [drop_nulls(x) for x in v]
    return v


def set_value(v):
    """Argo CD escapes commas in a parameter unless it is a {list}."""
    v = str(v)
    return v if v.startswith("{") and v.endswith("}") else re.sub(r"(?<!\\),", r"\\,", v)


def slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()


class Renderer:
    def __init__(self, root, work, kube_version):
        self.root = Path(root).resolve()
        self.work = Path(work)
        self.kube_version = kube_version
        self.charts = {}
        self.git_cache = {}
        self.built = set()

    def tmpfile(self, stem):
        return self.work / f"{stem}-{len(os.listdir(self.work))}.yaml"

    def git_checkout(self, url, rev):
        """Shallow-fetch an external git source at a branch, tag, commit or
        HEAD, as Argo CD accepts; returns its path."""
        key = (url, rev)
        if key not in self.git_cache:
            dest = self.work / f"git-{len(self.git_cache)}"
            run(["git", "init", "-q", str(dest)])
            run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", url, rev])
            run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"])
            self.git_cache[key] = dest
        return self.git_cache[key]

    def repo_dir(self, url, rev):
        return self.root if THIS_REPO.search(url) else self.git_checkout(url, rev or "HEAD")

    def pull_chart(self, url, chart, rev):
        """Download an upstream chart once per run, however many clusters use it."""
        key = (url, chart, rev)
        if key not in self.charts:
            dest = self.work / "charts" / slug(f"{url}-{chart}-{rev}")
            if "://" not in url:  # Argo CD writes OCI repos without a scheme
                args = [f"oci://{url}/{chart}"]
            else:
                args = [chart, "--repo", url]
            run(["helm", "pull", *args, "--version", rev, "--untar", "--untardir", str(dest)])
            self.charts[key] = dest / chart
        return self.charts[key]

    def build_deps(self, d):
        deps = (yaml.safe_load((d / "Chart.yaml").read_text(encoding="utf-8")) or {}).get("dependencies") or []
        if not deps or d in self.built:
            return
        # Argo CD registers dependency repos itself; a fresh helm doesn't.
        for dep in deps:
            repo = dep.get("repository", "")
            if repo.startswith(("http://", "https://")):
                run(["helm", "repo", "add", "--force-update", slug(repo.split("://", 1)[1]), repo])
        # Like Argo CD, resolve from Chart.yaml rather than a stale local lock.
        (d / "Chart.lock").unlink(missing_ok=True)
        run(["helm", "dependency", "build", "--skip-refresh", str(d)])
        self.built.add(d)

    def helm_template(self, app, src, chart_dir, refs, apis):
        helm = src.get("helm", {})
        if set(helm) - HELM_KEYS:
            raise RuntimeError(f"unsupported helm fields: {sorted(set(helm) - HELM_KEYS)}")
        name = helm.get("releaseName") or app["metadata"]["name"]
        ns = app["spec"]["destination"].get("namespace", "default")
        cmd = ["helm", "template", name, str(chart_dir), "--namespace", ns,
               "--include-crds", "--kube-version", self.kube_version]
        for v in sorted(apis):
            cmd += ["--api-versions", v]
        for vf in helm.get("valueFiles", []):
            if vf.startswith("$"):
                ref, _, rest = vf[1:].partition("/")
                if ref not in refs:
                    raise RuntimeError(f"unresolvable valueFile {vf}")
                cmd += ["--values", str(refs[ref] / rest)]
            else:
                cmd += ["--values", str(chart_dir / vf)]
        # Argo CD uses valuesObject when set and ignores values.
        if helm.get("valuesObject"):
            f = self.tmpfile(f"values-obj-{name}")
            f.write_text(yaml.safe_dump(drop_nulls(helm["valuesObject"])), encoding="utf-8")
            cmd += ["--values", str(f)]
        elif helm.get("values"):
            f = self.tmpfile(f"values-{name}")
            f.write_text(helm["values"], encoding="utf-8")
            cmd += ["--values", str(f)]
        for p in helm.get("parameters", []):
            flag = "--set-string" if p.get("forceString") else "--set"
            cmd += [flag, f"{p['name']}={set_value(p.get('value', ''))}"]
        # Helm 4 prints "Pulled: ... Digest: ..." for OCI charts on stdout,
        # which parses as a YAML mapping; keep only Kubernetes objects.
        return [d for d in load_docs(run(cmd)) if "apiVersion" in d and "kind" in d]

    def render_source(self, app, src, refs, apis):
        if set(src) - SOURCE_KEYS:
            raise RuntimeError(f"unsupported source fields: {sorted(set(src) - SOURCE_KEYS)}")
        if "ref" in src and "path" not in src and "chart" not in src:
            return []
        if "chart" in src:
            d = self.pull_chart(src["repoURL"], src["chart"], str(src["targetRevision"]))
            return self.helm_template(app, src, d, refs, apis)
        d = self.repo_dir(src["repoURL"], src.get("targetRevision")) / src.get("path", ".")
        if (d / "Chart.yaml").exists():
            self.build_deps(d)
            return self.helm_template(app, src, d, refs, apis)
        # A plain directory, non-recursive: Argo CD's default.
        docs = []
        for f in sorted(p for p in d.iterdir() if p.suffix in (".yaml", ".yml", ".json")):
            docs += load_docs(f.read_text(encoding="utf-8"))
        return docs

    def render_app(self, app, apis):
        spec = app["spec"]
        sources = spec.get("sources") or [spec["source"]]
        refs = {s["ref"]: self.repo_dir(s["repoURL"], s.get("targetRevision"))
                for s in sources if "ref" in s}
        docs = []
        for s in sources:
            docs += self.render_source(app, s, refs, apis)
        return docs


class Dumper(yaml.SafeDumper):
    """Writes multi-line strings (inline Helm values, scripts, dashboards) as
    | blocks, so their diffs read line by line. Trailing spaces, which block
    style can't hold, are dropped: the output is for review and validation,
    never applied."""


def _str(dumper, s):
    if "\n" in s:
        s = "\n".join(l.rstrip() for l in s.split("\n"))
        return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", s)


Dumper.add_representer(str, _str)


def redact(obj):
    if obj.get("kind") == "Secret":
        for field in ("data", "stringData"):
            if isinstance(obj.get(field), dict):
                obj[field] = {k: "<redacted>" for k in obj[field]}
    return obj


def object_filename(obj):
    md = obj.get("metadata", {})
    group = obj.get("apiVersion", "").rpartition("/")[0]
    parts = [obj.get("kind", "Unknown"), group, md.get("namespace", ""), md.get("name", "unnamed")]
    return re.sub(r"[^A-Za-z0-9._-]", "_", "_".join(p for p in parts if p)) + ".yaml"


def write_objects(out, docs, where):
    out.mkdir(parents=True, exist_ok=True)
    written = set()
    for obj in docs:
        name = object_filename(obj)
        if name in written:
            # Argo CD applies one and warns (RepeatedResourceWarning).
            print(f"::warning file={where}::{out.parent.name}/{out.name} renders {name[:-5]} more than once")
        written.add(name)
        (out / name).write_text(
            yaml.dump(redact(obj), Dumper=Dumper, sort_keys=True, width=120), encoding="utf-8")


def expand(r, root_app, apis):
    """Render root_app and every Application beneath it.
    Returns ({app name: objects}, {failed app name: error})."""
    rendered, failures, queue = {}, {}, [root_app]
    while queue:
        app = queue.pop(0)
        name = app.get("metadata", {}).get("name", "?")
        try:
            if name in rendered or name in failures:
                raise RuntimeError(f"Application {name} is rendered twice")
            docs = r.render_app(app, apis)
        except Exception as e:  # one broken app shouldn't hide the rest
            failures[name] = e
            continue
        rendered[name] = docs
        queue += [d for d in docs if d.get("kind") == "Application"]
    return rendered, failures


def render_cluster(r, root, f, out, builtins):
    where = f.relative_to(root).as_posix()
    roots = load_docs(f.read_text(encoding="utf-8"))
    # Charts that check .Capabilities for a CRD the cluster's own platform
    # installs see it the way they would live: render once to collect the
    # CRDs, then again with them in --api-versions.
    apis = builtins | set(RUNTIME_APIS)
    while True:
        rendered, failures = {}, {}
        for app in roots:
            res, fail = expand(r, app, apis)
            rendered.update(res)
            failures.update(fail)
        found = crd_apis(d for docs in rendered.values() for d in docs)
        if found <= apis:
            break
        apis |= found
    # The root Application is applied by hand or by kube-compute, so its own
    # manifest is part of what changes too.
    write_objects(out / "_root", roots, where)
    for name, docs in rendered.items():
        write_objects(out / name, docs, where)
        print(f"rendered {f.stem}/{name}")
    for name, e in failures.items():
        print(f"::error file={where}::{f.stem}/{name} failed to render\n{e}")
    return [f"{f.stem}/{n}" for n in failures]


def main():
    root, out = Path(sys.argv[1]), Path(sys.argv[2])
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    version = kube_version(root)
    builtins = builtin_apis(version)
    failures = []
    with tempfile.TemporaryDirectory() as work:
        r = Renderer(root, work, version)
        for f in sorted((root / CLUSTERS_DIR).glob("*.y*ml")):
            failures += render_cluster(r, root, f, out / f.stem, builtins)
    if failures:
        sys.exit(f"{len(failures)} Application(s) failed to render: {', '.join(failures)}")


if __name__ == "__main__":
    main()
