#!/usr/bin/env python3
"""Build the promotion record: one JSON file that says what a release of this repo contains.

A script is needed because no existing tool does the whole job. helm renders
the manifests, and docker buildx imagetools (or helm pull) resolves digests,
but nothing joins the rendered output, the images the kind end-to-end run
pulled, the chart digests and the runtime fetches into one file that has a
schema. The script runs those tools and does only the joining.

    ci/promotion_record.py build --rendered out/head --runtime out/runtime-images.json \
        --out out/promotion-record.json [--repo-root .] [--commit SHA]
    ci/promotion_record.py validate out/promotion-record.json

Inputs:
  --rendered  the output of ci/render.py: <cluster>/<app>/<object>.yaml
  --runtime   a JSON list of {"image", "imageID"} taken from the pods of the
              kind end-to-end run (ci/e2e/run.sh writes it)

Images come from two places, and the record holds the union:
  rendered  every image reference in the rendered objects. It is not a grep of
            `image:`. It also reads arguments and environment values that hold
            an image (the cert-manager solver, the Prometheus operator config
            reloader), a repository, image and version triple (the GPU
            operator's ClusterPolicy), and the untagged image of a
            system-upgrade Plan (rancher/rke2-upgrade). Digests come from the
            registry. The GPU driver tag is the one in the ClusterPolicy; the
            operator adds an OS suffix on the node, which the runtime list
            cannot show here because kind has no GPU.
  runtime   the images that running containers report. The digest in imageID
            is what the node pulled, so it wins over the registry.

Charts come from the Application sources and from the dependencies in
Chart.yaml files of this repo. The chart digest is the digest of the chart
archive (the same value as the index entry of a Helm repository) or the OCI
manifest digest.

notScanned lists what a container fetches at start and no image scan sees. Today
that is the Grafana plugins.

The scanner fields stay null. The security gate fills them in.

The command fails if a digest cannot be resolved. A record with a hole in it
must not look complete.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from render import load_docs  # noqa: E402

SCHEMA = Path(__file__).resolve().parent / "promotion-record.schema.json"
SCHEMA_VERSION = 1
SKIP_KINDS = {"CustomResourceDefinition", "Application", "ConfigMap", "Secret"}
PLUGIN_ENV = re.compile(r"^GF_(INSTALL_PLUGINS|PLUGINS_PREINSTALL(_SYNC|_ASYNC)?)$")
DIGEST = r"sha256:[a-f0-9]{64}"
REF_RE = re.compile(
    r"^(?P<name>(?:[A-Za-z0-9.-]+(?::\d+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)*)"
    r"(?::(?P<tag>\w[\w.-]{0,127}))?(?:@(?P<digest>" + DIGEST + "))?$")


def parse_ref(ref):
    """(name, tag, digest) of an image reference, with the registry written out
    (docker.io/library/redis), or None if the text is not an image reference."""
    m = REF_RE.match(ref)
    if not m:
        return None
    name, tag, digest = m["name"], m["tag"], m["digest"]
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", name
    if registry == "index.docker.io":
        registry = "docker.io"
    if registry == "docker.io" and "/" not in path:
        path = f"library/{path}"
    if not tag and not digest:
        tag = "latest"
    return f"{registry}/{path}", tag, digest


def has_registry(ref):
    first, slash, _ = ref.partition("/")
    return bool(slash) and ("." in first or ":" in first or first == "localhost")


def compose(repository, image, version):
    version = str(version)
    sep = "@" if version.startswith("sha256:") else ":"
    return f"{repository.rstrip('/')}/{image}{sep}{version}"


def with_plan_tags(obj):
    """A system-upgrade Plan names its image without a tag and takes the tag
    from spec.version, with + written as - (v1.37.1+rke2r1 -> v1.37.1-rke2r1)."""
    if obj.get("kind") != "Plan":
        return obj
    obj = copy.deepcopy(obj)
    spec = obj.get("spec", {})
    tag = str(spec.get("version", "")).replace("+", "-")
    for part in ("prepare", "upgrade"):
        image = (spec.get(part) or {}).get("image")
        if tag and isinstance(image, str) and parse_ref(image) and not re.search(r"[:@]", image.rsplit("/", 1)[-1]):
            spec[part]["image"] = f"{image}:{tag}"
    return obj


def image_from_text(text):
    """An image written inside an argument (--flag=ref) or an environment
    value. Strict: a registry host and a tag or digest, so ordinary
    arguments are not taken for images."""
    if text.startswith("--") and "=" in text:
        text = text.split("=", 1)[1]
    parsed = parse_ref(text) if has_registry(text) else None
    if parsed and (parsed[1] != "latest" or ":latest" in text or parsed[2]):
        return text
    return None


def images_in(node):
    """Every image reference below node."""
    found = set()
    if isinstance(node, dict):
        image = node.get("image")
        if isinstance(image, str) and image:
            repository, version = node.get("repository"), node.get("version")
            if isinstance(repository, str) and version not in (None, ""):
                found.add(compose(repository, image, version))
            elif parse_ref(image):
                found.add(image)
        for key in ("args", "command"):
            if isinstance(node.get(key), list):
                found |= {r for a in node[key] if isinstance(a, str) and (r := image_from_text(a))}
        if isinstance(node.get("name"), str) and isinstance(node.get("value"), str):
            if (r := image_from_text(node["value"])):
                found.add(r)
        for v in node.values():
            found |= images_in(v)
    elif isinstance(node, list):
        for v in node:
            found |= images_in(v)
    return found


def plugins_in(objs):
    """Grafana plugins that a pod installs at start: GF_*PLUGINS* environment
    variables, written inline or read from a ConfigMap of the same app."""
    config = {(o["metadata"].get("namespace"), o["metadata"]["name"]): o.get("data") or {}
              for o in objs if o.get("kind") == "ConfigMap"}
    found = set()

    def walk(node, ns):
        if isinstance(node, dict):
            if isinstance(node.get("name"), str) and PLUGIN_ENV.match(node["name"]):
                value = node.get("value")
                ref = (node.get("valueFrom") or {}).get("configMapKeyRef")
                if ref:
                    value = config.get((ns, ref["name"]), {}).get(ref["key"])
                found.update(p.strip() for p in str(value or "").split(",") if p.strip())
            for v in node.values():
                walk(v, ns)
        elif isinstance(node, list):
            for v in node:
                walk(v, ns)

    for o in objs:
        if o.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}:
            walk(o, o["metadata"].get("namespace"))
    return found


def read_rendered(rendered):
    """(rendered image references, Applications, plugin names)."""
    images, apps, plugins = set(), [], set()
    for app_dir in sorted(p for p in Path(rendered).glob("*/*") if p.is_dir()):
        objs = [d for f in sorted(app_dir.glob("*.yaml"))
                for d in load_docs(f.read_text(encoding="utf-8"))]
        apps += [o for o in objs if o.get("kind") == "Application"]
        for o in objs:
            if o.get("kind") not in SKIP_KINDS:
                images |= images_in(with_plan_tags(o))
        plugins |= plugins_in(objs)
    return images, apps, plugins


def chart_requests(apps, repo_root):
    """{(repository, name, version)} from Application sources and from the
    dependencies of the Chart.yaml files in this repo."""
    charts = set()
    for app in apps:
        spec = app.get("spec", {})
        for s in spec.get("sources") or [spec.get("source", {})]:
            if "chart" in s:
                repo = s["repoURL"] if "://" in s["repoURL"] else f"oci://{s['repoURL']}"
                charts.add((repo, s["chart"], str(s["targetRevision"])))
    files = [f for top in ("bootstrap", "platform") for f in Path(repo_root, top).glob("**/Chart.yaml")]
    for f in sorted(files):
        if "charts" in f.relative_to(repo_root).parts:
            continue
        for dep in (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("dependencies") or []:
            if dep.get("repository"):
                charts.add((dep["repository"], dep["name"], str(dep["version"])))
    return charts


def retry(fn, what, tries=3):
    for attempt in range(tries):
        try:
            return fn()
        except RuntimeError as e:
            if attempt == tries - 1:
                raise RuntimeError(f"{what}: {e}") from e
            time.sleep(float(os.environ.get("PROMOTION_RECORD_PAUSE", 2)) * (attempt + 1))


def run(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"{cmd[0]} exited {res.returncode}")
    return res.stdout.strip()


def registry_digest(ref):
    out = run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}"])
    if not re.fullmatch(DIGEST, out):
        raise RuntimeError(f"unexpected digest output {out!r}")
    return out


def chart_digest(repo, name, version):
    if repo.startswith("oci://"):
        return registry_digest(f"{repo[6:].rstrip('/')}/{name}:{version.replace('+', '_')}")
    with tempfile.TemporaryDirectory() as tmp:
        run(["helm", "pull", name, "--repo", repo, "--version", version, "--destination", tmp])
        archives = list(Path(tmp).glob("*.tgz"))
        if len(archives) != 1:
            raise RuntimeError(f"expected one archive, found {len(archives)}")
        return "sha256:" + hashlib.sha256(archives[0].read_bytes()).hexdigest()


def reference(parsed):
    name, tag, digest = parsed
    return (f"{name}:{tag}" if tag else name) + (f"@{digest}" if digest else "")


def runtime_images(path):
    """{reference: digest or None} from the pods' image and imageID."""
    found = {}
    for item in json.loads(Path(path).read_text(encoding="utf-8")):
        parsed = parse_ref(item["image"]) if item.get("image") else None
        if not parsed:
            continue
        ref = reference(parsed)
        m = re.search("@(" + DIGEST + ")$", item.get("imageID") or "")
        found[ref] = parsed[2] or (m[1] if m else found.get(ref))
    return found


def validate_record(record):
    import jsonschema
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(record), key=lambda e: list(map(str, e.path)))]


def build(args):
    images, apps, plugins = read_rendered(args.rendered)
    entries = {}
    for ref in images:
        parsed = parse_ref(ref)
        entries.setdefault(reference(parsed), {"digest": parsed[2], "sources": set()})["sources"].add("rendered")
    for ref, digest in runtime_images(args.runtime).items():
        entry = entries.setdefault(ref, {"digest": None, "sources": set()})
        entry["sources"].add("runtime")
        entry["digest"] = digest or entry["digest"]

    charts = sorted(chart_requests(apps, args.repo_root))
    errors, chart_digests = [], {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        pending_images = {ref: pool.submit(retry, lambda r=ref: registry_digest(r), ref)
                          for ref, e in entries.items() if not e["digest"]}
        pending_charts = {c: pool.submit(retry, lambda c=c: chart_digest(*c), f"chart {c[1]} {c[2]}")
                          for c in charts}
        for ref, fut in pending_images.items():
            try:
                entries[ref]["digest"] = fut.result()
            except RuntimeError as e:
                errors.append(str(e))
        for c, fut in pending_charts.items():
            try:
                chart_digests[c] = fut.result()
            except RuntimeError as e:
                errors.append(str(e))
    if errors:
        sys.exit("cannot resolve digests:\n  " + "\n  ".join(sorted(errors)))

    record = {
        "schemaVersion": SCHEMA_VERSION,
        "images": [{"reference": r, "digest": e["digest"], "sources": sorted(e["sources"])}
                   for r, e in sorted(entries.items())],
        "charts": [{"name": n, "version": v, "repository": r, "digest": chart_digests[(r, n, v)]}
                   for r, n, v in charts],
        "notScanned": [{"type": "grafana-plugin", "name": p,
                        "reason": "Grafana downloads the plugin when the pod starts"}
                       for p in sorted(plugins)],
        "scanner": {"name": None, "version": None, "databaseUpdatedAt": None},
    }
    if args.commit:
        record["commit"] = args.commit
    problems = validate_record(record)
    if problems:
        sys.exit("record does not match its schema:\n  " + "\n  ".join(problems))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}: {len(record['images'])} images, {len(record['charts'])} charts, "
          f"{len(record['notScanned'])} not scanned")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--rendered", required=True)
    b.add_argument("--runtime", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--repo-root", default=".")
    b.add_argument("--commit")
    v = sub.add_parser("validate")
    v.add_argument("file")
    args = ap.parse_args()
    if args.cmd == "build":
        build(args)
    else:
        problems = validate_record(json.loads(Path(args.file).read_text(encoding="utf-8")))
        if problems:
            sys.exit("\n".join(problems))
        print("ok")


if __name__ == "__main__":
    main()
