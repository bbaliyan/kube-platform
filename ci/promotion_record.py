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
            reloader), and the untagged image of a system-upgrade Plan
            (rancher/rke2-upgrade). Digests come from the registry.
  runtime   the images that running containers report. A container whose image
            field is only an image ID (the kubelet shows sha256:... for an image
            that a digest pins) is named by the repository in its imageID.

Test hooks. An image that only objects with the annotation `helm.sh/hook: test`
(or test-success, test-failure, and no other phase) reference, and that no container of the kind run used, is not in `images`. A
`helm test` pod never runs in a cluster unless someone runs `helm test`, and
Argo CD does not run it. Such an image is listed in notScanned as `test-only`.

Charts come from the Application sources and from the dependencies in
Chart.yaml files of this repo. The chart digest is the digest of the chart
archive (the same value as the index entry of a Helm repository) or the OCI
manifest digest.

notScanned lists what a container fetches at start and no image scan sees (the
Grafana plugins).

Every image has one digest, and the registry serves it. That is the digest the
security gate scans. digestSource says how the record got it. registry: the
registry returned it for the tag when the record was built (the digest of the
image index, as `docker buildx imagetools inspect` prints it). pinned: the
digest is written in the reference, and the registry served it when the record
was built. The node may have pulled another digest. The kind run loads its
images from single-platform archives, so the imageID of a running container
can be a digest that no registry serves. That digest is kept apart in
runtimeDigests, with runtimeDiffers true when it is not the record digest. It
is information only and nothing scans it.

The scanner fields stay null. The security gate fills them in.

Registries rate limit anonymous pulls from a shared runner address. So each
registry host has a limit on parallel lookups, and only a transient error (a
rate limit, a server error, a network fault) is retried, with a growing wait,
jitter and any Retry-After. PROMOTION_RECORD_CACHE=FILE adds a cache of the
digests that cannot change: a digest in the reference, or a full version tag
such as v1.2.3. Only the pull request record job sets it. The promotion
workflows never do, so a promotion always asks the registry.

The command fails if a digest cannot be resolved. A record with a hole in it
must not look complete.
"""

import argparse
import copy
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA = Path(__file__).resolve().parent / "promotion-record.schema.json"
# 2: digest is always a digest the registry serves; digestSource is registry or
# pinned; runtimeDigests and runtimeDiffers are new; notScanned has test-only.
SCHEMA_VERSION = 2
SKIP_KINDS = {"CustomResourceDefinition", "Application", "ConfigMap", "Secret"}
KNOWN_REGISTRIES = {"docker.io", "ghcr.io", "quay.io", "gcr.io", "registry.k8s.io", "k8s.gcr.io", "nvcr.io",
                    "public.ecr.aws", "mcr.microsoft.com", "registry.gitlab.com", "lscr.io", "cgr.dev",
                    "localhost"}
KNOWN_REGISTRY_SUFFIXES = (".gcr.io", ".pkg.dev", ".amazonaws.com")
TEST_HOOKS = {"test", "test-success", "test-failure"}
IMAGE_ID = re.compile(r"^(sha256:)?[a-f0-9]{64}$")
VERSION_TAG = re.compile(r"^v?\d[\w.-]*$")
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
    if not parsed or not (":" in text.rsplit("/", 1)[-1] or parsed[2]):
        return None
    host = text.split("/", 1)[0].split(":")[0]
    known = host in KNOWN_REGISTRIES or host.endswith(KNOWN_REGISTRY_SUFFIXES)
    # app.kubernetes.io/name:foo has the shape of an image. Unless the host is
    # a known registry, only a version tag or a digest makes it one.
    if known or parsed[2] or VERSION_TAG.match(parsed[1] or ""):
        return text
    return None


def images_in(node):
    """Every image reference below node."""
    found = set()
    if isinstance(node, dict):
        image = node.get("image")
        if isinstance(image, str) and parse_ref(image):
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


def is_test_hook(obj):
    """True when every hook phase of the object is a test phase. An object that
    also has a phase such as post-install runs in a cluster."""
    hooks = ((obj.get("metadata") or {}).get("annotations") or {}).get("helm.sh/hook") or ""
    phases = {h.strip() for h in str(hooks).split(",") if h.strip()}
    return bool(phases) and phases <= TEST_HOOKS


def read_rendered(rendered):
    """(rendered image references, Applications, plugin names). The references
    include those of helm test objects."""
    images, test_images, apps, plugins = read_rendered_split(rendered)
    return images | test_images, apps, plugins


def read_rendered_split(rendered):
    """(image references of the other objects, image references of helm test
    objects, Applications, plugin names)."""
    from render import load_docs  # imported here: ci/stable_watch.py resolve runs without PyYAML
    images, test_images, apps, plugins = set(), set(), [], set()
    for app_dir in sorted(p for p in Path(rendered).glob("*/*") if p.is_dir()):
        objs = [d for f in sorted(app_dir.glob("*.yaml"))
                for d in load_docs(f.read_text(encoding="utf-8"))]
        apps += [o for o in objs if o.get("kind") == "Application"]
        for o in objs:
            if o.get("kind") not in SKIP_KINDS:
                (test_images if is_test_hook(o) else images).update(images_in(with_plan_tags(o)))
        plugins |= plugins_in(objs)
    return images, test_images, apps, plugins


def chart_requests(apps, repo_root):
    """{(repository, name, version)} from Application sources and from the
    dependencies of the Chart.yaml files in this repo."""
    import yaml  # imported here: ci/stable_watch.py resolve runs without PyYAML
    charts = set()
    for app in apps:
        spec = app.get("spec", {})
        for s in spec.get("sources") or [spec.get("source", {})]:
            if "chart" in s:
                repo = s["repoURL"] if "://" in s["repoURL"] else f"oci://{s['repoURL']}"
                charts.add((repo.rstrip("/"), s["chart"], str(s["targetRevision"])))
    files = [f for top in ("bootstrap", "platform") for f in Path(repo_root, top).glob("**/Chart.yaml")]
    for f in sorted(files):
        if "charts" in f.relative_to(repo_root).parts:
            continue
        for dep in (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("dependencies") or []:
            if dep.get("repository"):
                charts.add((dep["repository"].rstrip("/"), dep["name"], str(dep["version"])))
    return charts


class Transient(RuntimeError):
    """A failure that a later attempt can cure: a rate limit, a server error, a network fault."""

    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = retry_after


TRANSIENT = re.compile(r"\b429\b|too many requests|toomanyrequests|rate limit|\b5\d\d\b|timeout|timed out"
                       r"|connection (reset|refused)|\bEOF\b|temporary failure|handshake|unavailable", re.I)
RETRY_AFTER = re.compile(r"retry-after\W+(\d+)", re.I)
MAX_WAIT = 60  # seconds for one wait; a rate limit window is often 1 minute
WAIT_BUDGET = 170  # seconds of waiting for one reference, under 3 minutes in total
MAX_TRIES = 8


def retry(fn, what, sleep=time.sleep, jitter=random.random):
    """Retry only a Transient error. The wait doubles from PROMOTION_RECORD_PAUSE
    seconds up to MAX_WAIT, is cut by up to half at random so that parallel
    lookups do not return together, and is never shorter than a Retry-After
    the tool printed. Waiting stops when WAIT_BUDGET is used up."""
    base, waited = float(os.environ.get("PROMOTION_RECORD_PAUSE", 2)), 0.0
    for attempt in range(MAX_TRIES):
        try:
            return fn()
        except Transient as e:
            wait = max(min(MAX_WAIT, base * 2 ** attempt) * (0.5 + 0.5 * jitter()),
                       min(MAX_WAIT, e.retry_after) if base else 0)
            if attempt == MAX_TRIES - 1 or waited + wait > WAIT_BUDGET:
                raise RuntimeError(f"{what}: {e}") from e
            waited += wait
            sleep(wait)
        except RuntimeError as e:
            raise RuntimeError(f"{what}: {e}") from e


class HostLimits:
    """At most N lookups at once per registry host. A public registry that
    rate limits anonymous pulls per shared address gets 1 or 2."""
    LIMITS = {"public.ecr.aws": 1, "ecr-public.aws.com": 1, "docker.io": 2, "mirror.gcr.io": 2}
    DEFAULT = 4

    def __init__(self):
        self._lock, self._semaphores = threading.Lock(), {}

    def slot(self, host):
        with self._lock:
            return self._semaphores.setdefault(host, threading.BoundedSemaphore(self.LIMITS.get(host, self.DEFAULT)))


def host_of(url_or_ref):
    return re.sub(r"^\w+://", "", url_or_ref).split("/")[0]


# A full version only. 3.23, 1.29, latest, stable and main move; v1.2.3 and 1.2.3-r1 do not.
IMMUTABLE_TAG = re.compile(r"^v?\d+\.\d+\.\d+(?:[-.+_](?!.*(?:latest|stable|main|master|nightly|dev|edge|snapshot|rolling))[\w.]+)?$",
                           re.I)


def immutable_image(ref):
    parsed = parse_ref(ref)
    return bool(parsed and (parsed[2] or (parsed[1] and IMMUTABLE_TAG.match(parsed[1]))))


class DigestCache:
    """Digests that cannot change, kept between runs in a JSON file. It is off
    unless PROMOTION_RECORD_CACHE names a file, and only the pull request
    record job sets that. A missing or corrupt file is an empty cache."""

    def __init__(self, path):
        self.path, self.entries, self.added = path, {}, {}
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}
            self.entries = {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)
                            and re.fullmatch(DIGEST, v)}
        except (OSError, ValueError, AttributeError):
            pass

    def get(self, key, cacheable):
        return self.entries.get(key) if cacheable else None

    def put(self, key, digest, cacheable):
        if self.path and cacheable:
            self.added[key] = digest

    def save(self):
        if not self.path or not self.added:
            return
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        tmp = f"{self.path}.tmp"
        Path(tmp).write_text(json.dumps({**self.entries, **self.added}, indent=1, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.replace(tmp, self.path)


def run(cmd):
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        message = res.stderr.strip() or f"{cmd[0]} exited {res.returncode}"
        if TRANSIENT.search(message):
            found = RETRY_AFTER.search(message)
            raise Transient(message, int(found[1]) if found else 0)
        raise RuntimeError(message)
    return res.stdout.strip()


def sources_of(ref):
    """Where to ask for the digest. A Docker Official Image has the same
    digest on Docker Hub, the AWS public mirror and mirror.gcr.io (ci/e2e/preload-images.sh
    relies on the same fact), and Docker Hub and AWS refuse anonymous requests
    from a shared address."""
    for prefix in ("ecr-public.aws.com/docker/library/", "docker.io/library/"):
        if ref.startswith(prefix):
            rest = ref[len(prefix):]
            alternatives = [f"docker.io/library/{rest}", f"mirror.gcr.io/library/{rest}"]
            return [ref] + [a for a in alternatives if a != ref]
    return [ref]


def registry_digest(ref):
    error = None
    for source in sources_of(ref):
        try:
            out = run(["docker", "buildx", "imagetools", "inspect", source, "--format", "{{.Manifest.Digest}}"])
        except RuntimeError as e:
            error = error if isinstance(error, Transient) else e  # a rate limit decides whether to retry
            continue
        if not re.fullmatch(DIGEST, out):
            raise RuntimeError(f"unexpected digest output {out!r}")
        return out
    raise error


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
    """{reference: set of digests the nodes report} from the pods' image and
    imageID. An image that is only an ID (sha256:...) takes its name from the
    imageID, which then is repository@digest. An imageID of the import-*
    repository (a preloaded archive) names no registry, so the digest is kept
    for the image field's reference only."""
    found = {}
    for item in json.loads(Path(path).read_text(encoding="utf-8")):
        image = item.get("image") or ""
        m = re.search(r"^(.*)@(" + DIGEST + ")$", item.get("imageID") or "")
        if IMAGE_ID.match(image):
            named = m and not re.search(r"/import-[\d-]+$", m[1])
            parsed = parse_ref(f"{m[1]}@{m[2]}") if named else None
        else:
            parsed = parse_ref(image) if image else None
        if not parsed:
            continue
        digests = found.setdefault(reference(parsed), set())
        if parsed[2]:
            digests.add(parsed[2])
        elif m:
            digests.add(m[2])
    return found


def validate_record(record):
    import jsonschema
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(record), key=lambda e: list(map(str, e.path)))]


def repository_of(ref):
    name = ref.split("@")[0]
    head, _, last = name.rpartition("/")
    return f"{head}/{last.split(':')[0]}" if head else last.split(":")[0]


def merge_entries(entries):
    """One entry per repository and digest. Where several references share a
    digest, the reference is name@digest."""
    groups = {}
    for ref, e in entries.items():
        groups.setdefault((repository_of(ref), e["digest"]), []).append((ref, e))
    merged = []
    for (name, digest), members in sorted(groups.items()):
        sources = sorted({x for _, e in members for x in e["sources"]})
        source = "pinned" if any(e["digestSource"] == "pinned" for _, e in members) else "registry"
        runtime = sorted({d for _, e in members for d in e["runtimeDigests"]})
        ref = members[0][0] if len(members) == 1 else f"{name}@{digest}"
        merged.append({"reference": ref, "digest": digest, "digestSource": source, "sources": sources,
                       "runtimeDigests": runtime, "runtimeDiffers": any(d != digest for d in runtime)})
    return merged


def build(args):
    images, test_images, apps, plugins = read_rendered_split(args.rendered)
    runtime = runtime_images(args.runtime)
    entries = {}

    def entry_key(ref):
        parsed = parse_ref(ref)
        # A tag written beside a digest adds nothing the digest does not say.
        return reference((parsed[0], None if parsed[2] else parsed[1], parsed[2]))

    def entry_for(ref):
        key, pinned = entry_key(ref), parse_ref(ref)[2]
        return key, entries.setdefault(key, {"digest": pinned, "digestSource": "pinned" if pinned else "registry",
                                             "sources": set(), "runtimeDigests": set()})

    for ref in images:
        key, entry = entry_for(ref)
        entry["sources"].add("rendered")
    for ref, digests in runtime.items():
        key, entry = entry_for(ref)
        entry["sources"].add("runtime")
        entry["runtimeDigests"] |= digests
    # An image that only a helm test object names, and no container of the kind run used, is not scanned.
    test_only = sorted({entry_key(r) for r in test_images} - set(entries))

    charts = sorted(chart_requests(apps, args.repo_root))
    errors, chart_digests = [], {}
    limits, cache = HostLimits(), DigestCache(os.environ.get("PROMOTION_RECORD_CACHE"))

    def lookup(key, host, cacheable, fn, what):
        """The cached digest, else fn() under the limit of its host. The pool is wide and the host limit is narrow."""
        if (hit := cache.get(key, cacheable)):
            return hit
        with limits.slot(host):
            digest = retry(fn, what)
        cache.put(key, digest, cacheable)
        return digest

    with ThreadPoolExecutor(max_workers=16) as pool:
        # A pinned digest is asked for too: the record never holds a digest the registry does not serve.
        pending_images = {ref: pool.submit(lookup, ref, parse_ref(ref)[0].split("/")[0], immutable_image(ref),
                                           lambda r=ref: registry_digest(r), ref) for ref in entries}
        pending_charts = {c: pool.submit(lookup, "chart|" + "|".join(c), host_of(c[0]), bool(IMMUTABLE_TAG.match(c[2])),
                                         lambda c=c: chart_digest(*c), f"chart {c[1]} {c[2]}")
                          for c in charts}
        for ref, fut in pending_images.items():
            try:
                served = fut.result()
                if entries[ref]["digest"] and served != entries[ref]["digest"]:
                    raise RuntimeError(f"{ref}: the registry returned {served}")
                entries[ref]["digest"] = served
            except RuntimeError as e:
                errors.append(str(e))
        for c, fut in pending_charts.items():
            try:
                chart_digests[c] = fut.result()
            except RuntimeError as e:
                errors.append(str(e))
    cache.save()
    if errors:
        sys.exit("cannot resolve digests:\n  " + "\n  ".join(sorted(errors)))

    not_scanned = [{"type": "grafana-plugin", "name": p,
                    "reason": "Grafana downloads the plugin when the pod starts"}
                   for p in sorted(plugins)]
    not_scanned += [{"type": "test-only", "name": ref,
                     "reason": "only an object with helm.sh/hook: test uses it; it runs only when someone runs helm test"}
                    for ref in test_only]
    record = {
        "schemaVersion": SCHEMA_VERSION,
        "commit": args.commit or run(["git", "rev-parse", "HEAD"]),
        "images": merge_entries(entries),
        "charts": [{"name": n, "version": v, "repository": r, "digest": chart_digests[(r, n, v)]}
                   for r, n, v in charts],
        "notScanned": not_scanned,
        "scanner": {"name": None, "version": None, "databaseUpdatedAt": None},
    }
    problems = validate_record(record)
    if problems:
        sys.exit("record does not match its schema:\n  " + "\n  ".join(problems))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    differ = sum(i["runtimeDiffers"] for i in record["images"])
    print(f"wrote {args.out}: {len(record['images'])} images ({differ} with a runtime digest that differs), "
          f"{len(record['charts'])} charts, {len(record['notScanned'])} not scanned")


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
