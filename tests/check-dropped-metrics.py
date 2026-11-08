#!/usr/bin/env python3
"""Fails if prometheus.dropUnusedControlPlaneMetrics drops a metric that a rule or dashboard uses.

A script is needed because no declarative tool compares a regex with the metric
names inside PromQL: the check renders the platform with the preset on through
ci/render.py, so the pinned kube-prometheus-stack version is read from the
Application and never repeated here. The check then collects every metric name in
the rendered PrometheusRules and in the dashboard ConfigMaps (the chart's and this
repo's own) and tries each drop regex on them. Prometheus anchors a relabel regex on
both ends, so re.fullmatch is the same test.

    tests/check-dropped-metrics.py <default render dir, e.g. out/head>

It also verifies that the four ServiceMonitors keep the chart's own
metricRelabelings, which a Helm list would otherwise replace, and that the check
itself can fail: it adds a regex that matches a used metric and expects a failure.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CLUSTER = "kind"
SERVICE_MONITORS = {
    "prometheus-apiserver",
    "prometheus-kube-etcd",
    "prometheus-kube-controller-manager",
    "prometheus-kube-scheduler",
}
IDENTIFIER = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
NOT_RE2 = re.compile(r"\(\?[=!<]|\\[1-9]")
# Fewer than this many names means the extraction broke, not that the rules are clean.
MIN_NAMES = 300


def load_dir(path):
    objects = []
    for f in sorted(Path(path).rglob("*.yaml")):
        objects.append(yaml.load(f.read_text(encoding="utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)))
    return objects


def strings_under(node, keys):
    """Every string stored under one of keys, at any depth."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys and isinstance(v, str):
                yield v
            else:
                yield from strings_under(v, keys)
    elif isinstance(node, list):
        for v in node:
            yield from strings_under(v, keys)


def used_metric_names(objects):
    """Identifiers in every rule expression and dashboard query, plus recorded names."""
    import json

    texts = []
    for obj in objects:
        if obj.get("kind") == "PrometheusRule":
            for group in obj["spec"].get("groups", []):
                for rule in group.get("rules", []):
                    texts.append(rule.get("expr", ""))
                    texts.append(rule.get("record", ""))
        elif obj.get("kind") == "ConfigMap" and (obj["metadata"].get("labels") or {}).get("grafana_dashboard"):
            for body in (obj.get("data") or {}).values():
                texts += strings_under(json.loads(body), {"expr", "query", "definition"})
    names = set()
    for text in texts:
        names.update(IDENTIFIER.findall(str(text)))
    return names


def service_monitors(objects):
    return {o["metadata"]["name"]: o for o in objects
            if o.get("kind") == "ServiceMonitor" and o["metadata"]["name"] in SERVICE_MONITORS}


def relabelings(service_monitor):
    return [r for ep in service_monitor["spec"]["endpoints"] for r in ep.get("metricRelabelings", [])]


def drop_regexes(monitors, default_monitors, errors):
    """The regexes the preset adds, after checking the chart's own rules come first."""
    regexes = []
    for name, monitor in sorted(monitors.items()):
        rules, defaults = relabelings(monitor), relabelings(default_monitors.get(name, {"spec": {"endpoints": []}}))
        if rules[:len(defaults)] != defaults:
            errors.append(f"{name}: the chart's own metricRelabelings are not kept first")
        added = [r for r in rules[len(defaults):] if r.get("action") == "drop" and r.get("sourceLabels") == ["__name__"]]
        if not added:
            errors.append(f"{name}: no drop rule on __name__ was rendered")
        for rule in added:
            if NOT_RE2.search(rule["regex"]):
                errors.append(f"{name}: the regex uses syntax that Prometheus (RE2) rejects")
            regexes.append((name, rule["regex"]))
    return regexes


def conflicts(regexes, names):
    found = []
    for monitor, regex in regexes:
        compiled = re.compile(regex)
        for metric in sorted(n for n in names if compiled.fullmatch(n)):
            found.append(f"{monitor}: a drop regex matches {metric}, which a rule or dashboard uses")
    return found


def render_with_preset(workdir):
    root = workdir / "repo"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "out"))
    clusters = root / "ci" / "clusters"
    cluster = yaml.safe_load((clusters / f"{CLUSTER}.yaml").read_text(encoding="utf-8"))
    for f in clusters.glob("*.yaml"):
        f.unlink()
    values = cluster["spec"]["sources"][0]["helm"]["valuesObject"]
    extra = values.setdefault("observabilityExtraHelmValues", {})
    extra.setdefault("prometheus", {})["dropUnusedControlPlaneMetrics"] = True
    (clusters / f"{CLUSTER}.yaml").write_text(yaml.safe_dump(cluster), encoding="utf-8")
    out = workdir / "out"
    subprocess.run([sys.executable, str(root / "ci" / "render.py"), str(root), str(out)], check=True)
    return out / CLUSTER


def main(default_render):
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        rendered = load_dir(render_with_preset(Path(tmp)))
    monitors = service_monitors(rendered)
    default_monitors = service_monitors(load_dir(Path(default_render) / CLUSTER))
    if set(monitors) != SERVICE_MONITORS:
        errors.append(f"expected the ServiceMonitors {sorted(SERVICE_MONITORS)}, found {sorted(monitors)}")
    names = used_metric_names(rendered)
    print(f"{len(names)} names used by rules and dashboards")
    if len(names) < MIN_NAMES:
        errors.append(f"only {len(names)} names found, the extraction is broken")
    regexes = drop_regexes(monitors, default_monitors, errors)
    errors += conflicts(regexes, names)

    # The check must be able to fail, or a pass means nothing.
    for bad in ("apiserver_request_total", "go_.*", "up|scrape_duration_seconds"):
        if not conflicts([("self-test", bad)], names):
            errors.append(f"self-test: the regex {bad} should conflict with a used name and did not")
    if conflicts([("self-test", "no_such_metric_.*")], names):
        errors.append("self-test: a regex that matches no used name reported a conflict")

    for message in errors:
        print(f"FAIL {message}")
    if not errors:
        print(f"ok   {len(regexes)} drop regexes match no used metric name")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
