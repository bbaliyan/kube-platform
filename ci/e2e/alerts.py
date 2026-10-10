#!/usr/bin/env python3
"""Fails if the platform's own Prometheus says something is wrong once it is
up: a warning or critical alert pending or firing, a scrape target down, or
an alert rule that fails to evaluate.

  python ci/e2e/alerts.py TIMEOUT_SECONDS

Waits until Prometheus has scraped every target and then evaluated every
rule group, so a broken scrape or a rule that is true from the start shows
up. Pending counts: most alerts must hold for 10 or 15 minutes before they
fire, longer than this job runs, so pending is the only way to see them
here. BRINGUP lists the few that look back over the bring-up itself; those
only count once firing.
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

PROXY = "/api/v1/namespaces/prometheus/services/prometheus-operated:9090/proxy/api/v1/"
POLL = 10
NEVER = {"Watchdog", "InfoInhibitor"}  # always firing, by design
# Their windows (5 minutes and more) still cover the bring-up, where a pod
# crash-looping while a webhook starts, or webhook 5xx errors, are normal.
BRINGUP = {"KubePodCrashLooping", "KubeAPIErrorBudgetBurn"}
# Scrape jobs that are down on kind, with why. Their targets don't fail the
# run, and nor do exactly these alerts about them; any other alert on these
# jobs (a ServiceMonitor gone missing, say) still does.
KIND_ONLY = {
    # kind's etcd serves metrics on 127.0.0.1:2381; RKE2's
    # etcd-expose-metrics also serves them on the node IP.
    "kube-etcd": ("etcd metrics on localhost only",
                  {"TargetDown", "etcdMembersDown", "etcdInsufficientMembers"}),
    # Both listen on 127.0.0.1, on kind and on RKE2 alike (see
    # prometheus-app.yaml); left here for when RKE2 is fixed.
    "kube-scheduler": ("listens on localhost only",
                       {"TargetDown", "KubeSchedulerInstanceUnreachable"}),
    "kube-controller-manager": ("listens on localhost only",
                                {"TargetDown", "KubeControllerManagerInstanceUnreachable"}),
}


def api(path):
    out = subprocess.run(["kubectl", "--request-timeout=30s", "get", "--raw", PROXY + path],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)["data"]


def targets():
    return api("targets?state=active")["activeTargets"]


def groups():
    return api("rules")["groups"]


def when(rfc3339):
    """Prometheus timestamps carry up to nine fractional digits, and a zero
    time (0001-01-01) for never."""
    t = re.sub(r"(\.\d{6})\d*", r"\1", rfc3339).replace("Z", "+00:00")
    return datetime.fromisoformat(t).timestamp()


def all_scraped_at():
    """When every target had been scraped at least once, in Prometheus's
    clock, or None if some haven't yet."""
    ts = targets()
    if not ts or any(t["lastScrape"].startswith("0001") for t in ts):
        return None
    return max(when(t["lastScrape"]) for t in ts)


def all_evaluated_since(moment):
    gs = groups()
    return bool(gs) and all(when(g["lastEvaluation"]) > moment for g in gs)


def expected(alert):
    labels = alert["labels"]
    job = KIND_ONLY.get(labels.get("job"))
    return job is not None and labels["alertname"] in job[1]


def describe(alert):
    labels = alert["labels"]
    where = " ".join(f"{k}={labels[k]}" for k in ("namespace", "job", "service", "pod")
                     if k in labels)
    text = alert.get("annotations", {})
    text = text.get("summary") or text.get("description") or ""
    return f"{labels['alertname']} ({labels.get('severity', '-')}, {alert['state']}) {where}: {text}"


def main():
    deadline = time.monotonic() + int(sys.argv[1])
    # Every target scraped once, then every rule group run after that, so
    # the alerts reflect every target. (Targets keep being scraped, so the
    # moment is taken once, not recomputed.)
    scraped = None
    while True:
        try:
            scraped = scraped or all_scraped_at()
            if scraped and all_evaluated_since(scraped):
                break
        except subprocess.CalledProcessError as e:
            print(f"Prometheus not answering yet: {e.stderr.strip()[:200]}", flush=True)
        if time.monotonic() > deadline:
            sys.exit("::error::Timed out waiting for Prometheus to scrape every target and run every rule")
        time.sleep(POLL)

    alerts = [a for a in api("alerts")["alerts"] if a["labels"]["alertname"] not in NEVER]
    known = [a for a in alerts if expected(a)]
    failing = [a for a in alerts if a not in known
               and a["labels"].get("severity", "warning") in ("warning", "critical")
               and not (a["labels"]["alertname"] in BRINGUP and a["state"] == "pending")]
    info = [a for a in alerts if a not in known + failing]
    down = [f"{t['labels'].get('job')} {t['scrapeUrl']}: {t['lastError']}" for t in targets()
            if t["health"] == "down" and t["labels"].get("job") not in KIND_ONLY]
    broken = [f"{g['name']}/{r['name']}: {r.get('lastError', '')}" for g in groups()
              for r in g["rules"] if r.get("health") != "ok"]
    missing = [f"{name} on {job}" for job, (_, names) in KIND_ONLY.items() for name in names
               if not any(a["labels"]["alertname"] == name and a["labels"].get("job") == job
                          for a in known)]

    lines = []
    for title, group in (("Warning or critical", map(describe, failing)),
                         ("Targets down", down), ("Rules failing", broken),
                         ("Info only, or bring-up history", map(describe, info)),
                         ("Expected on kind", map(describe, known))):
        group = list(group)
        if group:
            lines += [f"{title}:"] + [f"- {x}" for x in group] + [""]
    print("\n".join(lines) or "No alerts.")
    if missing:
        # The allowlist may have gone stale, or a scrape been fixed on kind.
        print(f"::warning::Expected on kind but not seen: {', '.join(missing)}")
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n## Prometheus alerts\n\n" + ("\n".join(lines) or "None.") + "\n")
    problems = len(failing) + len(down) + len(broken)
    if problems:
        sys.exit(f"::error::{problems} problem(s) in Prometheus: alerts, targets down or rules failing")


if __name__ == "__main__":
    main()
