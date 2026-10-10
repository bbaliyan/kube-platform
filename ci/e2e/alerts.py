#!/usr/bin/env python3
"""Fails if the platform's own Prometheus has a warning or critical alert
firing once it is up.

  python ci/e2e/alerts.py TIMEOUT_SECONDS

Waits until Prometheus has scraped every target and evaluated every rule
group at least once, so a broken scrape or a rule that is true from the
start shows up. Pending alerts are listed but don't fail the run: most
look back five minutes or more, which here still covers the bring-up.
"""
import json
import os
import subprocess
import sys
import time

PROXY = "/api/v1/namespaces/prometheus/services/prometheus-operated:9090/proxy/api/v1/"
POLL = 10
NEVER = {"Watchdog", "InfoInhibitor"}  # always firing, by design
# Alerts that only fire because the cluster is kind, with why.
KIND_ONLY = {}


def api(path):
    out = subprocess.run(["kubectl", "--request-timeout=30s", "get", "--raw", PROXY + path],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)["data"]


def evaluated():
    """Whether every target has been scraped and every rule group run."""
    targets = api("targets?state=active")["activeTargets"]
    groups = api("rules")["groups"]
    unscraped = [t for t in targets if t["lastScrape"].startswith("0001")]
    unrun = [g for g in groups if g["lastEvaluation"].startswith("0001")]
    return targets and groups and not unscraped and not unrun


def describe(alert):
    labels = alert["labels"]
    where = " ".join(f"{k}={labels[k]}" for k in ("namespace", "job", "service", "pod")
                     if k in labels)
    text = alert.get("annotations", {})
    text = text.get("summary") or text.get("description") or ""
    return f"{labels['alertname']} ({labels.get('severity', '-')}, {alert['state']}) {where}: {text}"


def main():
    deadline = time.monotonic() + int(sys.argv[1])
    while True:
        try:
            if evaluated():
                break
        except subprocess.CalledProcessError as e:
            print(f"Prometheus not answering yet: {e.stderr.strip()[:200]}", flush=True)
        if time.monotonic() > deadline:
            sys.exit("::error::Timed out waiting for Prometheus to scrape every target and run every rule")
        time.sleep(POLL)

    alerts = [a for a in api("alerts")["alerts"] if a["labels"]["alertname"] not in NEVER]
    known = [a for a in alerts if a["labels"]["alertname"] in KIND_ONLY]
    pending = [a for a in alerts if a not in known and a["state"] == "pending"]
    failing = [a for a in alerts if a not in known and a["state"] == "firing"
               and a["labels"].get("severity") in ("warning", "critical")]
    info = [a for a in alerts if a not in known + pending + failing]

    lines = []
    for title, group in (("Firing", failing), ("Firing, info only", info),
                         ("Pending", pending), ("Expected on kind", known)):
        if group:
            lines += [f"{title}:"] + [f"- {describe(a)}" for a in group] + [""]
    print("\n".join(lines) or "No alerts.")
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n## Prometheus alerts\n\n" + ("\n".join(lines) or "None.") + "\n")
    if failing:
        sys.exit(f"::error::{len(failing)} warning or critical alert(s) firing")


if __name__ == "__main__":
    main()
