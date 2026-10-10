#!/usr/bin/env python3
"""Waits for the platform to come up: every Argo CD Application synced and
healthy, then every pod ready.

  python ci/e2e/wait.py TIMEOUT_SECONDS

An Application is ready when it is Synced and Healthy, its last sync
succeeded (a failed hook leaves it Synced and Healthy otherwise), and it has
no error condition. MANUAL lists the ones synced by hand on purpose; those
only have to compare cleanly. The set of Applications grows as app-of-apps
sync, so it only passes once all of them have stayed ready for STABLE_POLLS
polls in a row. On timeout it prints what is still wrong and exits non-zero.
"""
import json
import subprocess
import sys
import time

POLL = 15
STABLE_POLLS = 9  # two minutes
MANUAL = {"system-upgrade-plans"}


def kubectl_items(*args):
    out = subprocess.run(["kubectl", "--request-timeout=30s", *args, "-o", "json"],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)["items"]


def state(app):
    st = app.get("status", {})
    return st.get("sync", {}).get("status", "-"), st.get("health", {}).get("status", "-")


def errors(app):
    st = app.get("status", {})
    found = [f"{c['type']}: {c['message']}" for c in st.get("conditions", [])
             if c["type"].endswith("Error")]
    op = st.get("operationState", {})
    if op.get("phase") in ("Failed", "Error"):
        found.append(f"last sync {op['phase']}: {op.get('message', '')}")
    return found


def ready(app):
    name = app["metadata"]["name"]
    if name in MANUAL:
        return state(app)[0] != "Unknown" and not errors(app)
    return state(app) == ("Synced", "Healthy") and not errors(app)


def unready_pods():
    bad = []
    for pod in kubectl_items("get", "pods", "-A"):
        phase = pod["status"].get("phase")
        statuses = pod["status"].get("containerStatuses", [])
        if phase == "Succeeded" or (phase == "Running" and statuses
                                    and all(c["ready"] for c in statuses)):
            continue
        waiting = [c["state"]["waiting"].get("reason", "") for c in statuses
                   if "waiting" in c.get("state", {})]
        bad.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']}: "
                   f"{phase} {' '.join(waiting)}".rstrip())
    return bad


def report(apps):
    """What is still wrong with each Application that isn't ready."""
    for app in apps:
        if ready(app):
            continue
        sync, health = state(app)
        print(f"\n== {app['metadata']['name']}: {sync} / {health}")
        for e in errors(app):
            print(f"   {e}")
        for r in app.get("status", {}).get("resources", []):
            h = r.get("health", {})
            if r.get("status") != "Synced" or h.get("status") not in (None, "Healthy"):
                where = f"{r.get('namespace', '')}/{r['name']}".lstrip("/")
                print(f"   {r['kind']} {where}: {r.get('status')} / "
                      f"{h.get('status', '-')} {h.get('message', '')}".rstrip())


def main():
    deadline = time.monotonic() + int(sys.argv[1])
    stable = 0
    last_print = 0
    apps = []
    while True:
        try:
            apps = kubectl_items("get", "applications.argoproj.io", "-n", "argocd")
            waiting = [a for a in apps if not ready(a)]
        except subprocess.CalledProcessError as e:
            print(f"kubectl failed, retrying: {e.stderr.strip()}", flush=True)
            waiting = ["kubectl"]
        stable = stable + 1 if apps and not waiting else 0
        if stable >= STABLE_POLLS:
            break
        if time.monotonic() - last_print >= 60:
            last_print = time.monotonic()
            names = ", ".join(a if isinstance(a, str) else
                              f"{a['metadata']['name']} ({'/'.join(state(a))})" for a in waiting)
            print(f"{len(apps) - len(waiting)}/{len(apps)} ready; waiting on: {names or 'stability'}",
                  flush=True)
        if time.monotonic() > deadline:
            print("::error::Timed out waiting for Applications to be Synced and Healthy")
            report(apps)
            sys.exit(1)
        time.sleep(POLL)
    print(f"All {len(apps)} Applications are ready ({', '.join(sorted(MANUAL))} compared only).")

    # Argo CD doesn't health-check every pod: Job pods, operator-created ones.
    bad = unready_pods()
    if bad:
        print("::error::Pods not ready after every Application was:")
        print("\n".join(bad))
        sys.exit(1)
    print("Every pod is ready.")


if __name__ == "__main__":
    main()
