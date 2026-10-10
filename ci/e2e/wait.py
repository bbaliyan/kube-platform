"""Waits for every Argo CD Application to be Synced and Healthy.

  python ci/e2e/wait.py TIMEOUT_SECONDS

Applications without automated sync (system-upgrade-plans, synced by hand
on purpose) are left out. The set of Applications grows as app-of-apps sync,
so it only passes once every one has stayed Synced and Healthy across
several polls in a row. On timeout it prints what is still wrong and exits
non-zero.
"""
import json
import subprocess
import sys
import time

POLL = 15
STABLE_POLLS = 4


def kubectl_json(*args):
    out = subprocess.run(["kubectl", *args, "-o", "json"], check=True,
                         capture_output=True, text=True).stdout
    return json.loads(out)["items"]


def applications():
    return kubectl_json("get", "applications.argoproj.io", "-n", "argocd")


def automated(app):
    return "automated" in (app["spec"].get("syncPolicy") or {})


def state(app):
    st = app.get("status", {})
    return st.get("sync", {}).get("status", "-"), st.get("health", {}).get("status", "-")


def ready(app):
    return state(app) == ("Synced", "Healthy")


def report(apps):
    """What is still wrong with each Application that isn't ready."""
    for app in apps:
        if ready(app):
            continue
        st = app.get("status", {})
        sync, health = state(app)
        print(f"\n== {app['metadata']['name']}: {sync} / {health}")
        for c in st.get("conditions", []):
            print(f"   condition {c['type']}: {c['message']}")
        op = st.get("operationState", {})
        if op.get("phase") not in (None, "Succeeded"):
            print(f"   last sync {op['phase']}: {op.get('message', '')}")
        for r in st.get("resources", []):
            h = r.get("health", {})
            if r.get("status") != "Synced" or h.get("status") not in (None, "Healthy"):
                where = f"{r.get('namespace', '')}/{r['name']}".lstrip("/")
                print(f"   {r['kind']} {where}: {r.get('status')} / "
                      f"{h.get('status', '-')} {h.get('message', '')}".rstrip())


def main():
    deadline = time.monotonic() + int(sys.argv[1])
    stable = 0
    last_print = 0
    while True:
        apps = [a for a in applications() if automated(a)]
        waiting = [a for a in apps if not ready(a)]
        stable = stable + 1 if apps and not waiting else 0
        if stable >= STABLE_POLLS:
            print(f"All {len(apps)} automatically synced Applications are Synced and Healthy.")
            return
        if time.monotonic() - last_print >= 60:
            last_print = time.monotonic()
            names = ", ".join(f"{a['metadata']['name']} ({'/'.join(state(a))})" for a in waiting)
            print(f"{len(apps) - len(waiting)}/{len(apps)} ready; waiting on: {names or 'stability'}",
                  flush=True)
        if time.monotonic() > deadline:
            print("::error::Timed out waiting for Applications to become Synced and Healthy")
            report(apps)
            sys.exit(1)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
