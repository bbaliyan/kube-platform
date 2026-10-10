#!/usr/bin/env python3
"""Waits for the platform to come up: every Argo CD Application synced and
healthy and every pod ready. Fails as soon as something is known to be
broken, rather than at the timeout.

  python ci/e2e/wait.py TIMEOUT_SECONDS

An Application is ready when it is Synced and Healthy, its last sync
succeeded (a failed hook leaves it Synced and Healthy otherwise), and it has
no error condition. MANUAL lists the ones synced by hand on purpose; those
only have to compare cleanly. A parent is only Synced once every child
Application it renders exists, so all of them being ready means the set is
complete. It passes once that, and every pod being ready with no container
restarting, has held for STABLE_FOR seconds.

A healthy bring-up passes through plenty of errors while one app waits on
another's CRDs, webhooks or secrets, so a problem only fails the run once it
has lasted its grace period (GRACE). Two never clear up on their own, so they
fail it straight away: a sync that has used up its retries (auto-sync never
retries a revision that failed), and an image the registry says doesn't
exist. TIMEOUT_SECONDS is the backstop for anything else that hangs.
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

POLL = 10
STABLE_FOR = 60
MANUAL = {"system-upgrade-plans"}

# Seconds each problem may last before it fails the run, with what a healthy
# run was seen to go through: ComparisonError for two minutes while Argo CD
# replaces its own repo server; Degraded while the external-secrets webhook
# comes up; pods whose secrets ESO or a hook Job creates later; Unschedulable
# while a host-port pod rolls on the one node.
GRACE = {
    "ComparisonError": 300,
    "condition": 120,  # any other *Error condition: InvalidSpecError, SyncError
    "Degraded": 180,
    "image pull": 180,  # rate limits and registry blips; kubelet retries 4 times
    "CreateContainerConfigError": 180,
    "CreateContainerError": 120,
    "restarting": 180,  # CrashLoopBackOff on a webhook or CRD that isn't up yet
    "Unschedulable": 180,
    "not ready": 300,  # whatever the reason; counted from when it went unready
}
# What the runtime says when the image or tag isn't there; no retry fixes it.
MISSING_IMAGE = re.compile(r"code = NotFound|manifest unknown|: not found|repository does not exist")


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


def app_problems(app):
    """(key, grace, message, since) for each thing wrong with an Application."""
    name = app["metadata"]["name"]
    st = app.get("status", {})
    found = []
    op = st.get("operationState", {})
    # A sync being retried shows as Running; Failed or Error means the
    # retries are used up and auto-sync won't try this revision again.
    if op.get("phase") in ("Failed", "Error"):
        found.append((f"{name} sync", 0, f"{name}: last sync {op['phase']}: {op.get('message', '')}", None))
    for c in st.get("conditions", []):
        if c["type"].endswith("Error"):
            grace = GRACE.get(c["type"], GRACE["condition"])
            found.append((f"{name} {c['type']}", grace, f"{name}: {c['type']}: {c['message']}", None))
    if state(app)[1] == "Degraded":
        found.append((f"{name} Degraded", GRACE["Degraded"], f"{name}: Degraded", None))
    return found


def counts(pod):
    """Whether a pod has to be ready: not finished, not on its way out, and
    not a failed attempt of a Job (the Job's own health covers those)."""
    meta, phase = pod["metadata"], pod["status"].get("phase")
    owned_by_job = any(o["kind"] == "Job" for o in meta.get("ownerReferences", []))
    return not (phase == "Succeeded" or meta.get("deletionTimestamp")
                or (phase == "Failed" and owned_by_job))


def pod_ready(pod):
    return any(c["type"] == "Ready" and c["status"] == "True"
               for c in pod["status"].get("conditions", []))


def pod_problems(pod, apps_in):
    """(key, grace, message, since) for each thing wrong with a pod that
    isn't ready. apps_in maps a namespace to the Applications deploying there."""
    meta, st = pod["metadata"], pod["status"]
    where = f"{meta['namespace']}/{meta['name']}"
    owner = f" ({', '.join(apps_in[meta['namespace']])})" if meta["namespace"] in apps_in else ""
    found = []
    for c in st.get("initContainerStatuses", []) + st.get("containerStatuses", []):
        name = f"{where} {c['name']}"
        waiting = c.get("state", {}).get("waiting", {})
        reason, message = waiting.get("reason", ""), waiting.get("message", "")
        say = f"{name}{owner}: {reason}: {message}"
        if reason in ("InvalidImageName", "ErrImageNeverPull"):
            found.append((name, 0, say, None))
        elif reason in ("ErrImagePull", "ImagePullBackOff"):
            # The two alternate between retries, so they share a key.
            grace = 0 if MISSING_IMAGE.search(message) else GRACE["image pull"]
            found.append((f"{name} pull", grace, say, None))
        elif reason in ("CreateContainerConfigError", "CreateContainerError"):
            found.append((f"{name} {reason}", GRACE[reason], say, None))
        elif c.get("restartCount") and not c.get("ready"):
            # Keyed on restarts rather than CrashLoopBackOff, which comes and
            # goes as the container is retried.
            last = c.get("lastState", {}).get("terminated", {})
            found.append((f"{name} restarting", GRACE["restarting"],
                          f"{name}{owner}: restarted {c['restartCount']} times, last "
                          f"{last.get('reason', '?')} (exit {last.get('exitCode', '?')})", None))
    for cond in st.get("conditions", []):
        if cond["type"] == "PodScheduled" and cond.get("reason") == "Unschedulable":
            found.append((f"{where} unschedulable", GRACE["Unschedulable"],
                          f"{where}{owner}: Unschedulable: {cond.get('message', '')}", None))
    # Since it last went unready, so an old pod that blips (say, CoreDNS
    # while Cilium restarts) isn't overdue the moment it does.
    since = next((c.get("lastTransitionTime") for c in st.get("conditions", [])
                  if c["type"] == "Ready"), None) or meta["creationTimestamp"]
    found.append((f"{where} not ready", GRACE["not ready"],
                  f"{where}{owner}: not ready {st.get('phase')}", timestamp(since)))
    return found


def timestamp(rfc3339):
    return datetime.fromisoformat(rfc3339.replace("Z", "+00:00")).timestamp()


def unready(pods):
    return [p for p in pods if counts(p) and not pod_ready(p)]


def pod_line(pod):
    statuses = pod["status"].get("initContainerStatuses", []) + pod["status"].get("containerStatuses", [])
    waiting = [c["state"]["waiting"].get("reason", "") for c in statuses
               if "waiting" in c.get("state", {})]
    return (f"{pod['metadata']['namespace']}/{pod['metadata']['name']}: "
            f"{pod['status'].get('phase')} {' '.join(waiting)}".rstrip())


def report(apps):
    """What is still wrong with each Application that isn't ready."""
    for app in apps:
        if ready(app):
            continue
        sync, health = state(app)
        print(f"\n== {app['metadata']['name']}: {sync} / {health}")
        for e in errors(app):
            print(f"   {e}")
        # Argo CD 3 doesn't keep resource health in the Application; the
        # unready pods printed after this usually say why it's unhealthy.
        for r in app.get("status", {}).get("resources", []):
            if r.get("status") != "Synced":
                where = f"{r.get('namespace', '')}/{r['name']}".lstrip("/")
                print(f"   {r['kind']} {where}: {r.get('status')}")


def containers(pod):
    st = pod["status"]
    return st.get("initContainerStatuses", []) + st.get("containerStatuses", [])


def restarts_seen(pods):
    found = []
    for pod in pods:
        for c in containers(pod):
            if c.get("restartCount"):
                last = c.get("lastState", {}).get("terminated", {})
                found.append(f"{pod['metadata']['namespace']}/{pod['metadata']['name']} "
                             f"{c['name']}: {c['restartCount']}x, last {last.get('reason', '?')} "
                             f"(exit {last.get('exitCode', '?')})")
    return found


def summary(apps, outcome, started, bad_pods=(), restarted=()):
    """The run's summary page: the outcome and every Application's state."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = [f"## e2e: {outcome}", "",
             f"{int(time.time() - started)}s after the root Application was applied.", "",
             "| Application | Sync | Health | |", "|---|---|---|---|"]
    for app in sorted(apps, key=lambda a: a["metadata"]["name"]):
        name = app["metadata"]["name"]
        note = "synced by hand; compared only" if name in MANUAL else "; ".join(errors(app))
        mark = "✅" if ready(app) else "❌"
        lines.append(f"| {mark} {name} | {' | '.join(state(app))} | {note} |")
    if bad_pods:
        lines += ["", "Pods not ready:", "", *(f"- `{p}`" for p in bad_pods)]
    if restarted:
        lines += ["", "Containers that restarted along the way:", "",
                  *(f"- `{r}`" for r in restarted)]
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def fail(title, lines, apps, pods, started):
    print(f"::error::{title}")
    print("\n".join(lines))
    report(apps)
    bad = [pod_line(p) for p in unready(pods)]
    print("\nPods not ready:\n" + "\n".join(bad or ["(none)"]))
    summary(apps, title, started, bad)
    sys.exit(1)


def main():
    # Wall-clock time throughout, as pod timestamps come from the cluster's
    # (kind runs on the same host, so the clocks agree).
    started = time.time()
    deadline = started + int(sys.argv[1])
    first_seen = {}  # problem key -> when it was first seen
    stable_since = None
    last_restarts = None
    last_print = 0
    apps, pods = [], []
    while True:
        now = time.time()
        try:
            apps = kubectl_items("get", "applications.argoproj.io", "-n", "argocd")
            pods = kubectl_items("get", "pods", "-A")
        except subprocess.CalledProcessError as e:
            print(f"kubectl failed, retrying: {e.stderr.strip()}", flush=True)
            if now > deadline:
                fail("Timed out with kubectl failing", [], apps, pods, started)
            stable_since = None
            time.sleep(POLL)
            continue

        apps_in = {}
        for a in apps:
            ns = a["spec"].get("destination", {}).get("namespace")
            if ns:
                apps_in.setdefault(ns, []).append(a["metadata"]["name"])
        problems = [p for a in apps for p in app_problems(a)]
        problems += [p for pod in unready(pods) for p in pod_problems(pod, apps_in)]

        # A problem's clock runs while it's seen on every poll in a row.
        keys = {key for key, *_ in problems}
        first_seen = {k: t for k, t in first_seen.items() if k in keys}
        for key, _, _, since in problems:
            first_seen.setdefault(key, since or now)
        overdue = [f"{msg} (for {int(now - first_seen[key])}s)"
                   for key, grace, msg, _ in problems if now - first_seen[key] >= grace]
        if overdue:
            fail("Failed early: " + overdue[0][:250], overdue[1:], apps, pods, started)

        waiting = [a for a in apps if not ready(a)]
        bad_pods = unready(pods)
        restarts = sum(c.get("restartCount", 0) for p in pods for c in containers(p))
        if apps and not waiting and not bad_pods and restarts == last_restarts:
            stable_since = stable_since or now
        else:
            stable_since = None
        last_restarts = restarts
        if stable_since and now - stable_since >= STABLE_FOR:
            break

        if now - last_print >= 60:
            last_print = now
            names = ", ".join(f"{a['metadata']['name']} ({'/'.join(state(a))})" for a in waiting)
            print(f"{len(apps) - len(waiting)}/{len(apps)} ready, {len(bad_pods)} pods not; "
                  f"waiting on: {names or ('pods' if bad_pods else 'stability')}", flush=True)
            # Every problem and how long it has lasted, so GRACE can be tuned
            # from what healthy runs actually go through.
            for key, grace, msg, _ in problems:
                if not key.endswith(" not ready"):
                    print(f"   {int(now - first_seen[key])}s/{grace}s {msg[:300]}", flush=True)
        if now > deadline:
            fail("Timed out waiting for Applications and pods to be ready", [], apps, pods, started)
        time.sleep(POLL)

    print(f"All {len(apps)} Applications ({', '.join(sorted(MANUAL))} compared only) "
          f"and every pod ready for {STABLE_FOR}s.")
    # Restarts the bring-up recovered from on its own, which pass but are
    # worth knowing about (an OOMKilled init container, say).
    restarted = restarts_seen(pods)
    if restarted:
        print("Containers that restarted along the way:\n" + "\n".join(restarted))
    summary(apps, "every Application and pod ready", started, restarted=restarted)


if __name__ == "__main__":
    main()
