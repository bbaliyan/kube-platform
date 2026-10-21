#!/usr/bin/env bash
# Fail when a rendered Argo CD Application lacks the
# resources-finalizer.argocd.argoproj.io finalizer. Without it, deleting or
# pruning the Application leaves what it deployed running, unowned. An
# Application that must not take its resources with it opts out with the
# annotation kube-stack/keep-resources-on-delete, whose value must say why.
# An opt-out must also set Prune=false and Delete=false in
# argocd.argoproj.io/sync-options. An Application cannot have both a finalizer
# and an opt-out. The check fails when it finds no Application at all.
# Run it on the output of ci/render.py: the sources are Helm templates.
set -euo pipefail

python3 -I - "$@" <<'PY'
import pathlib, sys, yaml

FINALIZER = "resources-finalizer.argocd.argoproj.io"
OPT_OUT = "kube-stack/keep-resources-on-delete"
SYNC_OPTIONS = "argocd.argoproj.io/sync-options"
PROTECTION = {"Prune=false", "Delete=false"}

problems, checked = [], 0
for directory in sys.argv[1:]:
    for path in sorted(pathlib.Path(directory).rglob("*.y*ml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not isinstance(doc, dict) or doc.get("kind") != "Application":
                continue
            checked += 1
            meta = doc.get("metadata") or {}
            name = meta.get("name")
            if not name:
                problems.append(f"{path}: Application has no name")
                continue
            annotations = meta.get("annotations") or {}
            reason = annotations.get(OPT_OUT)
            sync_options = {o.strip() for o in str(annotations.get(SYNC_OPTIONS, "")).split(",")}
            has_finalizer = FINALIZER in (meta.get("finalizers") or [])
            if reason is not None and has_finalizer:
                problems.append(f"{path}: Application {name} has both the finalizer and {OPT_OUT}")
            elif reason is not None:
                if not str(reason).strip():
                    problems.append(f"{path}: Application {name} has an empty {OPT_OUT} reason")
                if not PROTECTION <= sync_options:
                    problems.append(f"{path}: Application {name} opts out but {SYNC_OPTIONS} lacks Prune=false and Delete=false")
            elif not has_finalizer:
                problems.append(f"{path}: Application {name} lacks the {FINALIZER} finalizer")

if not checked:
    problems.append("no Applications found in " + ", ".join(sys.argv[1:]))

if problems:
    print("\n".join(problems))
    sys.exit(1)
print(f"{checked} Applications, each with the finalizer or a stated opt-out")
PY
