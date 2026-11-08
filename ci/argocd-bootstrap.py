#!/usr/bin/env python3
"""Render the Argo CD bootstrap manifest from this repo's own values.

A script is needed because no tool feeds the Helm values of one rendered
Application (the argocd Application of the bootstrap chart) into the render of
the chart it names. Reusing that Application keeps one source for the settings
and the version: what a node installs at first boot is what Argo CD then
reconciles.

    python ci/argocd-bootstrap.py <out-dir>

It writes argocd-bootstrap.yaml and argocd-bootstrap.yaml.sha256 to <out-dir>.
The sha256 file is in the format of `sha256sum -c`.
"""

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
NAME = "argocd-bootstrap.yaml"
NAMESPACE = "argocd"
REPO = "https://argoproj.github.io/argo-helm"


def helm(*args):
    return subprocess.run(["helm", *args], check=True, capture_output=True, text=True).stdout


def argocd_application():
    rendered = helm("template", "platform", str(ROOT / "bootstrap"),
                    "--values", str(ROOT / "platform/platform-versions/values.yaml"),
                    "--show-only", "templates/argocd-app.yaml")
    return yaml.safe_load(rendered)["spec"]


def render():
    spec = argocd_application()
    source = spec.get("source")
    if source is None:
        sys.exit("argocd-bootstrap: the argocd Application has no single source; this script reads spec.source")
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as values:
        values.write(source.get("helm", {}).get("values") or sys.exit("argocd-bootstrap: the argocd Application has no helm values"))
        values.flush()
        chart = helm("template", "argocd", source["chart"], "--repo", source["repoURL"],
                     "--version", source["targetRevision"], "--namespace", NAMESPACE,
                     "--include-crds", "--values", values.name)
    namespace = yaml.safe_dump({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
    return f"{namespace}---\n{chart}"


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    manifest = render()
    (out / NAME).write_text(manifest)
    digest = hashlib.sha256(manifest.encode()).hexdigest()
    (out / f"{NAME}.sha256").write_text(f"{digest}  {NAME}\n")
    print(f"{NAME} sha256 {digest}")


if __name__ == "__main__":
    main()
