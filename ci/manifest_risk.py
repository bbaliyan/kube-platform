#!/usr/bin/env python3
"""Compare two renders of this repo and keep only the changes that carry supply-chain risk.

A script is needed because no existing tool does this. ci/diff_comment.py shows
every changed line and cannot say whether a change matters. kubeconform and
Trivy see schema errors and image vulnerabilities, not a new hook, a wildcard
role or a mutating webhook. This script reads the output of ci/render.py for
`stable` and for the candidate, reduces each object to a few facts, and
compares the fact sets. It reuses ci/promotion_record.py to find images, so
both agree on what an image is.

    ci/manifest_risk.py --stable out/base --candidate out/head \
        --allowlist ci/registry-allowlist.yaml --out-dir out/manifest-risk

The risk classes:
  rbac        a rule of a Role or ClusterRole, and the subjects and role of a
              binding
  webhook     a webhook of a validating or mutating webhook configuration
  hook        an object with a Helm or Argo CD hook annotation
  privileged  a privileged container, a hostPath volume, hostNetwork
  image       an image repository that `stable` does not use
  registry    an image repository outside the allowlist (a new repository on a
              registry that is not listed, or outside the listed prefixes). This
              also catches a typosquat.

An addition is a fact the candidate has and `stable` does not. A rule that
changes shows as one removal and one addition. A new tag of a repository that
`stable` already uses is not an addition: the scan and the daily digest check
cover tags. Every addition needs the owner's approval. A removal never does.

Output, in --out-dir:
  manifest-risk.json  the result data. `needsApproval` is true when there is
                      any addition. The promote workflow reads it.
  manifest-risk.md    the text for the run summary and the release.
When GITHUB_OUTPUT is set, the script also writes `needs_approval` and
`additions` to it.

The script fails (exit 2) if a render directory is missing or has no objects,
so a broken render never looks like an empty diff.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from promotion_record import SKIP_KINDS, images_in, parse_ref, with_plan_tags  # noqa: E402
from render import load_docs  # noqa: E402

SCHEMA_VERSION = 1
CLASSES = ["rbac", "webhook", "hook", "privileged", "image", "registry"]
TITLES = {
    "rbac": "RBAC",
    "webhook": "Webhooks",
    "hook": "Hooks",
    "privileged": "Privileged, hostPath and hostNetwork",
    "image": "New image repositories",
    "registry": "Image repositories outside the allowlist",
}
HOOK_ANNOTATIONS = ("helm.sh/hook", "argocd.argoproj.io/hook")
WEBHOOK_KINDS = {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}
SUMMARY_LIMIT = 200  # rows per class in the Markdown; the JSON is complete


def fail(message):
    print(f"manifest-risk: {message}", file=sys.stderr)
    sys.exit(2)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def ident(obj):
    md = obj.get("metadata", {})
    return "/".join(p for p in (obj.get("kind", "?"), md.get("namespace", ""), md.get("name", "?")) if p)


def rbac_facts(obj):
    kind = obj.get("kind")
    if kind in ("Role", "ClusterRole"):
        for rule in obj.get("rules") or []:
            yield "rbac", f"rule {compact(rule)}"
        # An aggregated ClusterRole takes the rules of other roles by label.
        if obj.get("aggregationRule"):
            yield "rbac", f"aggregation {compact(obj['aggregationRule'])}"
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        role = obj.get("roleRef") or {}
        for s in obj.get("subjects") or []:
            yield "rbac", f"binds {compact(s)} to {role.get('kind')}/{role.get('name')}"


def webhook_facts(obj):
    for hook in obj.get("webhooks") or []:
        detail = {k: hook.get(k) for k in ("failurePolicy", "rules", "namespaceSelector", "objectSelector")}
        client = hook.get("clientConfig") or {}
        detail["target"] = client.get("url") or compact(client.get("service"))
        yield "webhook", f"{hook.get('name')} {compact(detail)}"


def hook_facts(obj):
    annotations = obj.get("metadata", {}).get("annotations") or {}
    for key in HOOK_ANNOTATIONS:
        if key in annotations:
            yield "hook", f"{key}={annotations[key]}"


def pod_specs(node):
    """Every pod spec below node: any mapping that holds a list of containers."""
    if isinstance(node, dict):
        if isinstance(node.get("containers"), list):
            yield node
        for v in node.values():
            yield from pod_specs(v)
    elif isinstance(node, list):
        for v in node:
            yield from pod_specs(v)


def privileged_facts(obj):
    for spec in pod_specs(obj):
        if spec.get("hostNetwork") is True:
            yield "privileged", "hostNetwork"
        for volume in spec.get("volumes") or []:
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                yield "privileged", f"hostPath {volume['hostPath'].get('path')}"
        for key in ("containers", "initContainers", "ephemeralContainers"):
            for c in spec.get(key) or []:
                if isinstance(c, dict) and (c.get("securityContext") or {}).get("privileged") is True:
                    yield "privileged", f"privileged container {c.get('name')}"


def load_side(root):
    """({(class, object, detail): clusters}, {repository: {image refs}}) for one render."""
    root = Path(root)
    files = sorted(root.rglob("*.yaml")) if root.is_dir() else []
    if not files:
        fail(f"no rendered objects in {root}")
    facts, repositories = {}, {}
    for f in files:
        cluster = f.relative_to(root).parts[0]
        for obj in load_docs(f.read_text(encoding="utf-8")):
            kind = obj.get("kind")
            where = ident(obj)
            found = list(hook_facts(obj))
            if kind in WEBHOOK_KINDS:
                found += webhook_facts(obj)
            if kind not in SKIP_KINDS:
                found += list(rbac_facts(obj)) + list(privileged_facts(obj))
            for cls, detail in found:
                facts.setdefault((cls, where, detail), set()).add(cluster)
            if kind != "ClusterPolicy" and kind in SKIP_KINDS:
                continue
            # A ClusterPolicy is the GPU operator's image list; read it the way the record does.
            for ref in images_in(with_plan_tags(obj), operator_policy=kind == "ClusterPolicy"):
                parsed = parse_ref(ref)
                if parsed:
                    repositories.setdefault(parsed[0], {}).setdefault(ref, set()).add(cluster)
    return facts, repositories


def load_allowlist(path):
    """{registry: (prefixes, reason)}. An entry without `repositories` trusts the whole registry."""
    entries = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    allowed = {}
    for e in entries:
        if not isinstance(e, dict) or not e.get("registry") or not str(e.get("reason", "")).strip():
            fail(f"every allowlist entry needs a registry and a reason: {e}")
        if e["registry"] in allowed:
            fail(f"allowlist lists {e['registry']} twice; use one entry per registry")
        allowed[e["registry"]] = ([str(p) for p in e.get("repositories") or []], e["reason"])
    return allowed


def in_allowlist(repository, allowed):
    registry, _, path = repository.partition("/")
    if registry not in allowed:
        return False
    prefixes = allowed[registry][0]
    return not prefixes or any(path.startswith(p) for p in prefixes)


def compare(stable, candidate, allowed):
    """(additions, removals): sorted lists of {class, object, detail, clusters}."""
    (s_facts, s_repos), (c_facts, c_repos) = stable, candidate
    additions, removals = [], []

    def row(cls, where, detail, clusters):
        return {"class": cls, "object": where, "detail": detail, "clusters": sorted(clusters)}

    for key in sorted(set(c_facts) - set(s_facts)):
        additions.append(row(*key, c_facts[key]))
    for key in sorted(set(s_facts) - set(c_facts)):
        removals.append(row(*key, s_facts[key]))
    for repository in sorted(set(c_repos) - set(s_repos)):
        refs = c_repos[repository]
        clusters = set().union(*refs.values())
        additions.append(row("image", repository, ", ".join(sorted(refs)), clusters))
        if not in_allowlist(repository, allowed):
            additions.append(row("registry", repository, ", ".join(sorted(refs)), clusters))
    for repository in sorted(set(s_repos) - set(c_repos)):
        refs = s_repos[repository]
        removals.append(row("image", repository, ", ".join(sorted(refs)), set().union(*refs.values())))
    order = {c: i for i, c in enumerate(CLASSES)}
    key = lambda r: (order[r["class"]], r["object"], r["detail"])  # noqa: E731
    return sorted(additions, key=key), sorted(removals, key=key)


def table(rows, verb):
    out = []
    for cls in CLASSES:
        part = [r for r in rows if r["class"] == cls]
        if not part:
            continue
        out += [f"### {TITLES[cls]} ({verb}: {len(part)})", "", "| Object | Detail | Clusters |", "|---|---|---|"]
        for r in part[:SUMMARY_LIMIT]:
            detail = r["detail"].replace("|", "\\|").replace("\n", " ")
            out.append(f"| `{r['object']}` | `{detail}` | {', '.join(r['clusters'])} |")
        if len(part) > SUMMARY_LIMIT:
            out.append(f"| _{len(part) - SUMMARY_LIMIT} more rows are in manifest-risk.json_ | | |")
        out.append("")
    return out


def markdown(additions, removals):
    lines = ["## Manifest-risk diff", ""]
    if not additions and not removals:
        lines.append("No change in the risk classes between `stable` and the candidate. "
                     "No approval is needed.")
    elif not additions:
        lines.append("The candidate adds nothing in the risk classes. No approval is needed.")
    else:
        lines.append(f"The candidate adds {len(additions)} item(s) in the risk classes. "
                     "The owner must approve them on the `promote` environment.")
    lines.append("")
    if additions:
        lines += table(additions, "added")
    if removals:
        lines += ["Removals never need approval.", ""] + table(removals, "removed")
    return "\n".join(lines).rstrip() + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--stable", required=True, help="ci/render.py output for stable")
    p.add_argument("--candidate", required=True, help="ci/render.py output for the candidate")
    p.add_argument("--allowlist", required=True, help="registry allowlist file")
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()

    allowed = load_allowlist(args.allowlist)
    additions, removals = compare(load_side(args.stable), load_side(args.candidate), allowed)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "needsApproval": bool(additions),
        "additionCount": len(additions),
        "removalCount": len(removals),
        "additions": additions,
        "removals": removals,
    }
    (out / "manifest-risk.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "manifest-risk.md").write_text(markdown(additions, removals), encoding="utf-8")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"needs_approval={str(bool(additions)).lower()}\nadditions={len(additions)}\n")
    print(f"manifest-risk: {len(additions)} addition(s), {len(removals)} removal(s); "
          f"approval {'needed' if additions else 'not needed'}")


if __name__ == "__main__":
    main()
