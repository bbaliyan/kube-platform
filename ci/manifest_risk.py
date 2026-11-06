#!/usr/bin/env python3
"""Compare two renders of this repo and keep only the changes that carry supply-chain risk.

A script is needed because no existing tool does this. ci/diff_comment.py shows
every changed line and cannot say whether a change matters. kubeconform and
Trivy see schema errors and image vulnerabilities, not a new hook, a wildcard
role or a mutating webhook. This script reads the output of ci/render.py for
`stable` and for the candidate, reduces each object to a few facts, and
compares the fact sets cluster by cluster. It reuses ci/promotion_record.py to
find images, so both agree on what an image is.

    ci/manifest_risk.py --stable out/base --candidate out/head \
        --allowlist ci/registry-allowlist.yaml --out-dir out/manifest-risk

The risk classes:
  rbac        a rule of a Role or ClusterRole, an aggregation rule or label,
              and the subjects and role of a binding
  webhook     a webhook of a webhook configuration (selectors, failure policy,
              target, CA bundle), an admission policy, an APIService, a CRD
              conversion webhook
  hook        an object with a Helm or Argo CD hook annotation, and the image,
              command and arguments of its containers
  privileged  privileged mode, added capabilities, privilege escalation,
              Unmasked procMount, Unconfined seccomp or AppArmor, running as
              root, hostPath and local volumes, hostNetwork, hostPID, hostIPC,
              hostPort, and the privileged Pod Security label of a namespace
  source      where an Argo CD Application pulls from (repoURL and chart or
              path, never targetRevision) and the sources and cluster resources
              an AppProject allows
  image       an image repository that `stable` does not use on that cluster
  registry    an image repository outside the allowlist, which also catches a
              typosquat

An addition is a fact that a cluster has in the candidate and does not have in
`stable`. The comparison is per cluster: a fact that exists on the aws cluster
in `stable` is still new on the kind cluster. A rule that changes shows as one
removal and one addition. A new tag of a repository that `stable` already uses
is not an addition: the soak, the scan and the daily digest check cover tags.
Every addition needs the owner's approval. A removal never does.

Output, in --out-dir:
  manifest-risk.json  the result data. `needsApproval` is true when there is
                      any addition. The promote workflow reads it.
  manifest-risk.md    the text for the run summary and the release. Every
                      field is cleaned and cut to a fixed length.
When GITHUB_OUTPUT is set, the script also writes `needs_approval` and
`additions` to it. It writes only a boolean and a number.

The script fails (exit 2) if a render is missing or has no objects, or if an
object cannot be read, so a broken render never looks like an empty diff.
"""

import argparse
import collections
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from promotion_record import SKIP_KINDS, images_in, parse_ref, with_plan_tags  # noqa: E402
from render import Loader  # noqa: E402

SCHEMA_VERSION = 1
CLASSES = ["rbac", "webhook", "hook", "privileged", "source", "image", "registry"]
HOOK_ANNOTATIONS = ("helm.sh/hook", "argocd.argoproj.io/hook")
WEBHOOK_KINDS = {"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}
POLICY_KINDS = {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
                "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding"}
NOT_WORKLOADS = SKIP_KINDS | {"List"}
APPARMOR_ANNOTATION = "container.apparmor.security.beta.kubernetes.io/"
AGGREGATE_LABEL = "rbac.authorization.k8s.io/aggregate-to-"

# Limits that keep the output readable and bounded, however hostile the input.
OBJECT_LIMIT = 120   # characters of an object name in the summary
DETAIL_LIMIT = 240   # characters of a detail
CLUSTER_LIMIT = 120  # characters of the cluster list
MD_ROWS = 150        # added rows in the summary, most severe first
MD_REMOVED_ROWS = 30
MD_HIDDEN_OBJECTS = 50
JSON_ROWS = 5000     # rows per list in the JSON; the counts are always complete
MD_BYTES = 900_000   # GitHub caps a job summary at 1 MiB


def fail(message):
    print(f"manifest-risk: {message}", file=sys.stderr)
    sys.exit(2)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def dct(x):
    return x if isinstance(x, dict) else {}


def lst(x):
    return [i for i in x if isinstance(i, dict)] if isinstance(x, list) else []


def ident(obj):
    md = dct(obj.get("metadata"))
    parts = (str(obj.get("kind", "?")), str(md.get("namespace") or ""), str(md.get("name") or "?"))
    return "/".join(p for p in parts if p)


def all_dicts(node):
    """Every mapping at or below node."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from all_dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from all_dicts(v)


def has_ca(client):
    return "caBundle set" if client.get("caBundle") else "no caBundle"


def target_of(client):
    return client.get("url") or compact(client.get("service"))


def rbac_facts(obj):
    kind = obj.get("kind")
    labels = dct(dct(obj.get("metadata")).get("labels"))
    if kind in ("Role", "ClusterRole"):
        for rule in lst(obj.get("rules")):
            yield "rbac", f"rule {compact(rule)}"
        if obj.get("aggregationRule"):
            yield "rbac", f"aggregation {compact(obj['aggregationRule'])}"
        for key in sorted(labels):
            if str(key).startswith(AGGREGATE_LABEL):
                yield "rbac", f"label {key}={labels[key]}"
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        role = dct(obj.get("roleRef"))
        for s in lst(obj.get("subjects")):
            yield "rbac", f"binds {compact(s)} to {role.get('kind')}/{role.get('name')}"


def webhook_facts(obj):
    kind, spec = obj.get("kind"), dct(obj.get("spec"))
    if kind in WEBHOOK_KINDS:
        keys = ("failurePolicy", "rules", "namespaceSelector", "objectSelector", "matchPolicy",
                "sideEffects", "timeoutSeconds", "matchConditions", "reinvocationPolicy")
        for hook in lst(obj.get("webhooks")):
            detail = {k: hook.get(k) for k in keys}
            client = dct(hook.get("clientConfig"))
            detail["target"] = target_of(client)
            detail["ca"] = has_ca(client)
            yield "webhook", f"{hook.get('name')} {compact(detail)}"
    elif kind == "APIService":
        detail = {k: spec.get(k) for k in ("group", "version", "service", "insecureSkipTLSVerify")}
        detail["ca"] = "caBundle set" if spec.get("caBundle") else "no caBundle"
        yield "webhook", f"apiservice {compact(detail)}"
    elif kind in POLICY_KINDS:
        yield "webhook", f"spec {compact(spec)}"
    elif kind == "CustomResourceDefinition":
        conversion = dct(spec.get("conversion"))
        if conversion.get("strategy") == "Webhook":
            webhook = dct(conversion.get("webhook"))
            client = dct(webhook.get("clientConfig"))
            yield "webhook", (f"conversion {target_of(client)} {has_ca(client)} "
                              f"{compact(webhook.get('conversionReviewVersions'))}")


def hook_facts(obj):
    annotations = dct(dct(obj.get("metadata")).get("annotations"))
    for key in HOOK_ANNOTATIONS:
        if key not in annotations:
            continue
        yield "hook", f"{key}={annotations[key]}"
        for d in all_dicts(obj):
            if isinstance(d.get("image"), str) and d.get("name"):
                yield "hook", (f"{key}={annotations[key]} container {d['name']} image {d['image']} "
                               f"command {compact(d.get('command'))} args {compact(d.get('args'))}")


def security_context_facts(d):
    sc = dct(d.get("securityContext"))
    where = f"container {d['name']}" if d.get("name") else "pod"
    if sc.get("privileged") is True:
        yield "privileged", f"privileged {where}"
    if sc.get("allowPrivilegeEscalation") is True:
        yield "privileged", f"allowPrivilegeEscalation {where}"
    if sc.get("procMount") == "Unmasked":
        yield "privileged", f"procMount Unmasked {where}"
    for key in ("seccompProfile", "appArmorProfile"):
        if dct(sc.get(key)).get("type") == "Unconfined":
            yield "privileged", f"{key} Unconfined {where}"
    caps = dct(sc.get("capabilities")).get("add")
    for cap in sorted(str(c) for c in caps) if isinstance(caps, list) else []:
        yield "privileged", f"capability {cap} {where}"
    if sc.get("runAsUser") == 0 and not isinstance(sc.get("runAsUser"), bool):
        yield "privileged", f"runAsUser 0 {where}"


def privileged_facts(obj):
    kind, md = obj.get("kind"), dct(obj.get("metadata"))
    if kind == "Namespace" and dct(md.get("labels")).get("pod-security.kubernetes.io/enforce") == "privileged":
        yield "privileged", "namespace label pod-security.kubernetes.io/enforce=privileged"
    spec = dct(obj.get("spec"))
    if kind == "PersistentVolume" and isinstance(spec.get("local"), dict):
        yield "privileged", f"local volume {dct(spec['local']).get('path')}"
    for d in all_dicts(obj):
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if d.get(key) is True:
                yield "privileged", key
        if isinstance(d.get("hostPath"), dict):
            yield "privileged", f"hostPath {d['hostPath'].get('path')}"
        port = d.get("hostPort")
        if isinstance(port, int) and not isinstance(port, bool) and port > 0:
            yield "privileged", f"hostPort {port}"
        yield from security_context_facts(d)
        for key, value in dct(d.get("annotations")).items():
            if str(key).startswith(APPARMOR_ANNOTATION) and value == "unconfined":
                yield "privileged", f"annotation {key}=unconfined"


def source_facts(obj):
    spec = dct(obj.get("spec"))
    if obj.get("kind") == "Application":
        for s in lst(spec.get("sources")) + lst([spec.get("source")]):
            what = f"chart={s.get('chart')}" if s.get("chart") else f"path={s.get('path') or '.'}"
            yield "source", f"repoURL={s.get('repoURL')} {what}"
    elif obj.get("kind") == "AppProject":
        for repo in spec.get("sourceRepos") or []:
            yield "source", f"sourceRepos {repo}"
        for key in ("clusterResourceWhitelist", "namespaceResourceWhitelist"):
            for entry in lst(spec.get(key)):
                yield "source", f"{key} {compact(entry)}"


def facts_of(obj):
    found = list(source_facts(obj)) + list(hook_facts(obj)) + list(webhook_facts(obj))
    if obj.get("kind") not in NOT_WORKLOADS:
        found += list(rbac_facts(obj)) + list(privileged_facts(obj))
    return found


def read_objects(root):
    """Every object of one render as (cluster, object). A List is flattened. An
    object that cannot be read fails the run."""
    root = Path(root)
    files = sorted(root.rglob("*.yaml")) if root.is_dir() else []
    out = []
    for f in files:
        cluster = f.relative_to(root).parts[0]
        try:
            docs = list(yaml.load_all(f.read_text(encoding="utf-8"), Loader=Loader))
        except (yaml.YAMLError, UnicodeDecodeError) as e:
            fail(f"cannot read {f}: {(str(e).splitlines() or ['error'])[0]}")
        stack = [d for d in docs if d is not None]
        while stack:
            d = stack.pop(0)
            if not isinstance(d, dict) or not isinstance(d.get("kind"), str):
                fail(f"cannot read an object in {f}: it has no kind")
            if d["kind"].endswith("List") and "items" in d:
                if not isinstance(d["items"], list):
                    fail(f"cannot read the List in {f}: items is not a list")
                stack = d["items"] + stack
            else:
                out.append((cluster, d))
    if not out:
        fail(f"no rendered objects in {root}")
    return out


def load_side(root):
    """({(cluster, class, object, detail)}, {(cluster, repository): {image refs}}) for one render."""
    facts, repositories = set(), {}
    for cluster, obj in read_objects(root):
        kind, where = obj["kind"], ident(obj)
        for cls, detail in facts_of(obj):
            facts.add((cluster, cls, where, detail))
        if kind in SKIP_KINDS and kind != "ClusterPolicy":
            continue
        # A ClusterPolicy is the GPU operator's image list; read it the way the record does.
        for ref in images_in(with_plan_tags(obj), operator_policy=kind == "ClusterPolicy"):
            parsed = parse_ref(ref)
            if parsed:
                repositories.setdefault((cluster, parsed[0]), set()).add(ref)
    return facts, repositories


def load_allowlist(path):
    """{registry: (prefixes or None, reason)}. An entry without `repositories` trusts the whole registry."""
    try:
        entries = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as e:
        fail(f"cannot read the allowlist: {e}")
    if not isinstance(entries, list):
        fail("the allowlist must be a list of entries")
    allowed = {}
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("registry"), str) or not e["registry"] \
                or not str(e.get("reason") or "").strip():
            fail(f"every allowlist entry needs a registry and a reason: {e}")
        registry = e["registry"]
        if "/" in registry or "://" in registry or registry != registry.strip().lower():
            fail(f"allowlist registry must be a lower-case host without a scheme or path: {registry}")
        if registry in allowed:
            fail(f"allowlist lists {registry} twice; use one entry per registry")
        prefixes = None
        if "repositories" in e:
            raw = e["repositories"]
            if not isinstance(raw, list) or not raw or not all(isinstance(p, str) and p.strip("/") for p in raw):
                fail(f"allowlist repositories for {registry} must be a non-empty list of prefixes; "
                     "leave the key out to trust the whole registry")
            # A prefix ends at a path boundary, so `grafana` cannot trust `grafana-evil/`.
            prefixes = [p.strip("/") + "/" for p in raw]
        allowed[registry] = (prefixes, e["reason"])
    return allowed


def in_allowlist(repository, allowed):
    registry, _, path = repository.partition("/")
    if registry not in allowed:
        return False
    prefixes = allowed[registry][0]
    return prefixes is None or any(path.startswith(p) for p in prefixes)


def severity(row):
    """0 is the most severe. The approver reads the rows in this order."""
    cls, detail = row["class"], row["detail"]
    if cls == "registry":
        return 0
    if cls == "rbac" and ('"*"' in detail or detail.endswith(" to ClusterRole/cluster-admin")):
        return 0
    if cls == "privileged" and (detail.startswith("privileged ") or detail.startswith("capability ALL ")
                                or detail.startswith("capability SYS_ADMIN ")):
        return 0
    if cls == "source" and "*" in detail:
        return 0
    if cls in ("webhook", "hook", "privileged"):
        return 1
    if cls in ("rbac", "source"):
        return 2
    return 3


def compare(stable, candidate, allowed):
    """(additions, removals): lists of {class, severity, object, detail, clusters}, most severe first."""
    (s_facts, s_repos), (c_facts, c_repos) = stable, candidate

    def rows(keys, repos, other_repos, check_allowlist):
        grouped = collections.defaultdict(set)
        for cluster, cls, where, detail in keys:
            grouped[(cls, where, detail)].add(cluster)
        for cluster, repository in repos.keys() - other_repos.keys():
            detail = ", ".join(sorted(repos[(cluster, repository)]))
            grouped[("image", repository, detail)].add(cluster)
            if check_allowlist and not in_allowlist(repository, allowed):
                grouped[("registry", repository, f"outside the allowlist: {detail}")].add(cluster)
        out = [{"class": c, "object": w, "detail": d, "clusters": sorted(cl)}
               for (c, w, d), cl in grouped.items()]
        for r in out:
            r["severity"] = severity(r)
        order = {c: i for i, c in enumerate(CLASSES)}
        return sorted(out, key=lambda r: (r["severity"], order[r["class"]], r["object"], r["detail"]))

    return (rows(c_facts - s_facts, c_repos, s_repos, True),
            rows(s_facts - c_facts, s_repos, c_repos, False))


def clean(text, limit):
    """Text that is safe inside a Markdown table cell and a code span: no backtick,
    newline, pipe, angle bracket or mention. Cut to limit, with a hash of the
    whole text so two long values that differ stay distinct."""
    whole = str(text)
    text = re.sub(r"[\x00-\x1f\x7f  ]+", " ", whole)
    text = (text.replace("`", "'").replace("|", "¦").replace("<", "‹")
            .replace(">", "›").replace("@", "@​"))
    if len(text) > limit:
        text = f"{text[:limit]}...[{hashlib.sha256(whole.encode()).hexdigest()[:8]}]"
    return text


def row_line(r):
    return (f"| {r['severity']} | {r['class']} | `{clean(r['object'], OBJECT_LIMIT)}` | "
            f"`{clean(r['detail'], DETAIL_LIMIT)}` | {clean(', '.join(r['clusters']), CLUSTER_LIMIT)} |")


def section(title, rows, limit):
    out = [f"### {title}", "", "| Severity | Class | Object | Detail | Clusters |", "|---|---|---|---|---|"]
    out += [row_line(r) for r in rows[:limit]]
    hidden = rows[limit:]
    if hidden:
        by_object = collections.Counter(r["object"] for r in hidden)
        out += ["", f"{len(hidden)} more row(s) on {len(by_object)} object(s) are not shown here. "
                "They are in manifest-risk.json, in the same order. Rows per object:", ""]
        for obj, n in by_object.most_common(MD_HIDDEN_OBJECTS):
            out.append(f"- `{clean(obj, OBJECT_LIMIT)}`: {n}")
        if len(by_object) > MD_HIDDEN_OBJECTS:
            rest = sum(n for _, n in by_object.most_common()[MD_HIDDEN_OBJECTS:])
            out.append(f"- and {len(by_object) - MD_HIDDEN_OBJECTS} more object(s): {rest} row(s)")
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
    if additions or removals:
        added = collections.Counter(r["class"] for r in additions)
        removed = collections.Counter(r["class"] for r in removals)
        lines += ["| Class | Added | Removed |", "|---|---|---|"]
        lines += [f"| {c} | {added[c]} | {removed[c]} |" for c in CLASSES if added[c] or removed[c]]
        lines.append("")
    if additions:
        lines += section("Added, most severe first", additions, MD_ROWS)
    if removals:
        lines += ["Removals never need approval.", ""]
        lines += section("Removed", removals, MD_REMOVED_ROWS)
    text = "\n".join(lines).rstrip() + "\n"
    if len(text.encode()) > MD_BYTES:
        text = text.encode()[:MD_BYTES].decode(errors="ignore") + "\n\n_Output cut. See manifest-risk.json._\n"
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--stable", required=True, help="ci/render.py output for stable")
    p.add_argument("--candidate", required=True, help="ci/render.py output for the candidate")
    p.add_argument("--allowlist", required=True, help="registry allowlist file")
    p.add_argument("--out-dir", required=True)
    args = p.parse_args()

    allowed = load_allowlist(args.allowlist)
    additions, removals = compare(load_side(args.stable), load_side(args.candidate), allowed)

    def bounded(rows):
        return [{**r, "object": r["object"][:OBJECT_LIMIT * 2],
                 "detail": clean(r["detail"], DETAIL_LIMIT * 2)} for r in rows[:JSON_ROWS]]

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "needsApproval": bool(additions),
        "additionCount": len(additions),
        "removalCount": len(removals),
        "truncated": max(len(additions), len(removals)) > JSON_ROWS,
        "additions": bounded(additions),
        "removals": bounded(removals),
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
