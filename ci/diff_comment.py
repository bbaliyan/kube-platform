#!/usr/bin/env python3
"""Build the PR comment showing how a change alters what Argo CD applies.

Compares two render.py output directories (main vs. the PR) and writes a
Markdown comment: a per-object summary for each example cluster, then the
full diff in collapsible sections, trimmed to fit GitHub's comment size limit.

    python ci/diff_comment.py <base-dir> <head-dir> <out.md>
"""

import difflib
import sys
from pathlib import Path

MARKER = "<!-- rendered-manifests-diff -->"
LIMIT = 60000  # GitHub caps comments at 65536 characters


def objects(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(root.rglob("*.yaml"))} if root.exists() else {}


def main():
    base, head, out = objects(sys.argv[1]), objects(sys.argv[2]), Path(sys.argv[3])
    if not Path(sys.argv[1]).exists():
        out.write_text(f"{MARKER}\n## Rendered manifests\n\nCould not render the base branch, "
                       "so there is nothing to compare against. See the workflow log.\n", encoding="utf-8")
        return

    changes = []
    for path in sorted(set(base) | set(head)):
        old, new = base.get(path), head.get(path)
        if old == new:
            continue
        diff = "".join(difflib.unified_diff(
            (old or "").splitlines(keepends=True), (new or "").splitlines(keepends=True),
            fromfile=f"main/{path}", tofile=f"pr/{path}"))
        added = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
        state = "added" if old is None else "removed" if new is None else "changed"
        changes.append((path, state, added, removed, diff))

    lines = [MARKER, "## Rendered manifests", ""]
    if not changes:
        lines.append("No change to what Argo CD applies on any example cluster in `ci/clusters/`.")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    clusters = sorted({p.split("/", 1)[0] for p, *_ in changes})
    lines += [f"This PR changes {len(changes)} object(s) Argo CD applies, across "
              f"{len(clusters)} example cluster(s): {', '.join(clusters)}.", "",
              "| Cluster | App | Object | | +/- |", "|---|---|---|---|---|"]
    for path, state, added, removed, _ in changes:
        cluster, app, obj = path.split("/", 2)
        lines.append(f"| {cluster} | {app} | `{obj[:-5]}` | {state} | +{added} −{removed} |")
    lines.append("")

    body = "\n".join(lines)
    omitted = []
    for path, _, _, _, diff in changes:
        block = f"\n<details><summary><code>{path}</code></summary>\n\n```diff\n{diff}```\n</details>\n"
        if len(body) + len(block) > LIMIT:
            omitted.append(path)
            continue
        body += block
    if omitted:
        body += (f"\n_{len(omitted)} diff(s) omitted to fit the comment size limit; "
                 "the full diff is in the workflow's `rendered-manifests` artifact._\n")
    out.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    main()
