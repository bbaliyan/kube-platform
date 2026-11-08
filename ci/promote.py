#!/usr/bin/env python3
"""The decisions of the promote workflow: which commit, whether it is a revert, whether the gates agree.

A script is needed because no existing tool does these decisions. git and the
GitHub CLI give the facts (first-parent history, the time each pull request
merged, the pinned release), but nothing joins them into "the newest commit
that landed at least 7 days ago", "a chart or image that main dropped again" or
"the final job agrees with the gate jobs". The workflow runs this file from a
trusted checkout and never from the candidate tree. The script runs git and gh
and does only the joining and the decision. Everything else (render, tests,
scan, manifest-risk diff) stays in the Makefile.

    ci/promote.py select   --repo-root . --head SHA --repo OWNER/NAME --out out/select.json
                           [--fast-path-reason TEXT] [--stable-ref origin/stable]
    ci/promote.py baseline --releases releases.json [--first-promotion --stable-sha SHA --tags FILE]
    ci/promote.py check-baseline --record FILE --stable-sha SHA
    ci/promote.py deps     --rendered out/head --repo-root . --out deps.json
    ci/promote.py revert-check --candidate deps.json --head deps.json --stable deps.json --out revert.json
    ci/promote.py choose   (reads toJSON(needs) from the environment variable NEEDS_JSON)
    ci/promote.py digest / check-digest --path FILE_OR_DIR [--expected SHA256]
    ci/promote.py review   --select S --record R --risk J --risk-md M --revert V --candidate SHA
    ci/promote.py verify   --select S --record R --risk J --revert V --candidate SHA --stable-sha SHA
    ci/promote.py tag-name < ls-remote-output
    ci/promote.py notes    --select S --record R --risk-md M --candidate SHA --tag TAG --repo OWNER/NAME

When GITHUB_OUTPUT is set, the commands write their results to it as single-line values.

Candidate rule. The unit is a commit on the first-parent line of main, because
that is how a pull request lands. The time a commit landed is the `merged_at`
of its merged pull request, from the GitHub API. The committer date is not
used: a push that skips a pull request lets its author choose that date. A
commit with no merged pull request has an unknown time and counts as landed
now, so it is never old enough. The effective time of a commit is the latest
landing time of itself and of every older commit after `stable`, so a commit
that claims an early time cannot hide a younger change below it. The weekly
run takes the newest commits whose effective time is at least 7 days old, at
most three, newest first. The workflow tries them in this order.

Revert check. A chart (repository, name, version) or image (repository, tag) of
the candidate is a revert when main HEAD does not have it, `stable` does not
have it, and main HEAD does not hold a newer version of the same chart or
image repository. A newer version at HEAD is an ordinary update that landed
after the candidate and is not a revert. A version that cannot be ordered
(a digest, a tag without numbers) counts as a revert.

Fast path. A manual run with a written reason promotes main HEAD at once. If
any other commit since `stable` is younger than 7 days, the run is marked: the
approval must cover the aggregate diff of all of them, and the summary says so.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

SCHEMA_VERSION = 1
SOAK_DAYS = 7
MAX_CANDIDATES = 3
MAX_COMMITS = 300
MAX_RECORD_AGE_HOURS = 72
NOTES_LIMIT = 100_000
SUMMARY_LIMIT = 400_000
# The commit that `stable` was created at. A first promotion is allowed only while
# stable is still here and no stable-* tag exists.
INITIAL_STABLE = "26229cc6fb30845eb7b323d80e113ae5d83012ef"
REASON_LIMIT = 200
TAG_RE = re.compile(r"^stable-\d{8}(-\d+)?$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def parse_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_from(arg):
    return parse_time(arg) if arg else datetime.now(timezone.utc)


def set_output(**values):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        for key, value in values.items():
            value = str(value)
            if "\n" in value or "\r" in value:
                sys.exit(f"output {key} holds a line break")
            f.write(f"{key}={value}\n")


def clean_reason(text):
    """The reason as stored: no control characters, cut to REASON_LIMIT."""
    return CONTROL.sub(" ", (text or "")).strip()[:REASON_LIMIT]


ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "`": "'", "|": "&#124;", "[": "&#91;", "]": "&#93;",
           "*": "&#42;", "_": "&#95;", "~": "&#126;", "#": "&#35;", "!": "&#33;", "\\": "&#92;", "@": "@\u200b"}


def escape_text(text):
    """Text that is safe in Markdown, HTML and a mention. It follows clean() in
    ci/manifest_risk.py and also escapes the emphasis and link characters. One
    pass, so an escape is never escaped again."""
    text = re.sub(r"[\x00-\x1f\x7f\u00a0\u2028\u2029]+", " ", str(text))
    return re.sub(r"[&<>`|\[\]*_~#!\\@]", lambda m: ESCAPES[m.group(0)], text)


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- candidates

def with_effective(commits, now):
    """commits: newest first, each {"sha", "landedAt"} (landedAt may be null).
    Returns the same order with the effective landing time of each commit."""
    out, running = [], None
    for c in reversed(commits):
        t = parse_time(c["landedAt"]) if c.get("landedAt") else now
        running = t if running is None or t > running else running
        out.append({"sha": c["sha"], "landedAt": iso(running), "known": bool(c.get("landedAt"))})
    return list(reversed(out))


def weekly_candidates(commits, now, soak_days=SOAK_DAYS, limit=MAX_CANDIDATES):
    cutoff = now - timedelta(days=soak_days)
    eligible = [c for c in with_effective(commits, now) if parse_time(c["landedAt"]) <= cutoff]
    chosen = eligible[:limit]
    assert all(parse_time(c["landedAt"]) <= cutoff for c in chosen), "a candidate is younger than the soak"
    return chosen, len(eligible)


def fast_path_candidate(commits, now, soak_days=SOAK_DAYS):
    """main HEAD, and the other commits since stable that are younger than the soak."""
    cutoff = now - timedelta(days=soak_days)
    head = with_effective(commits, now)[0]
    others = with_effective(commits[1:], now)
    young = [c for c in others if parse_time(c["landedAt"]) > cutoff]
    return head, young


def decide_selection(commits, state, now, fast_reason="", limit=MAX_CANDIDATES):
    result = {"schemaVersion": SCHEMA_VERSION, "now": iso(now), "soakDays": SOAK_DAYS,
              "mode": "fast-path" if fast_reason else "weekly", "fastPathReason": fast_reason,
              "candidates": [], "eligibleCount": 0, "youngerCommits": [], "aggregateApproval": False,
              "action": "promote", "nothingReason": ""}
    if state != "behind":
        result.update(action="nothing", nothingReason="stable is at or ahead of main HEAD")
        return result
    if not commits:
        result.update(action="nothing", nothingReason="no commit since stable")
        return result
    if fast_reason:
        head, young = fast_path_candidate(commits, now)
        result["candidates"] = [head]
        result["eligibleCount"] = 1
        result["youngerCommits"] = [c["sha"] for c in young]
        result["aggregateApproval"] = bool(young)
        return result
    chosen, eligible = weekly_candidates(commits, now, limit=limit)
    result["candidates"], result["eligibleCount"] = chosen, eligible
    if not chosen:
        result.update(action="nothing", nothingReason="no commit has landed at least 7 days ago yet")
    return result


def run(cmd, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if check and res.returncode != 0:
        sys.exit(f"{' '.join(cmd[:4])} failed: {res.stderr.strip() or res.stdout.strip()}")
    return res


def is_ancestor(root, older, newer):
    res = run(["git", "-C", root, "merge-base", "--is-ancestor", older, newer], check=False)
    if res.returncode not in (0, 1):
        sys.exit(f"git merge-base failed: {res.stderr.strip()}")
    return res.returncode == 0


def landed_at(repo, sha, branch):
    """The latest merged_at of the merged pull requests that hold the commit.
    Only a pull request whose merge commit is this commit counts. A rebase
    merge has none, so its commits have an unknown time and are never old
    enough. That is the safe side."""
    out = run(["gh", "api", "-H", "Accept: application/vnd.github+json",
               f"repos/{repo}/commits/{sha}/pulls"]).stdout
    times = [pr["merged_at"] for pr in json.loads(out)
             if pr.get("merged_at") and pr.get("merge_commit_sha") == sha
             and (pr.get("base") or {}).get("ref") == branch]
    return max(times) if times else None


def gather(args):
    root = args.repo_root
    stable = run(["git", "-C", root, "rev-parse", "--verify", f"{args.stable_ref}^{{commit}}"]).stdout.strip()
    head = args.head
    if head == stable or is_ancestor(root, head, stable):
        return stable, head, "ahead", []
    if not is_ancestor(root, stable, head):
        sys.exit(f"stable ({stable}) is not an ancestor of main HEAD ({head}): the histories diverged. "
                 "The owner must fix this by hand.")
    shas = run(["git", "-C", root, "rev-list", "--first-parent", f"{stable}..{head}"]).stdout.split()
    if len(shas) > MAX_COMMITS:
        sys.exit(f"{len(shas)} commits since stable; the limit is {MAX_COMMITS}. Promote by hand.")
    parent = run(["git", "-C", root, "rev-parse", f"{shas[-1]}^"]).stdout.strip()
    if parent != stable:
        sys.exit("stable is not on the first-parent line of main HEAD; refusing to guess.")
    return stable, head, "behind", [{"sha": s, "landedAt": landed_at(args.repo, s, args.branch)} for s in shas]


def cmd_select(args):
    now = now_from(args.now)
    reason = clean_reason(args.fast_path_reason)
    if args.commits_file:
        data = load_json(args.commits_file)
        stable, head, state, commits = data["stable"], data["head"], data.get("state", "behind"), data["commits"]
    else:
        if not args.head:
            sys.exit("select needs --head")
        stable, head, state, commits = gather(args)
    result = decide_selection(commits, state, now, reason, args.limit)
    result.update(stableSha=stable, headSha=head)
    write_json(args.out, result)
    cands = [c["sha"] for c in result["candidates"]] + [""] * args.limit
    set_output(nothing_to_do="true" if result["action"] == "nothing" else "false",
               candidate_count=len(result["candidates"]), candidate_1=cands[0], candidate_2=cands[1],
               candidate_3=cands[2], stable_sha=stable, mode=result["mode"])
    print(markdown_selection(result))
    return 0


def markdown_selection(sel):
    lines = [f"## Candidate selection ({sel['mode']})", "",
             f"- main HEAD: `{sel['headSha']}`", f"- stable: `{sel['stableSha']}`"]
    if sel["mode"] == "fast-path":
        lines.append(f"- fast path reason: {escape_text(sel['fastPathReason'])}")
        if sel["aggregateApproval"]:
            lines.append(f"- **{len(sel['youngerCommits'])} other commit(s) since stable are younger than "
                         f"{sel['soakDays']} days. Approve the aggregate diff of all of them.**")
    if sel["action"] == "nothing":
        lines.append(f"- nothing to do: {sel['nothingReason']}")
    for i, c in enumerate(sel["candidates"], 1):
        known = "" if c["known"] else " (landing time unknown)"
        lines.append(f"- candidate {i}: `{c['sha']}`, landed {c['landedAt']}{known}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ baseline

def pick_baseline_tag(releases):
    """The newest published stable-YYYYMMDD release. A draft, a pre-release and
    any other tag name are ignored."""
    tags = sorted(r["tagName"] for r in releases
                  if TAG_RE.match(r.get("tagName", "")) and not r.get("isDraft") and not r.get("isPrerelease"))
    return tags[-1] if tags else ""


def check_first_promotion(stable_sha, tags_text):
    """Problems that forbid a first promotion: any stable-* tag, or a stable
    that has moved from the commit it was created at."""
    problems = []
    tags = [line.split()[-1] for line in tags_text.splitlines() if line.strip()]
    if tags:
        problems.append(f"tags exist ({', '.join(tags[:3])}); a first promotion needs none")
    if stable_sha != INITIAL_STABLE:
        problems.append(f"stable is at {stable_sha}, not at its initial commit {INITIAL_STABLE}")
    return problems


def cmd_baseline(args):
    tag = pick_baseline_tag(load_json(args.releases))
    if tag and args.first_promotion:
        sys.exit(f"first_promotion was set, but release {tag} exists. Run again without it.")
    if args.first_promotion:
        tags_text = Path(args.tags).read_text(encoding="utf-8") if args.tags else "unreadable"
        problems = check_first_promotion(args.stable_sha or "", tags_text)
        if problems:
            sys.exit("first_promotion refused: " + "; ".join(problems))
    if not tag and not args.first_promotion:
        sys.exit("no stable release exists. If this is the first promotion, start the run by hand with "
                 "first_promotion set. A scheduled run does not promote without a baseline.")
    set_output(baseline_tag=tag, first_promotion="false" if tag else "true")
    print(f"baseline: {tag or 'none (first promotion)'}")
    return 0


def cmd_check_baseline(args):
    record = load_json(args.record)
    if record.get("commit") != args.stable_sha:
        sys.exit(f"the baseline record is for {record.get('commit')}, but stable is {args.stable_sha}. "
                 "stable moved without a release. The owner must fix this by hand.")
    print("baseline record matches stable")
    return 0


# ------------------------------------------------------------- revert check

def deps_of(rendered, repo_root):
    import promotion_record as pr
    images, apps, _ = pr.read_rendered(rendered)
    refs = set()
    for ref in images:
        name, tag, digest = pr.parse_ref(ref)
        refs.add(pr.reference((name, None if digest else tag, digest)))
    charts = sorted([r, n, v] for r, n, v in pr.chart_requests(apps, repo_root))
    return {"images": sorted(refs), "charts": charts}


def cmd_deps(args):
    write_json(args.out, deps_of(args.rendered, args.repo_root))
    return 0


def image_parts(ref):
    if "@" in ref:
        name, _, digest = ref.partition("@")
        return name, digest
    head, _, last = ref.rpartition("/")
    base, _, tag = last.partition(":")
    return (f"{head}/{base}" if head else base), tag


def entries(deps):
    found = {("image", *image_parts(r)) for r in deps["images"]}
    found |= {("chart", f"{r} {n}", v) for r, n, v in deps["charts"]}
    return found


def numbers(version):
    if version.startswith("sha256:"):
        return None
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) or None


def is_newer(version, than):
    a, b = numbers(version), numbers(than)
    return a is not None and b is not None and a > b


def revert_check(candidate, head, stable):
    have_head, have_stable = entries(head), entries(stable)
    reverted = []
    for kind, key, version in sorted(entries(candidate)):
        if (kind, key, version) in have_head or (kind, key, version) in have_stable:
            continue
        head_versions = sorted(v for k, n, v in have_head if (k, n) == (kind, key))
        if any(is_newer(v, version) for v in head_versions):
            continue
        reverted.append({"kind": kind, "name": key, "version": version, "headVersions": head_versions,
                         "stableVersions": sorted(v for k, n, v in have_stable if (k, n) == (kind, key))})
    return {"schemaVersion": SCHEMA_VERSION, "blocked": bool(reverted), "reverted": reverted}


def cmd_revert_check(args):
    result = revert_check(load_json(args.candidate), load_json(args.head), load_json(args.stable))
    write_json(args.out, result)
    for r in result["reverted"]:
        print(f"revert: {r['kind']} {r['name']} {r['version']} (main has {r['headVersions'] or 'none'}, "
              f"stable has {r['stableVersions'] or 'none'})")
    print("revert check: blocked" if result["blocked"] else "revert check: clear")
    return 1 if result["blocked"] else 0


# ------------------------------------------------------------------- digest

def tree_digest(path):
    """One SHA-256 for a file or a directory: over the sorted relative names and
    the digests of the files. The producing job writes it as a job output, and
    each consumer checks the downloaded copy against it."""
    path = Path(path)
    if path.is_symlink():
        sys.exit(f"{path} is a symlink")
    files = [path] if path.is_file() else sorted(f for f in path.rglob("*") if f.is_file() or f.is_symlink())
    if not files:
        sys.exit(f"{path} holds no file")
    lines = []
    for f in files:
        if f.is_symlink():
            sys.exit(f"{f} is a symlink")
        name = "." if f == path else f.relative_to(path).as_posix()
        lines.append(f"{name} {hashlib.sha256(f.read_bytes()).hexdigest()}")
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def cmd_digest(args):
    value = tree_digest(args.path)
    set_output(digest=value)
    print(value)
    return 0


def cmd_check_digest(args):
    value = tree_digest(args.path)
    if not re.fullmatch(r"[a-f0-9]{64}", args.expected or "") or value != args.expected:
        print(f"check-digest: {args.path} is {value}, the producing job said {args.expected or 'nothing'}", file=sys.stderr)
        return 1
    print(f"check-digest: {args.path} matches")
    return 0


# ------------------------------------------------------------------- choose

SLOTS = (1, 2, 3)


def choose(needs):
    """The first candidate whose job succeeded and whose evaluation says pass.
    needs is the `needs` context of the choose job (toJSON(needs)). A skipped,
    failed or cancelled candidate is passed over. Approval is needed unless the
    result is exactly 'false'."""
    select = (needs.get("select") or {}).get("outputs") or {}
    rows, picked = [], None
    for slot in SLOTS:
        node = needs.get(f"candidate-{slot}") or {}
        out = node.get("outputs") or {}
        sha = select.get(f"candidate_{slot}") or ""
        outcome = node.get("result") or "skipped"
        passed = bool(sha) and outcome == "success" and out.get("result") == "pass"
        rows.append({"slot": slot, "sha": sha, "job": outcome, "failed": out.get("failed") or ""})
        if passed and picked is None:
            picked = {"slot": slot, "sha": sha, "needs_approval": "false" if out.get("needs_approval") == "false" else "true",
                      "scanned_digest": out.get("scanned_digest") or "", "risk_digest": out.get("risk_digest") or ""}
    return picked, rows


def cmd_choose(args):
    picked, rows = choose(json.loads(os.environ["NEEDS_JSON"]))
    lines = ["## Candidates", ""]
    for r in rows:
        detail = f" (failed: {r['failed']})" if r["failed"] else ""
        lines.append(f"- {r['slot']}: `{r['sha'] or 'none'}` {r['job']}{detail}")
    print("\n".join(lines))
    picked = picked or {"slot": "", "sha": "", "needs_approval": "", "scanned_digest": "", "risk_digest": ""}
    set_output(**picked)
    return 0


# ------------------------------------------------------------------- verify

def validate_record(record):
    import promotion_record as pr
    return pr.validate_record(record)


def verify(sel, record, risk, revert, candidate, stable_sha, now, first_promotion=False,
           max_age_hours=MAX_RECORD_AGE_HOURS):
    problems = []
    if sel.get("schemaVersion") != SCHEMA_VERSION or sel.get("action") != "promote":
        problems.append("the selection does not say promote")
    if not SHA_RE.match(candidate or ""):
        problems.append("the candidate is not a full commit hash")
    listed = [c["sha"] for c in sel.get("candidates", [])]
    if candidate not in listed:
        problems.append("the candidate is not one the selection chose")
    if sel.get("stableSha") != stable_sha:
        problems.append(f"stable moved since the selection ({sel.get('stableSha')} -> {stable_sha})")
    chosen = next((c for c in sel.get("candidates", []) if c["sha"] == candidate), None)
    if chosen and sel.get("mode") == "weekly":
        if parse_time(chosen["landedAt"]) > now - timedelta(days=sel.get("soakDays", SOAK_DAYS)):
            problems.append("a weekly candidate is younger than the soak")
    if sel.get("mode") == "fast-path" and not sel.get("fastPathReason"):
        problems.append("a fast path run has no reason")
    if len(sel.get("fastPathReason") or "") > REASON_LIMIT:
        problems.append("the fast path reason is longer than the limit")

    problems += [f"record: {p}" for p in validate_record(record)]
    scan = record.get("scan") or {}
    if record.get("commit") != candidate:
        problems.append(f"the record is for {record.get('commit')}, not the candidate")
    if scan.get("verdict") != "pass":
        problems.append(f"the security verdict is {scan.get('verdict')!r}, not 'pass'")
    counts = scan.get("counts") or {}
    if counts.get("blocking") != 0 or any(f.get("status") == "blocking" for f in scan.get("findings", [])):
        problems.append("the record lists blocking findings")
    if scan.get("reasons"):
        problems.append("the record lists block reasons")
    listed_images = len(record.get("images", []))
    if scan.get("imagesListed") != listed_images or scan.get("imagesScanned") != listed_images:
        problems.append("the scan did not cover every image of the record")
    if not (record.get("scanner") or {}).get("databaseUpdatedAt"):
        problems.append("the record names no scanner database time")
    expected_baseline = None if first_promotion else stable_sha
    if scan.get("baselineCommit") != expected_baseline:
        problems.append(f"the delta was taken against {scan.get('baselineCommit')}, expected {expected_baseline}")
    if scan.get("scannedAt"):
        age = now - parse_time(scan["scannedAt"])
        if age > timedelta(hours=max_age_hours):
            problems.append(f"the scan is {int(age.total_seconds() // 3600)} hours old; the limit is "
                            f"{max_age_hours}. Run the workflow again.")
        if age < timedelta(minutes=-5):
            problems.append("the scan time is in the future")

    if risk.get("schemaVersion") != 1 or not isinstance(risk.get("needsApproval"), bool):
        problems.append("the manifest-risk result is not valid")
    elif risk["needsApproval"] != (risk.get("additionCount", 0) > 0):
        problems.append("the manifest-risk result contradicts itself")
    if revert.get("schemaVersion") != SCHEMA_VERSION or revert.get("blocked") is not False or revert.get("reverted"):
        problems.append("the revert check did not clear the candidate")
    return problems


def cmd_verify(args):
    sel, record = load_json(args.select), load_json(args.record)
    risk, revert = load_json(args.risk), load_json(args.revert)
    problems = verify(sel, record, risk, revert, args.candidate, args.stable_sha, now_from(args.now),
                      args.first_promotion, args.max_age_hours)
    for p in problems:
        print(f"verify: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"verify: ok, {args.candidate} may be promoted")
    return 0


# ------------------------------------------------------------ text outputs

def cut(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit("\n", 1)[0] + f"\n\n(cut at {limit} characters; the full file is a run artifact)\n"


def risk_headline(risk):
    if risk["needsApproval"]:
        return (f"**The manifest-risk diff has {risk['additionCount']} addition(s). "
                "Read every addition before you approve.**")
    return "The manifest-risk diff has no additions. Approving still moves `stable`."


def cmd_review(args):
    sel, record = load_json(args.select), load_json(args.record)
    risk, revert = load_json(args.risk), load_json(args.revert)
    scan = record.get("scan", {})
    counts = scan.get("counts", {})
    lines = ["# Review before you approve", "", f"- candidate: `{args.candidate}`",
             f"- stable now: `{sel['stableSha']}`", f"- mode: {sel['mode']}"]
    if sel["mode"] == "fast-path":
        lines.append(f"- fast path reason: {escape_text(sel['fastPathReason'])}")
        if sel["aggregateApproval"]:
            lines.append(f"- **{len(sel['youngerCommits'])} other commit(s) are younger than "
                         f"{sel['soakDays']} days. This approval covers the aggregate diff of all of them.**")
    lines += [f"- security gate: {scan.get('verdict')}, {counts.get('blocking')} blocking, "
              f"{counts.get('known')} known, {counts.get('ignored')} ignored, {counts.get('kev')} on the KEV list",
              f"- revert check: {'blocked' if revert.get('blocked') else 'clear'}", "",
              risk_headline(risk), ""]
    md = Path(args.risk_md).read_text(encoding="utf-8")
    print("\n".join(lines) + "\n" + cut(md, SUMMARY_LIMIT))
    return 0


def cmd_notes(args):
    sel, record = load_json(args.select), load_json(args.record)
    scan = record.get("scan", {})
    counts = scan.get("counts", {})
    lines = [f"Promotion of `{args.candidate}` to `stable`.", "",
             f"- mode: {sel['mode']}"]
    if sel["mode"] == "fast-path":
        lines.append(f"- fast path reason: {escape_text(sel['fastPathReason'])}")
    lines += [f"- images scanned: {scan.get('imagesScanned')} of {scan.get('imagesListed')}",
              f"- findings: {counts.get('blocking')} blocking, {counts.get('known')} known, "
              f"{counts.get('ignored')} ignored, {counts.get('kev')} on the KEV list",
              f"- scanner: {record['scanner']['name']} {record['scanner']['version']}, database "
              f"{record['scanner']['databaseUpdatedAt']}", "",
              "Verify the record:", "", "    gh attestation verify promotion-record.json "
              f"--repo {args.repo}", "",
              "Bootstrap Argo CD. In the download directory, verify the manifest, then apply it:", "",
              "    sha256sum -c argocd-bootstrap.yaml.sha256",
              "    kubectl apply --server-side --force-conflicts -f argocd-bootstrap.yaml", "",
              "## Manifest-risk diff", "",
              cut(Path(args.risk_md).read_text(encoding="utf-8"), NOTES_LIMIT)]
    print("\n".join(lines))
    return 0


def next_tag(today, existing):
    base = f"stable-{today:%Y%m%d}"
    taken = set(existing)
    for name in [base] + [f"{base}-{n}" for n in range(2, 10)]:
        if name not in taken:
            return name
    sys.exit(f"{base} and its suffixes -2 to -9 are all taken")


def cmd_tag_name(args):
    names = {m.group(1) for line in sys.stdin
             if (m := re.search(r"refs/tags/(stable-\d{8}(?:-\d+)?)$", line.strip()))}
    tag = next_tag(now_from(args.now), names)
    set_output(tag=tag)
    print(tag)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("select")
    s.add_argument("--repo-root", default=".")
    s.add_argument("--head", help="main HEAD at the time of the run")
    s.add_argument("--repo")
    s.add_argument("--branch", default="main")
    s.add_argument("--stable-ref", default="origin/stable")
    s.add_argument("--fast-path-reason", default="")
    s.add_argument("--commits-file", help="tests: a JSON file in place of git and gh")
    s.add_argument("--limit", type=int, default=MAX_CANDIDATES)
    s.add_argument("--now")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_select)

    b = sub.add_parser("baseline")
    b.add_argument("--releases", required=True)
    b.add_argument("--first-promotion", action="store_true")
    b.add_argument("--stable-sha", help="needed with --first-promotion")
    b.add_argument("--tags", help="git ls-remote output for refs/tags/stable-*; needed with --first-promotion")
    b.set_defaults(fn=cmd_baseline)

    c = sub.add_parser("check-baseline")
    c.add_argument("--record", required=True)
    c.add_argument("--stable-sha", required=True)
    c.set_defaults(fn=cmd_check_baseline)

    d = sub.add_parser("deps")
    d.add_argument("--rendered", required=True)
    d.add_argument("--repo-root", default=".")
    d.add_argument("--out", required=True)
    d.set_defaults(fn=cmd_deps)

    r = sub.add_parser("revert-check")
    for name in ("candidate", "head", "stable"):
        r.add_argument(f"--{name}", required=True)
    r.add_argument("--out", required=True)
    r.set_defaults(fn=cmd_revert_check)

    ch = sub.add_parser("choose", help="reads the needs context from the environment variable NEEDS_JSON")
    ch.set_defaults(fn=cmd_choose)

    dg = sub.add_parser("digest")
    dg.add_argument("--path", required=True)
    dg.set_defaults(fn=cmd_digest)

    cd = sub.add_parser("check-digest")
    cd.add_argument("--path", required=True)
    cd.add_argument("--expected", required=True)
    cd.set_defaults(fn=cmd_check_digest)

    rv = sub.add_parser("review")
    for name in ("select", "record", "risk", "risk-md", "revert", "candidate"):
        rv.add_argument(f"--{name}", required=True)
    rv.set_defaults(fn=cmd_review)

    v = sub.add_parser("verify")
    for name in ("select", "record", "risk", "revert", "candidate", "stable-sha"):
        v.add_argument(f"--{name}", required=True)
    v.add_argument("--first-promotion", action="store_true")
    v.add_argument("--max-age-hours", type=int, default=MAX_RECORD_AGE_HOURS)
    v.add_argument("--now")
    v.set_defaults(fn=cmd_verify)

    t = sub.add_parser("tag-name")
    t.add_argument("--now")
    t.set_defaults(fn=cmd_tag_name)

    n = sub.add_parser("notes")
    for name in ("select", "record", "risk-md", "candidate", "tag", "repo"):
        n.add_argument(f"--{name}", required=True)
    n.set_defaults(fn=cmd_notes)

    args = p.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
