#!/usr/bin/env python3
"""The daily watch of `stable`: fetch its record, rescan it, look for drift, keep the issues.

A script is needed because no existing tool does the joining. The GitHub CLI
gives the facts (the release, the attestation, issues), Trivy finds
vulnerabilities, and `docker buildx imagetools` and `helm pull` resolve
digests, but nothing compares the digests with the promotion record, tells a
complete scan from a partial one, measures how far `stable` is behind `main`,
and keeps exactly one open issue per condition that opens, updates and closes
itself. The script runs those tools and does only the joining and the
decision. It reuses the gate (ci/security_gate.py) for the scan decision and
the record builder (ci/promotion_record.py) for the digest lookups.

    ci/stable_watch.py fetch   --repo OWNER/NAME --out-dir out/stable [--stable-ref origin/stable]
    ci/stable_watch.py resolve --record R --out resolved.json
    ci/stable_watch.py lag     --repo OWNER/NAME --head SHA --out lag.json [--repo-root .]
    ci/stable_watch.py report  --fetch F --record R --scan S --kev K --resolved D --lag L \
                               --ignore ci/security-gate.trivyignore --out state.json [--summary S.md]
    ci/stable_watch.py sync    --state state.json --repo OWNER/NAME
    ci/stable_watch.py watchdog --repo OWNER/NAME

The steps run in separate jobs, so a job holds only what it needs:
  fetch    gets the record of the latest published `stable-YYYYMMDD` release and
           verifies its attestation, with the same gh command as ci promote.yaml.
           Status none (no release yet), ok, or failed.
  resolve  asks the registries for every image and chart digest of the record.
           It uses only the standard library, because it runs on the runner
           host, where docker buildx is. A registry error is written to the
           result and is never a missing difference.
  lag      measures how old the oldest commit of `main` is that `stable` lacks.
  report   (no network, no write) decides, from the files above, which
           conditions are active, clear or unknown, and writes the issue texts.
  sync     (the only step that writes) opens, updates and closes the issues.

Conditions, each with one issue that carries a hidden marker in its first line:
  rolling     "Known vulnerabilities in stable". Always updated in place, never
              closed and never duplicated.
  drift       an image or chart digest differs from the record.
  kev         a finding on the CISA Known Exploited Vulnerabilities list.
  stale       `stable` is more than 21 days behind `main`.
  incomplete  the check could not finish, or the scan is not trustworthy.
A condition is `active`, `clear` or `unknown`. Unknown means the check could not
run (a registry outage, a failed scan). An unknown condition never closes its
issue and never reports clean; it makes the incomplete issue active.

The scan follows the gate's fail-closed rules because it calls the gate's
decide() with no baseline: a stale database, an unreadable KEV file, an image
without a result, an image Trivy read nothing in, and an invalid ignore entry
all make the scan incomplete. Only a KEV finding is a priority finding. The
other findings go to the rolling issue.

Text from outside the repository (finding descriptions, registry errors) goes
into an issue only after it is cut to a limit and escaped (cap and safe below,
the style of clean() in ci/manifest_risk.py). Issue titles are fixed strings.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from promote import (escape_text, is_ancestor, landed_at, parse_time, pick_baseline_tag,  # noqa: E402
                     run as promote_run, set_output)

STALE_DAYS = 21
ROW_LIMIT = 40
NOT_SCANNED_LIMIT = 20
BODY_LIMIT = 60_000
FIELD_LIMIT = 120
ERROR_LIMIT = 300
ATTEST_ISSUER = "https://token.actions.githubusercontent.com"
SIGNER_WORKFLOW = ".github/workflows/promote.yaml"
LABEL = "stable-watch"
PRIORITY_LABEL = "priority"
LABELS = {LABEL: ("0e8a16", "Opened and updated by the stable-watch workflow"),
          PRIORITY_LABEL: ("b60205", "Needs the owner's attention")}
BOT_LOGINS = {"github-actions", "app/github-actions", "github-actions[bot]"}
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")

# kind: (title, priority). The titles are fixed text.
KINDS = {
    "rolling": ("Known vulnerabilities in stable", False),
    "drift": ("Priority: an upstream tag or chart changed after review", True),
    "kev": ("Priority: a known exploited vulnerability in stable", True),
    "stale": (f"Priority: stable is more than {STALE_DAYS} days behind main", True),
    "incomplete": ("Priority: the daily check of stable is incomplete", True),
}


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_from(arg):
    return parse_time(arg) if arg else datetime.now(timezone.utc)


def marker(kind):
    return f"<!-- stable-watch:{kind} -->"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def optional(path):
    """(data, None), or (None, why it is missing). A path that is None or absent
    is a missing result, which the report treats as incomplete, never as clean."""
    if not path:
        return None, "not given"
    try:
        return load_json(path), None
    except (OSError, ValueError) as e:
        return None, f"cannot read {Path(path).name}: {e}"


# ---------------------------------------------------------------- sanitising

def cap(text, limit):
    """Text cut to limit, with a hash of the whole text if it was cut, so two
    long values that differ stay distinct. Control characters become spaces."""
    whole = str(text)
    text = re.sub(r"[\x00-\x1f\x7f   ]+", " ", whole)
    if len(text) > limit:
        text = f"{text[:limit]}...[{hashlib.sha256(whole.encode()).hexdigest()[:8]}]"
    return text


def safe(text, limit=FIELD_LIMIT):
    """Text from outside the repository, safe in a Markdown table cell, in HTML
    and as a mention. A bare URL is broken so GitHub does not link it."""
    text = cap(text, limit).replace("://", ":\u200b//")
    text = re.sub(r"(?i)\bwww\.", lambda m: m.group(0)[:3] + "\u200b.", text)
    return escape_text(text)


def table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    return lines + ["| " + " | ".join(r) + " |" for r in rows]


# --------------------------------------------------------------------- fetch

def gh(*args):
    res = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8")
    if res.returncode != 0:
        tail = " | ".join(res.stderr.strip().splitlines()[-3:]) or f"gh {args[0]} exited {res.returncode}"
        raise RuntimeError(cap(tail, ERROR_LIMIT))
    return res.stdout


class Urgent(RuntimeError):
    """A fetch failure that is not an outage: the record failed verification or does not fit stable."""


def cmd_fetch(args):
    from promotion_record import validate_record
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    meta = {"status": "failed", "reason": "", "tag": "", "publishedAt": None}
    try:
        releases = json.loads(gh("release", "list", "--repo", args.repo, "--limit", "100",
                                 "--json", "tagName,isDraft,isPrerelease,publishedAt"))
        tag = pick_baseline_tag(releases)
        if not tag:
            meta.update(status="none", reason="stable has not been promoted yet: no stable-YYYYMMDD release exists")
        else:
            meta["tag"] = tag
            meta["publishedAt"] = next(r.get("publishedAt") for r in releases if r["tagName"] == tag)
            gh("release", "download", tag, "--repo", args.repo, "--pattern", "promotion-record.json",
               "--dir", str(out), "--clobber")
            path = out / "promotion-record.json"
            try:
                gh("attestation", "verify", str(path), "--repo", args.repo,
                   "--signer-workflow", f"{args.repo}/{SIGNER_WORKFLOW}", "--source-ref", "refs/heads/main",
                   "--cert-oidc-issuer", ATTEST_ISSUER)
            except RuntimeError as e:
                raise Urgent(f"the attestation did not verify: {e}") from e
            record = load_json(path)
            problems = validate_record(record)
            if problems:
                raise Urgent("the record does not match its schema: " + cap(problems[0], ERROR_LIMIT))
            stable = args.stable_sha or promote_run(
                ["git", "-C", args.repo_root, "rev-parse", "--verify", f"{args.stable_ref}^{{commit}}"]).stdout.strip()
            if record["commit"] != stable:
                raise Urgent(f"the record of {tag} is for {record['commit']}, but stable is {stable}. "
                                   "stable moved without a release")
            meta.update(status="ok", commit=record["commit"])
    except (RuntimeError, OSError, ValueError, StopIteration, SystemExit) as e:
        meta.update(status="failed", urgent=isinstance(e, Urgent),
                    reason=cap(e.code if isinstance(e, SystemExit) else e, ERROR_LIMIT))
        # A record that failed verification must not reach another job.
        (out / "promotion-record.json").unlink(missing_ok=True)
    write_json(out / "fetch.json", meta)
    set_output(status=meta["status"], tag=meta["tag"])
    if meta["status"] == "none":
        print(f"::notice::{meta['reason']}")
    elif meta["status"] == "failed":
        print(f"::warning::the record of stable could not be fetched or verified: {meta['reason']}")
    else:
        print(f"fetched and verified the record of {meta['tag']}")
    return 0


# ------------------------------------------------------------------- resolve

def resolve_all(record, lookup_image, lookup_chart, workers=4):
    """Ask the registries for every digest of the record. An error is kept in the
    entry. lookup_* take the entry and return a digest or raise RuntimeError."""
    def attempt(fn, entry):
        try:
            digest = fn(entry)
            note = None
            if isinstance(digest, tuple):
                digest, note = digest
            if not DIGEST.match(str(digest)):
                raise RuntimeError(f"unexpected digest {digest!r}")
            return {"digest": digest, "error": None, **({"note": note} if note else {})}
        except RuntimeError as e:
            return {"digest": None, "error": cap(e, ERROR_LIMIT)}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        images = [(e, pool.submit(attempt, lookup_image, e)) for e in record["images"]]
        charts = [(c, pool.submit(attempt, lookup_chart, c)) for c in record["charts"]]
        return {
            "images": [{"reference": e["reference"], **f.result()} for e, f in images],
            "charts": [{"name": c["name"], "version": c["version"], "repository": c["repository"], **f.result()}
                       for c, f in charts],
        }


def primary_digest(pr, ref):
    """The digest from the registry the reference names, and no other. The record
    builder falls back to mirrors for Docker Official Images; a mirror is not the
    registry the cluster pulls from, so here a failed primary lookup is an error."""
    out = pr.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}"])
    if not DIGEST.match(out):
        raise RuntimeError(f"unexpected digest output {out!r}")
    return out


def primary_chart_digest(pr, c):
    if c["repository"].startswith("oci://"):
        return primary_digest(pr, f"{c['repository'][6:].rstrip('/')}/{c['name']}:{c['version'].replace('+', '_')}")
    return pr.chart_digest(c["repository"], c["name"], c["version"])


def image_digest(pr, entry):
    """The digest from the registry the reference names. If that lookup errors and
    the image is a Docker Official Image, the mirrors of promotion_record.sources_of
    may confirm the digest of the record, and only that digest: a mirror that
    returns another digest, or errors too, leaves the image unresolved. A mirror
    answer cannot find a tag move while the primary registry is down."""
    ref = entry["reference"]
    try:
        return pr.retry(lambda: primary_digest(pr, ref), ref)
    except RuntimeError as primary_error:
        for source in pr.sources_of(ref)[1:]:
            try:
                digest = primary_digest(pr, source)
            except RuntimeError:
                continue
            host = source.split("/")[0]
            if digest != entry["digest"]:
                raise RuntimeError(f"the primary lookup failed ({primary_error}); {host} returned another "
                                   "digest than the record, which is not drift evidence") from None
            return digest, f"confirmed through {host}; the primary registry did not answer"
        raise


def cmd_resolve(args):
    import promotion_record as pr
    record = load_json(args.record)
    result = resolve_all(
        record,
        lambda e: image_digest(pr, e),
        lambda c: pr.retry(lambda: primary_chart_digest(pr, c), f"chart {c['name']} {c['version']}"))
    result["resolvedAt"] = iso(datetime.now(timezone.utc))
    write_json(args.out, result)
    failed = [x for x in result["images"] + result["charts"] if x["error"]]
    print(f"resolved {len(result['images'])} images and {len(result['charts'])} charts; {len(failed)} failed")
    return 0


# ----------------------------------------------------------------------- lag

def lag_of(repo_root, repo, head, stable_ref, now):
    """How far `stable` is behind `main`: the age of the oldest first-parent
    commit of main that stable lacks, measured from the time it landed (the
    merge time of its pull request; unknown if it has none)."""
    git = lambda *a: promote_run(["git", "-C", repo_root, *a]).stdout.strip()  # noqa: E731
    stable = git("rev-parse", "--verify", f"{stable_ref}^{{commit}}")
    result = {"stableSha": stable, "headSha": head, "state": "unknown", "days": None, "oldestCommit": None,
              "landedAt": None, "landedSource": None, "error": None}
    if head == stable or is_ancestor(repo_root, head, stable):
        return {**result, "state": "current", "days": 0.0}
    if not is_ancestor(repo_root, stable, head):
        return {**result, "error": "stable is not an ancestor of main: the histories diverged"}
    shas = git("rev-list", "--first-parent", f"{stable}..{head}").split()
    if not shas:
        return {**result, "error": "stable is behind main, but no commit is on the first-parent line"}
    oldest = shas[-1]
    # A commit with no merged pull request has an unknown landing time. The committer
    # date is chosen by the author, so it is not used (promote.landed_at does the same).
    landed, source = landed_at(repo, oldest, "main"), "pull request merge"
    if not landed:
        return {**result, "oldestCommit": oldest,
                "error": f"the oldest commit that stable lacks ({oldest}) has no merged pull request, so its age is unknown"}
    days = (now - parse_time(landed)).total_seconds() / 86400
    return {**result, "state": "behind", "days": round(days, 2), "oldestCommit": oldest,
            "landedAt": iso(parse_time(landed)), "landedSource": source}


def cmd_lag(args):
    try:
        result = lag_of(args.repo_root, args.repo, args.head, args.stable_ref, now_from(args.now))
    except (SystemExit, OSError, ValueError, KeyError) as e:
        result = {"state": "unknown", "days": None, "error": cap(e.code if isinstance(e, SystemExit) else e, ERROR_LIMIT)}
    write_json(args.out, result)
    print(f"lag: {result['state']}" + (f", {result['days']} days" if result.get("days") is not None else ""))
    return 0


# -------------------------------------------------------------------- report

def finding_row(f):
    return [safe(f["severity"]), safe(f["id"]), safe(f["image"]), safe(f["package"]),
            safe(f["installedVersion"] or "-"), safe(f["fixedVersion"] or "-")]


FINDING_HEADERS = ["Severity", "ID", "Image", "Package", "Installed", "Fixed in"]


def findings_section(title, rows, empty="None."):
    lines = ["", f"### {title}", ""]
    if not rows:
        return lines + [empty]
    lines += table(FINDING_HEADERS, [finding_row(f) for f in rows[:ROW_LIMIT]])
    if len(rows) > ROW_LIMIT:
        lines += ["", f"Showing {ROW_LIMIT} of {len(rows)}. The next scan lists the same findings in the same order."]
    return lines


def rank(f):
    return (not f["kev"], f["severity"] != "CRITICAL", f["image"], f["id"], f["package"])


def classify(record, new_record):
    """The findings of the rescan in the groups the issues need."""
    scan = new_record["scan"]
    old_keys = {(f["image"], f["id"], f["package"]) for f in (record.get("scan") or {}).get("findings", [])}
    live = sorted((f for f in scan["findings"] if f["status"] != "ignored"), key=rank)
    return {
        "kev": [f for f in live if f["kev"]],
        "fixable": [f for f in live if f["severity"] in ("HIGH", "CRITICAL") and f["fixedVersion"]],
        "unfixed": [f for f in live if f["severity"] in ("HIGH", "CRITICAL") and not f["fixedVersion"]],
        "new": [f for f in live if (f["image"], f["id"], f["package"]) not in old_keys],
        "ignored": [f for f in scan["findings"] if f["status"] == "ignored"],
    }


def mirror_lines(notes):
    if not notes:
        return []
    lines = ["", "### Confirmed through a mirror", "",
             "The primary registry did not answer for these images. A mirror returned the digest of the record, "
             "so they count as resolved. While the primary registry is down, a tag move cannot be found.", ""]
    lines += table(["Image", "Note"], [[safe(n), safe(t)] for n, t in notes[:ROW_LIMIT]])
    return lines


def rolling_body(ctx, groups, complete, now):
    record, meta = ctx["record"], ctx["fetch"]
    scan, scanner = ctx["scan"], ctx["scanner"]
    lines = [marker("rolling"),
             "The stable-watch workflow updates this issue once a day. It never opens a second one. Do not edit it by hand.",
             ""]
    if complete:
        lines.append("**Status: complete.**")
    else:
        lines.append(f"**Status: INCOMPLETE. Do not read the lists below as clean.** The reasons are in the issue "
                     f"\"{KINDS['incomplete'][0]}\" and in the run log. That issue opens after the second incomplete run in a row.")
    lines += [""] + table(["", ""], [
        ["Release", f"`{safe(meta['tag'])}`, published {safe(meta.get('publishedAt') or 'unknown')}"],
        ["stable commit", f"`{safe(record['commit'])}`"],
        ["Record scanned", safe((record.get("scan") or {}).get("scannedAt") or "unknown")],
        ["Rescan", iso(now)],
        ["Scanner", f"{safe(scanner.get('name') or 'unknown')} {safe(scanner.get('version') or '')}, "
                    f"database updated {safe(scanner.get('databaseUpdatedAt') or 'unknown')}"],
        ["Images scanned", f"{scan['imagesScanned']} of {scan['imagesListed']}"],
        ["Findings", f"{len(groups['fixable'])} HIGH or CRITICAL with a fix, {len(groups['unfixed'])} without a fix, "
                     f"{len(groups['kev'])} on the KEV list, {len(groups['ignored'])} ignored. "
                     f"{scan['counts']['otherSeverities']} lower-severity findings are not listed."],
        ["New since the record", str(len(groups["new"]))],
    ])
    lines += findings_section("New since the record", groups["new"], "No new finding since the record was scanned.")
    lines += findings_section("On the CISA KEV list", groups["kev"])
    lines += findings_section("HIGH or CRITICAL with a fix", groups["fixable"])
    lines += findings_section("HIGH or CRITICAL without a fix", groups["unfixed"])
    lines += mirror_lines(ctx.get("mirror", []))
    unscanned = record.get("notScanned", [])
    if unscanned:
        lines += ["", "### Not scanned", ""]
        lines += table(["Type", "Name"], [[safe(n["type"]), safe(n["name"])] for n in unscanned[:NOT_SCANNED_LIMIT]])
        if len(unscanned) > NOT_SCANNED_LIMIT:
            lines += ["", f"Showing {NOT_SCANNED_LIMIT} of {len(unscanned)}."]
    return lines


def drift_changes(record, resolved):
    """(changes, unresolved, missing) of the record against the registries.
    changes: [(kind, name, recorded, now)]. unresolved: [(name, error)]."""
    changes, unresolved = [], []
    by_ref = {x["reference"]: x for x in resolved.get("images", [])}
    for e in record["images"]:
        got = by_ref.get(e["reference"])
        if got is None:
            unresolved.append((e["reference"], "no lookup result"))
        elif got["error"]:
            unresolved.append((e["reference"], got["error"]))
        elif got["digest"] != e["digest"]:
            changes.append(("image", e["reference"], e["digest"], got["digest"]))
    by_chart = {(x["repository"], x["name"], x["version"]): x for x in resolved.get("charts", [])}
    for c in record["charts"]:
        name = f"{c['name']} {c['version']} ({c['repository']})"
        got = by_chart.get((c["repository"], c["name"], c["version"]))
        if got is None:
            unresolved.append((name, "no lookup result"))
        elif got["error"]:
            unresolved.append((name, got["error"]))
        elif got["digest"] != c["digest"]:
            changes.append(("chart", name, c["digest"], got["digest"]))
    return changes, unresolved


def evaluate(fetch, record, scan_data, scan_error, kev, resolved, resolved_error, lag, lag_error, ignore_path, now):
    """The state of every condition. Nothing here touches the network."""
    from security_gate import decide, load_ignore
    conditions, problems = {}, []

    def set_condition(kind, state, body=None, clear_note=""):
        conditions[kind] = {"state": state, "title": KINDS[kind][0], "body": body, "clearNote": clear_note}

    # ---- stale: needs no record
    if lag is None or lag.get("state") == "unknown" or lag.get("error"):
        problems.append("the age of stable against main is unknown: " + cap((lag or {}).get("error") or lag_error or "no result", ERROR_LIMIT))
        set_condition("stale", "unknown")
    elif lag["state"] == "behind" and lag["days"] > STALE_DAYS:
        tag = fetch.get("tag") or "unknown"
        body = [marker("stale"),
                f"`stable` is {lag['days']:.1f} days behind `main`. The limit is {STALE_DAYS} days.", "",
                f"- stable: `{safe(lag['stableSha'])}`, last release `{safe(tag)}`, published {safe(fetch.get('publishedAt') or 'unknown')}",
                f"- main: `{safe(lag['headSha'])}`",
                f"- oldest commit of main that stable lacks: `{safe(lag['oldestCommit'])}`, landed {safe(lag['landedAt'])} "
                f"({safe(lag['landedSource'])})", "",
                "A promotion that works resets this. Steps:", "",
                "1. Open the latest runs of the Promote workflow and read why none passed.",
                "2. Fix the cause, or start a Promote run by hand.",
                "3. After a promotion, this issue closes by itself on the next daily run."]
        set_condition("stale", "active", body)
    else:
        set_condition("stale", "clear", clear_note=f"`stable` is no longer more than {STALE_DAYS} days behind `main` "
                      f"({lag['days']:.1f} days).")

    if fetch.get("status") != "ok":
        reason = fetch.get("reason") or "no result"
        problems.append("the record of stable could not be fetched or verified: " + cap(reason, ERROR_LIMIT))
        for kind in ("rolling", "drift", "kev"):
            set_condition(kind, "unknown")
        return finish(conditions, problems, now, fetch.get("urgent"))

    ctx = {"record": record, "fetch": fetch,
           "mirror": [(i["reference"], i["note"]) for i in (resolved or {}).get("images", []) if i.get("note")]}

    # ---- scan: the gate's decision with no baseline
    groups = None
    if scan_data is None:
        problems.append("the scan produced no result: " + cap(scan_error or "no file", ERROR_LIMIT))
        scan_ok = False
    else:
        ignored, exempt, ignore_problems = load_ignore(ignore_path, now.date())
        new_record, reasons = decide(record, scan_data, kev, ignored, ignore_problems, None, now, exempt)
        groups = classify(record, new_record)
        kev_reasons = {f"{f['id']} in {f['image']} is on the CISA KEV list" for f in new_record["scan"]["findings"]
                       if f["status"] == "blocking"}
        incomplete = [r for r in reasons if r not in kev_reasons]
        problems += [cap(r, ERROR_LIMIT) for r in incomplete]
        scan_ok = not incomplete
        ctx.update(scan=new_record["scan"], scanner=new_record["scanner"])
    if "scan" not in record:
        problems.append("the record has no scan summary, so no finding can be called new")
        scan_ok = False

    # ---- kev
    if groups and groups["kev"]:
        body = [marker("kev"), "The daily rescan found a vulnerability on the CISA Known Exploited Vulnerabilities list "
                "in the image set of `stable`.", ""]
        body += findings_section("Findings", groups["kev"])[2:]
        body += ["", "Steps:", "",
                 "1. Read the advisory of each ID and decide if the image is exposed.",
                 "2. If a fixed image exists, update the image in `main` and promote it.",
                 "3. If you accept the risk, add an entry with a reason and an expiry date to `ci/security-gate.trivyignore`."]
        set_condition("kev", "active", body)
    elif scan_ok:
        set_condition("kev", "clear", clear_note="The rescan finds no vulnerability on the KEV list.")
    else:
        set_condition("kev", "unknown")

    # ---- rolling
    if groups:
        body = rolling_body(ctx, groups, scan_ok, now)
        set_condition("rolling", "active", body)
    else:
        set_condition("rolling", "unknown")

    # ---- drift
    if resolved is None:
        problems.append("the digests were not re-resolved: " + cap(resolved_error or "no file", ERROR_LIMIT))
        set_condition("drift", "unknown")
    else:
        changes, unresolved = drift_changes(record, resolved)
        if unresolved:
            problems.append(f"{len(unresolved)} digest(s) could not be resolved, so drift is not ruled out: "
                            + "; ".join(f"{cap(n, 80)} ({cap(e, 120)})" for n, e in unresolved[:5])
                            + (f"; and {len(unresolved) - 5} more" if len(unresolved) > 5 else ""))
        if changes:
            body = [marker("drift"),
                    f"An upstream tag or chart changed after review. The registries serve {len(changes)} digest(s) "
                    f"that differ from the promotion record of release `{safe(fetch['tag'])}`.", ""]
            body += table(["Kind", "Name", "In the record", "Now"],
                          [[c[0], safe(c[1]), f"`{safe(c[2])}`", f"`{safe(c[3])}`"] for c in changes[:ROW_LIMIT]])
            if len(changes) > ROW_LIMIT:
                body += ["", f"Showing {ROW_LIMIT} of {len(changes)}."]
            if unresolved:
                body += ["", f"{len(unresolved)} more digest(s) could not be resolved today. See the issue "
                         f"\"{KINDS['incomplete'][0]}\"."]
            body += mirror_lines(ctx["mirror"])
            body += ["", "An image written with its digest (`digestSource: pinned`) cannot change by tag. The record "
                     "holds the digest the registry served for it.", "",
                     "Steps:", "",
                     "1. Find what changed upstream: the release notes, the tag history and the chart diff.",
                     "2. If the change is not expected, treat it as a possible supply-chain attack. Do not promote until you know the cause.",
                     "3. If the change is expected, the next promotion records the new digest and this issue closes by itself."]
            set_condition("drift", "active", body)
        elif unresolved:
            set_condition("drift", "unknown")
        else:
            set_condition("drift", "clear", clear_note="Every image and chart digest matches the promotion record again.")

    return finish(conditions, problems, now)


def finish(conditions, problems, now, urgent=False):
    if problems:
        body = [marker("incomplete"),
                "The daily check of `stable` could not finish, or a result cannot be trusted. A result that is missing is "
                "never reported as clean. Until this clears, a condition that needs the missing result stays as it was.", "",
                "Reasons:", ""]
        body += [f"- {safe(p, ERROR_LIMIT + 100)}" for p in problems[:30]]
        if len(problems) > 30:
            body.append(f"- and {len(problems) - 30} more")
        body += ["", "Steps:", "",
                 "1. Read the run log of the Stable watch workflow.",
                 "2. If the cause is an outage, wait. The next daily run verifies again.",
                 "3. If the cause is a stale scanner database, an expired ignore entry or a failed scan, fix it and start the workflow by hand."]
        conditions["incomplete"] = {"state": "active", "title": KINDS["incomplete"][0], "body": body, "clearNote": ""}
    else:
        conditions["incomplete"] = {"state": "clear", "title": KINDS["incomplete"][0], "body": None,
                                    "clearNote": "Every part of the daily check finished and its results can be trusted."}
    conditions["incomplete"]["immediate"] = bool(urgent)
    priority = sorted(k for k, c in conditions.items() if KINDS[k][1] and c["state"] == "active")
    return {"generatedAt": iso(now), "conditions": conditions, "problems": problems, "priority": priority}


def summary_of(state):
    lines = ["## Stable watch", ""]
    for kind, (title, _) in KINDS.items():
        c = state["conditions"].get(kind)
        if c:
            lines.append(f"- {title}: **{c['state']}**")
    if state["problems"]:
        lines += ["", "Incomplete:"] + [f"- {safe(p, ERROR_LIMIT + 100)}" for p in state["problems"][:30]]
    return "\n".join(lines) + "\n"


def cmd_report(args):
    now = now_from(args.now)
    fetch, fetch_error = optional(args.fetch)
    if fetch is None:
        fetch = {"status": "failed", "reason": fetch_error, "tag": "", "publishedAt": None}
    if fetch["status"] == "none":
        state = {"generatedAt": iso(now), "conditions": {}, "problems": [], "priority": [], "note": fetch["reason"]}
    else:
        record = load_json(args.record) if fetch["status"] == "ok" else None
        scan_data, scan_error = optional(args.scan)
        kev, _ = optional(args.kev)
        resolved, resolved_error = optional(args.resolved)
        lag, lag_error = optional(args.lag)
        state = evaluate(fetch, record, scan_data, scan_error, kev, resolved, resolved_error, lag, lag_error,
                         args.ignore, now)
    write_json(args.out, state)
    text = summary_of(state) if state["conditions"] else f"## Stable watch\n\n{state['note']}\n"
    if args.summary:
        Path(args.summary).write_text(text, encoding="utf-8")
    print(text)
    return 0


# ---------------------------------------------------------------------- sync

def stable_part(body):
    """The body without its time stamp line, to tell a real change from a new day."""
    return "\n".join(l for l in (body or "").splitlines() if not l.startswith("Last checked:")).strip()


def with_stamp(lines, now):
    text = "\n".join(lines) + f"\n\nLast checked: {iso(now)}\n"
    if len(text) > BODY_LIMIT:
        text = text[:BODY_LIMIT] + "\n\n[cut: the issue body limit]\n"
    return text


class Tracker:
    """The issue operations, through gh. A failure is kept, and the rest still runs."""

    def __init__(self, repo):
        self.repo, self.errors, self.done = repo, [], []

    def call(self, *args, text=None):
        with tempfile.TemporaryDirectory() as tmp:
            call = list(args)
            if text is not None:
                path = Path(tmp, "body.md")
                path.write_text(text, encoding="utf-8")
                call += ["--body-file", str(path)]
            try:
                return gh(*call, "--repo", self.repo)
            except RuntimeError as e:
                self.errors.append(f"gh {' '.join(args[:2])}: {e}")
                return None

    def ensure_labels(self):
        for name, (color, description) in LABELS.items():
            if self.call("label", "create", name, "--color", color, "--description", description, "--force") is None:
                return False
        return True

    def existing(self):
        out = self.call("issue", "list", "--search", "stable in:title", "--state", "all", "--limit", "1000",
                        "--json", "number,title,state,body,author")
        if out is None:
            return None
        found = {kind: [] for kind in KINDS}
        for issue in json.loads(out):
            login = (issue.get("author") or {}).get("login", "")
            for kind, (title, _) in KINDS.items():
                # Author and exact title decide. The marker in the body is information only: a
                # hand-edited body must not make the next run open a second issue.
                if login in BOT_LOGINS and issue["title"] == title:
                    found[kind].append(issue)
        for issues in found.values():
            issues.sort(key=lambda i: i["number"])
        return found

    def create(self, kind, text):
        labels = [LABEL] + ([PRIORITY_LABEL] if KINDS[kind][1] else [])
        args = ["issue", "create", "--title", KINDS[kind][0]]
        for label in labels:
            args += ["--label", label]
        if self.call(*args, text=text) is not None:
            self.done.append(f"opened {kind}")

    def update(self, kind, number, text, comment=None):
        if self.call("issue", "edit", str(number), text=text) is not None:
            self.done.append(f"updated {kind} #{number}")
            if comment:
                self.call("issue", "comment", str(number), text=comment)

    def close(self, kind, number, comment):
        if self.call("issue", "comment", str(number), text=comment) is not None:
            if self.call("issue", "close", str(number), "--reason", "completed") is not None:
                self.done.append(f"closed {kind} #{number}")

    def reopen(self, kind, number, comment):
        if self.call("issue", "reopen", str(number)) is not None:
            self.done.append(f"reopened {kind} #{number}")
            self.call("issue", "comment", str(number), text=comment)


STREAK = re.compile(r"<!-- stable-watch:streak=(\d+) -->")
STREAK_TO_OPEN = 2


def streak_line(n):
    return f"<!-- stable-watch:streak={n} -->"


def streak_of(issue):
    m = STREAK.search((issue or {}).get("body") or "")
    return int(m[1]) if m else 0


def with_streak(lines, n):
    """The issue lines with the streak marker as the second line."""
    return [lines[0], streak_line(n)] + [l for l in lines[1:] if not STREAK.fullmatch(l)]


def sync(state, tracker, now):
    if not state["conditions"]:
        return
    if not tracker.ensure_labels():
        return
    found = tracker.existing()
    if found is None:
        return
    # The incomplete issue opens after STREAK_TO_OPEN incomplete runs in a row, or at
    # once for an urgent cause. The count lives in the rolling issue, which exists to
    # carry state between runs. An unknown result never closes anything.
    rolling_issues = found["rolling"]
    rolling_issue = ([i for i in rolling_issues if i["state"] == "OPEN"] or rolling_issues[-1:] or [None])[0]
    incomplete = state["conditions"]["incomplete"]
    streak = streak_of(rolling_issue) + 1 if incomplete["state"] == "active" else 0
    if incomplete["state"] == "active" and streak < STREAK_TO_OPEN and not incomplete.get("immediate"):
        incomplete["state"] = "unknown"
    rolling = state["conditions"].get("rolling")
    if rolling and rolling["state"] == "active":
        rolling["body"] = with_streak(rolling["body"], streak)
    elif rolling_issue is None and streak:
        rolling.update(state="active", body=[marker("rolling"), streak_line(streak),
                       "No complete scan has run yet. The reasons are in the run log of the Stable watch workflow."])
    elif rolling_issue is not None and streak != streak_of(rolling_issue):
        body = STREAK.sub(streak_line(streak), rolling_issue["body"]) if STREAK.search(rolling_issue["body"]) \
            else "\n".join(with_streak(rolling_issue["body"].splitlines(), streak))
        tracker.update("rolling", rolling_issue["number"], body)
    for kind, cond in state["conditions"].items():
        issues = found[kind]
        open_ones = [i for i in issues if i["state"] == "OPEN"]
        if cond["state"] == "unknown":
            continue
        if cond["state"] == "clear":
            for issue in open_ones:
                tracker.close(kind, issue["number"], f"Cleared on {iso(now)}. {cond['clearNote']}")
            continue
        text = with_stamp(cond["body"], now)
        if kind == "rolling":
            target = (open_ones or issues[-1:] or [None])[0]
            if target is None:
                tracker.create(kind, text)
                continue
            if target["state"] != "OPEN":
                tracker.reopen(kind, target["number"], "The rolling issue was closed. It is open again.")
            tracker.update(kind, target["number"], text)
            continue
        if not open_ones:
            tracker.create(kind, text)
            continue
        first, extra = open_ones[0], open_ones[1:]
        if stable_part(first["body"]) != stable_part(text):
            tracker.update(kind, first["number"], text, comment=f"The details changed on {iso(now)}. See the issue text.")
        for issue in extra:
            tracker.close(kind, issue["number"], f"Closed as a duplicate of #{first['number']}.")


def cmd_watchdog(args):
    """Fail when the newest run of the Stable watch workflow is older than --max-days.
    It runs from a workflow that a quiet repository cannot disable. It skips, with a
    notice, when stable has no release yet, the same rule as the watch itself."""
    now = now_from(args.now)
    try:
        releases = json.loads(gh("release", "list", "--repo", args.repo, "--limit", "100",
                                 "--json", "tagName,isDraft,isPrerelease,publishedAt"))
        if not pick_baseline_tag(releases):
            print("::notice::stable has not been promoted yet, so the Stable watch is not expected to run")
            return 0
        runs = json.loads(gh("run", "list", "--repo", args.repo, "--workflow", args.workflow, "--limit", "5",
                             "--json", "createdAt,status,conclusion,event"))
    except (RuntimeError, ValueError) as e:
        print(f"::error::the watchdog could not read the runs: {e}", file=sys.stderr)
        return 1
    newest = max((parse_time(r["createdAt"]) for r in runs), default=None)
    if newest is None or now - newest > timedelta(days=args.max_days):
        seen = iso(newest) if newest else "never"
        print(f"::error::the Stable watch has not run for more than {args.max_days} days (last run: {seen}). "
              "GitHub may have disabled the schedule. Enable the workflow and start it by hand.", file=sys.stderr)
        return 1
    print(f"the newest Stable watch run is from {iso(newest)}")
    return 0


def cmd_sync(args):
    state = load_json(args.state)
    tracker = Tracker(args.repo)
    sync(state, tracker, now_from(args.now))
    for line in tracker.done:
        print(line)
    for line in tracker.errors:
        print(f"::error::{line}", file=sys.stderr)
    if tracker.errors:
        return 1
    if state["priority"]:
        print("::error::priority condition(s) active: " + ", ".join(state["priority"]), file=sys.stderr)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--repo", required=True)
    f.add_argument("--out-dir", required=True)
    f.add_argument("--repo-root", default=".")
    f.add_argument("--stable-ref", default="origin/stable")
    f.add_argument("--stable-sha", help="for tests; default: git rev-parse of --stable-ref")
    r = sub.add_parser("resolve")
    r.add_argument("--record", required=True)
    r.add_argument("--out", required=True)
    g = sub.add_parser("lag")
    g.add_argument("--repo", required=True)
    g.add_argument("--head", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--repo-root", default=".")
    g.add_argument("--stable-ref", default="origin/stable")
    g.add_argument("--now", help="ISO time, for tests")
    p = sub.add_parser("report")
    for name in ("fetch", "record", "scan", "kev", "resolved", "lag"):
        p.add_argument(f"--{name}")
    p.add_argument("--ignore", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--summary")
    p.add_argument("--now", help="ISO time, for tests")
    w = sub.add_parser("watchdog")
    w.add_argument("--repo", required=True)
    w.add_argument("--workflow", default="stable-watch.yaml")
    w.add_argument("--max-days", type=float, default=2)
    w.add_argument("--now", help="ISO time, for tests")
    s = sub.add_parser("sync")
    s.add_argument("--state", required=True)
    s.add_argument("--repo", required=True)
    s.add_argument("--now", help="ISO time, for tests")
    args = ap.parse_args()
    sys.exit({"fetch": cmd_fetch, "resolve": cmd_resolve, "lag": cmd_lag, "report": cmd_report,
              "sync": cmd_sync, "watchdog": cmd_watchdog}[args.cmd](args))


if __name__ == "__main__":
    main()
