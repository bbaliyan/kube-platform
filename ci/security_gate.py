#!/usr/bin/env python3
"""The delta security gate: scan the images of a promotion record and decide.

A script is needed because no existing tool does the decision. Trivy finds
vulnerabilities, but it cannot compare them with the images of the current
`stable` record, match them to the CISA Known Exploited Vulnerabilities list,
apply an ignore file with a required reason and expiry, or fail when the
database is old or an image was skipped. The script runs Trivy (from the pinned
kube-devenv image) and does only the joining and the decision.

    ci/security_gate.py scan   --record out/promotion-record.json --out out/scan-results.json
    ci/security_gate.py decide --record out/promotion-record.json --scan out/scan-results.json \
        --kev out/kev.json --ignore ci/security-gate.trivyignore \
        (--baseline stable-record.json | --no-baseline) \
        --out out/promotion-record.json --summary out/security-summary.md
    ci/security_gate.py check-ignore ci/security-gate.trivyignore

`scan` runs Trivy over every image of the record, by digest, and writes the raw
findings. `decide` reads them and writes the scanner fields and the scan summary
into the record. It exits 1 when it blocks.

Block when:
  new      An image whose digest is not in the baseline has a fixable HIGH or
           CRITICAL finding that the baseline does not list for the same
           repository, vulnerability and package.
  KEV      Any finding, of any severity, on the CISA Known Exploited
           Vulnerabilities list. Fixed or not, old or new, in a changed image or
           not.
Everything else is published as known. An image whose digest is in the baseline
never blocks except for a KEV finding, so a promotion that changes nothing is
not blocked by a vulnerability that was found later. The daily rescan reports
those.

Fail closed (block) when:
  - Trivy cannot report its version, its database is older than 48 hours, or the
    database time is in the future;
  - the database cannot be downloaded;
  - an image of the record has no scan result, or its scan failed;
  - Trivy detects nothing in an image (no results and no operating system), so
    an image it could not read never looks clean;
  - the KEV file is missing, unreadable, older than 21 days or dated in the future;
  - an ignore entry has a bad ID, no reason, no valid expiry date, an expiry
    more than 90 days away, or has expired;
  - the baseline is not a valid record, its verdict is not pass, or it did not
    scan every image it lists. The baseline must be named: --no-baseline is only
    for the first promotion, and the caller must choose it on purpose.

The ignore file has one entry per line, in the .trivyignore style:
    CVE-2026-0001 exp:2027-01-31 reason:no upstream fix, not reachable
An ignored finding stays in the record with the status "ignored". It does not
block. An entry can silence a KEV finding too.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from promotion_record import repository_of, validate_record  # noqa: E402

MAX_DATABASE_AGE = timedelta(hours=48)
MAX_KEV_AGE = timedelta(days=21)
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}
MAX_SUMMARY_ROWS = 40
EXPIRY = re.compile(r"(?:^|\s)exp:(\S+)")
REASON = re.compile(r"(?:^|\s)reason:(.*\S)")
VULN_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3})$")
MAX_IGNORE_DAYS = 90
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def parse_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def now_utc(text=None):
    return parse_time(text) if text else datetime.now(timezone.utc)


# ---------------------------------------------------------------- ignore file

def load_ignore(path, today):
    """({id: reason} of the valid entries, [problems]). An entry that is
    expired or incomplete is a problem and is not in the dict."""
    entries, problems = {}, []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        vuln_id, _, rest = line.strip().partition(" ")
        expiry, reason = EXPIRY.search(rest), REASON.search(rest)
        try:
            expires = date.fromisoformat(expiry[1]) if expiry else None
        except ValueError:
            expires = None
        bad = False
        if not VULN_ID.match(vuln_id):
            problems.append(f"{path}:{number}: {vuln_id} is not a CVE or GHSA id")
            bad = True
        if expires is None:
            problems.append(f"{path}:{number}: {vuln_id} has no valid exp:YYYY-MM-DD date")
            bad = True
        elif expires < today:
            problems.append(f"{path}:{number}: {vuln_id} expired on {expires}")
            bad = True
        elif (expires - today).days > MAX_IGNORE_DAYS:
            problems.append(f"{path}:{number}: {vuln_id} expires on {expires}, "
                            f"more than {MAX_IGNORE_DAYS} days from today")
            bad = True
        if not reason:
            problems.append(f"{path}:{number}: {vuln_id} has no reason:<text>")
            bad = True
        if not bad:
            entries[vuln_id] = reason[1]
    return entries, problems


# ------------------------------------------------------------------ scanning

def run(cmd, timeout):
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
    if res.returncode != 0:
        tail = " | ".join(res.stderr.strip().splitlines()[-3:]) or f"{cmd[0]} exited {res.returncode}"
        raise RuntimeError(tail)
    return res.stdout


def findings_of(report):
    """Findings of a Trivy JSON report, one per vulnerability and package. The
    same pair can appear in several targets (a binary and the package that
    ships it). The merged finding keeps a fix if any instance has one, and the
    highest severity, so a fixable instance is never hidden by an unfixable one."""
    if not isinstance(report, dict) or "SchemaVersion" not in report or "ArtifactName" not in report:
        raise RuntimeError("the output is not a Trivy report")
    if not report.get("Results") and not (report.get("Metadata") or {}).get("OS"):
        raise RuntimeError("no packages detected: Trivy found no results and no operating system")
    found = {}
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            new = {
                "id": v["VulnerabilityID"],
                "package": v["PkgName"],
                "installedVersion": v.get("InstalledVersion", ""),
                "fixedVersion": v.get("FixedVersion") or None,
                "severity": v.get("Severity", "UNKNOWN"),
            }
            old = found.setdefault((new["id"], new["package"]), new)
            if old is not new:
                old["fixedVersion"] = old["fixedVersion"] or new["fixedVersion"]
                if SEVERITY_RANK.get(new["severity"], 0) > SEVERITY_RANK.get(old["severity"], 0):
                    old["severity"] = new["severity"]
    return sorted(found.values(), key=lambda f: (f["id"], f["package"]))


def scan_image(entry, attempts):
    target = f"{repository_of(entry['reference'])}@{entry['digest']}"
    error = None
    for _ in range(attempts):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp, "report.json")
            try:
                run(["trivy", "image", "--skip-db-update", "--scanners", "vuln", "--image-src", "remote",
                     "--cache-backend", "memory", "--format", "json", "--output", str(out), target], 1200)
                return {"reference": entry["reference"], "digest": entry["digest"], "error": None,
                        "findings": findings_of(json.loads(out.read_text(encoding="utf-8")))}
            except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as e:
                error = str(e)
    return {"reference": entry["reference"], "digest": entry["digest"], "error": error, "findings": []}


def scanner_info():
    """Read after the scans, so the database exists. Anything missing is an error."""
    try:
        info = json.loads(run(["trivy", "version", "--format", "json"], 60))
        return {"name": "trivy", "version": info["Version"],
                "databaseUpdatedAt": info["VulnerabilityDB"]["UpdatedAt"]}, None
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as e:
        return None, f"cannot read the Trivy version and database time: {e}"


def scan(args):
    record = json.loads(Path(args.record).read_text(encoding="utf-8"))
    # One download before the workers, so they do not race for the database.
    try:
        run(["trivy", "image", "--download-db-only"], 900)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda e: scan_image(e, args.attempts), record["images"]))
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        results = [{"reference": i["reference"], "digest": i["digest"], "findings": [],
                    "error": f"the database download failed: {e}"} for i in record["images"]]
    scanner, scanner_error = scanner_info()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(
        {"scanner": scanner, "scannerError": scanner_error, "results": results}, indent=2) + "\n", encoding="utf-8")
    failed = [r for r in results if r["error"]]
    print(f"scanned {len(results) - len(failed)} of {len(results)} images; {len(failed)} failed")
    for r in failed:
        print(f"  {r['reference']}: {r['error']}", file=sys.stderr)


# ------------------------------------------------------------------ decision

def kev_ids(kev, now):
    """(set of CVE ids, problem or None)."""
    try:
        ids = {v["cveID"] for v in kev["vulnerabilities"]}
        released = parse_time(kev["dateReleased"])
    except (KeyError, TypeError, ValueError):
        return set(), "the KEV file is not a CISA catalog"
    if not ids:
        return set(), "the KEV file lists no vulnerabilities"
    if released - now > timedelta(days=1):
        return set(), f"the KEV file is dated in the future ({released:%Y-%m-%d})"
    if now - released > MAX_KEV_AGE:
        return set(), f"the KEV file is older than {MAX_KEV_AGE.days} days (released {released:%Y-%m-%d})"
    return ids, None


def baseline_problem(baseline):
    """Why a record cannot be the baseline, or None."""
    problems = validate_record(baseline)
    if problems:
        return "it does not match the schema (" + problems[0] + ")"
    scan = baseline.get("scan")
    if not scan:
        return "it has no scan summary"
    if scan["verdict"] != "pass":
        return "its verdict is not pass"
    if scan["imagesScanned"] != scan["imagesListed"] or scan["imagesListed"] != len(baseline["images"]):
        return "it did not scan every image it lists"
    return None


def decide(record, scan_data, kev, ignored, ignore_problems, baseline, now):
    """(new record, [reasons the run is blocked]). baseline is a record, or None
    for the first promotion."""
    reasons = list(ignore_problems)
    scanner = scan_data.get("scanner")
    if not scanner:
        reasons.append(scan_data.get("scannerError") or "the scanner version is unknown")
    else:
        try:
            age = now - parse_time(scanner["databaseUpdatedAt"])
        except (KeyError, TypeError, ValueError):
            age = None
            reasons.append("the Trivy database time is unreadable")
        if age is not None and age < timedelta(0):
            reasons.append("the Trivy database time is in the future")
        elif age is not None and age > MAX_DATABASE_AGE:
            reasons.append(f"the Trivy database is {age.total_seconds() / 3600:.0f} hours old "
                           f"(the limit is {MAX_DATABASE_AGE.total_seconds() / 3600:.0f})")
    kev_set, kev_problem = kev_ids(kev, now)
    if kev_problem:
        reasons.append(kev_problem)

    results = {r["digest"]: r for r in scan_data.get("results", [])}
    listed = {e["digest"]: e for e in record["images"]}
    for digest, entry in sorted(listed.items(), key=lambda kv: kv[1]["reference"]):
        r = results.get(digest)
        if r is None:
            reasons.append(f"no scan result for {entry['reference']}")
        elif r["error"]:
            reasons.append(f"scan failed for {entry['reference']}: {r['error']}")
    scanned = [d for d in listed if d in results and not results[d]["error"]]

    baseline_digests, baseline_keys = set(), set()
    if baseline is not None:
        problem = baseline_problem(baseline)
        if problem:
            reasons.append(f"the baseline is not usable: {problem}")
        else:
            # A passing baseline scanned every image it lists, so each digest has results.
            baseline_digests = {i["digest"] for i in baseline["images"]}
            baseline_keys = {(f["image"], f["id"], f["package"]) for f in baseline["scan"]["findings"]}

    findings, others = [], 0
    for digest in scanned:
        entry = listed[digest]
        image = repository_of(entry["reference"])
        for f in results[digest]["findings"]:
            kev_hit = f["id"] in kev_set
            if f["severity"] not in BLOCKING_SEVERITIES and not kev_hit:
                others += 1
                continue
            status = "known"
            if f["id"] in ignored:
                status = "ignored"
            elif kev_hit:
                status = "blocking"
                reasons.append(f"{f['id']} in {image} is on the CISA KEV list")
            elif (baseline is not None and f["fixedVersion"] and digest not in baseline_digests
                  and (image, f["id"], f["package"]) not in baseline_keys):
                status = "blocking"
                reasons.append(f"{f['id']} ({f['severity']}, fixed in {f['fixedVersion']}) "
                               f"is new in {image}: package {f['package']}")
            findings.append({"image": image, "id": f["id"], "package": f["package"],
                             "installedVersion": f["installedVersion"], "fixedVersion": f["fixedVersion"],
                             "severity": f["severity"], "kev": kev_hit, "status": status})
    findings.sort(key=lambda f: (f["image"], f["id"], f["package"]))

    count = lambda status: sum(f["status"] == status for f in findings)  # noqa: E731
    out = dict(record)
    out["scanner"] = scanner or {"name": None, "version": None, "databaseUpdatedAt": None}
    out["scan"] = {
        "scannedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": "block" if reasons else "pass",
        "baselineCommit": baseline.get("commit") if baseline else None,
        "imagesListed": len(listed),
        "imagesScanned": len(scanned),
        "counts": {"blocking": count("blocking"), "known": count("known"), "ignored": count("ignored"),
                   "kev": sum(f["kev"] for f in findings), "otherSeverities": others},
        "reasons": sorted(set(reasons)),
        "findings": findings,
    }
    return out, sorted(set(reasons))


def summary_of(record):
    scan, scanner = record["scan"], record["scanner"]
    c = scan["counts"]
    lines = [
        "## Security gate",
        "",
        f"Verdict: **{scan['verdict']}**. Scanner: {scanner['name']} {scanner['version']}, "
        f"database updated {scanner['databaseUpdatedAt']}.",
        f"Images scanned: {scan['imagesScanned']} of {scan['imagesListed']}. "
        f"Baseline: {scan['baselineCommit'] or 'none (first promotion)'}.",
        f"Findings: {c['blocking']} blocking, {c['known']} known, {c['ignored']} ignored, "
        f"{c['kev']} on the KEV list. {c['otherSeverities']} lower-severity findings are not listed.",
    ]
    if scan["reasons"]:
        lines += ["", "Why it blocks:", ""] + [f"- {r}" for r in scan["reasons"]]
    rows = [f for f in scan["findings"] if f["status"] != "ignored"]
    rows.sort(key=lambda f: (f["status"] != "blocking", f["severity"] != "CRITICAL"))
    if rows:
        lines += ["", "| Status | Severity | ID | Image | Package | Installed | Fixed in |", "|---|---|---|---|---|---|---|"]
        lines += [f"| {f['status']} | {f['severity']} | {f['id']} | {f['image']} | {f['package']} | "
                  f"{f['installedVersion']} | {f['fixedVersion'] or '-'} |" for f in rows[:MAX_SUMMARY_ROWS]]
        if len(rows) > MAX_SUMMARY_ROWS:
            lines += ["", f"Showing {MAX_SUMMARY_ROWS} of {len(rows)}. The record has the rest."]
    return "\n".join(lines) + "\n"


def run_decide(args):
    today = now_utc(args.now).date()
    record = json.loads(Path(args.record).read_text(encoding="utf-8"))
    baseline = None if args.no_baseline else json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    ignored, ignore_problems = load_ignore(args.ignore, today)
    try:
        kev = json.loads(Path(args.kev).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        kev = None
    new_record, reasons = decide(record, json.loads(Path(args.scan).read_text(encoding="utf-8")),
                                 kev, ignored, ignore_problems, baseline, now_utc(args.now))
    problems = validate_record(new_record)
    if problems:
        sys.exit("record does not match its schema:\n  " + "\n  ".join(problems))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(new_record, indent=2) + "\n", encoding="utf-8")
    text = summary_of(new_record)
    if args.summary:
        Path(args.summary).write_text(text, encoding="utf-8")
    print(text)
    if reasons:
        print(f"BLOCKED: {len(reasons)} reason(s)", file=sys.stderr)
        sys.exit(1)


def run_check_ignore(args):
    _, problems = load_ignore(args.file, now_utc(args.now).date())
    if problems:
        sys.exit("\n".join(problems))
    print("ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--record", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--attempts", type=int, default=2)
    d = sub.add_parser("decide")
    d.add_argument("--record", required=True)
    d.add_argument("--scan", required=True)
    d.add_argument("--kev", required=True)
    d.add_argument("--ignore", required=True)
    d.add_argument("--out", required=True)
    d.add_argument("--summary")
    d.add_argument("--now", help="ISO time, for tests")
    base = d.add_mutually_exclusive_group(required=True)
    base.add_argument("--baseline")
    base.add_argument("--no-baseline", action="store_true")
    c = sub.add_parser("check-ignore")
    c.add_argument("file")
    c.add_argument("--now", help="ISO time, for tests")
    args = ap.parse_args()
    {"scan": scan, "decide": run_decide, "check-ignore": run_check_ignore}[args.cmd](args)


if __name__ == "__main__":
    main()
