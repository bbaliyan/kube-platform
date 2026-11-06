# CI

## Entry points

Run these inside the kube-devenv image (`make test-integration` also needs
docker, kind, helm, kubectl and pyyaml).

- `make test-commit`: lint, secret scan, pipeline lint, render, schema check
  and commit-message check. No secrets, nothing privileged.
- `make test-integration`: the kind end-to-end run described below.
- `make hooks`: runs the fast subset (`make test-fast`) before each commit.

`.github/workflows/tiers.yaml` only sets up and calls these. It runs the
integration tier for PRs from this repo, not for fork PRs.

The `commit` and `integration` jobs gate a merge. They run at the same time,
so a PR waits for the slower one, not for both. The `diff` job runs beside
them, and `comment` runs after it. Neither gates:

- The `diff` job runs `make diff-comment`. It renders `main` and the branch, and
  writes the rendered diff to `out/comment.md` and to the job summary. It is not
  part of `make test-commit`. It uploads `out/` as the `rendered-manifests`
  artifact.
- The `comment` job posts that file as a PR comment. It is the only job with
  `pull-requests: write`. For a fork PR, read the diff in the `diff` job's summary.

A job rename changes the required check names. Update the ruleset in the same
change.

## Application finalizers

Every Application in `bootstrap/` and `platform/` must either carry the
`resources-finalizer.argocd.argoproj.io` finalizer or opt out. `make test-commit`
runs `ci/check-app-finalizers.sh` on the rendered output and fails if one does
neither, or both.

The finalizer makes Argo CD delete what an Application deployed when the
Application is deleted or pruned. Without it, the Application object goes and
its resources keep running, unowned.

An Application opts out when its removal would break the cluster or lose data:
the network, Argo CD, certificates and the CA, secrets, storage, ingress, DNS
records, the node upgrade controller, the CRDs consumers add objects to, and
the log and metric volumes. To opt out, set the annotation
`kube-stack/keep-resources-on-delete` to the reason, and set
`argocd.argoproj.io/sync-options: Prune=false,Delete=false`. Non-Application
resources that a cascade must not remove carry the same sync options.

An opt-out guards against `kubectl delete` and a prune. `argocd app delete` and
the Argo CD UI add the finalizer themselves and cascade by default. Use
`--cascade=false` with them on an opted-out Application.

An opt-out also changes what happens when a consumer turns a feature off, for
example `gpuOperatorEnabled`, a removed `storageProvisioners` entry, the cloud
controller manager or the CSI driver. Before, the root pruned the Application
and left its resources behind. Now the Application stays and keeps syncing, and
the root shows it as "requires pruning" until someone deletes it by hand. Use
`argocd app delete --cascade=false` if the resources must stay, or a cascading
delete if they must go.

## Promote workflow

`.github/workflows/promote.yaml` is the only way `stable` moves. It runs every
Sunday at 22:00 UTC and can be started by hand. `promote-candidate.yaml` is the
part that tests one candidate. `ci/promote.py` makes the decisions, and the
Makefile runs the checks. The workflow files only set up and call them.

### What a run does

1. **Select.** It takes the newest commits of `main` that landed at least
   7 days ago, at most three. If `stable` is already at or ahead of `main`, or
   no commit is old enough yet, the run ends with nothing to do. This is a green
   run.
2. **Test each candidate, newest first.** A candidate runs these jobs:
   `tests` (`make test-commit`), `integration` (the kind run, tried twice),
   `record`, `scan` (the security gate) and `risk` (the manifest-risk diff and
   the revert check). If any job fails, the workflow tries the next older
   candidate. The first candidate that passes every job wins. The summary of
   `choose` lists every candidate that was skipped and the jobs that failed.
3. **Choose and review.** The `choose` job picks the winner, repeats the final
   checks and writes the review text to its summary: the scan counts, the
   revert check and the manifest-risk diff.
4. **Promote.** The `promote` job waits for the owner. After the approval it
   repeats the checks, requires release immutability, pushes the tag, attests
   the record, creates a draft release, pushes the commit to `stable`, and
   publishes the release. If the job fails or is cancelled before the push, one
   step removes the draft release if it exists and another removes the tag if
   it exists. Neither removes anything once `stable` is at the candidate.

### The candidate rule

A commit has landed when its pull request merged. `ci/promote.py` reads the
merge time from the GitHub API, and only from a pull request whose merge commit
is that commit. It does not use the commit date, because the author of a push
that skips a pull request chooses that date. A commit with no such pull request
counts as landed now. This includes the commits of a rebase merge, so use merge
commits or squash merges. The age of a candidate is the age of
the youngest commit between `stable` and the candidate, so a commit that claims
an early time cannot hide a younger change under it. A candidate younger than
7 days is never chosen on the weekly run.

The revert check blocks a candidate that holds a chart or image that `main` no
longer has and `stable` does not have. A newer version of the same chart or
image at `main` is an ordinary update and does not block. A version that has
no numbers in it (a digest, or a tag such as `latest`) cannot be ordered, so
it blocks.

### Which code judges the candidate

The candidate is data. The workflow checks out the main commit that started the
run (the trusted checkout) and the candidate side by side. `make promote-overlay`
then replaces `ci/`, `tests/` and the `Makefile` of the candidate checkout with
the trusted ones. The scripts, the Makefile, `render.py`, `render-base.sh` and
`registry-allowlist.yaml` are therefore never the candidate's own. The same
holds for the settings the commit tier reads: `.githooks`, `.gitleaks.toml`,
`.gitleaksignore`, `.pipelinelintignore`, `.shellcheckrc`, the yamllint and
actionlint settings, and `renovate.json` (the list is `OVERLAY_PATHS` in the
Makefile). A path that the trusted tree lacks is removed from the candidate, a
symlink in the candidate is removed and never followed, and each copy is
compared with the trusted one. The `scan`
job, which runs the security gate and reads its ignore file, does not check out
the candidate at all.

The trusted checkout is the head of `main` at the start of the run, not a
soaked commit. It is the same code that the workflow file itself comes from.
An old candidate and a newer `ci/` can disagree (for example, `ci/clusters`
names an app that the candidate lacks). The candidate then fails closed and the
next older one is tried.

No job that handles candidate data has a secret or a write permission, with one
exception: the `scan` step gets the read-only Docker Hub token if both
`DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` exist. The `promote` job has the
deploy key. It does not check out the candidate. It fetches the history of
`main`, which holds the candidate commit as data.

The jobs after `select` run in the pinned kube-devenv image, which has the
Python packages, git, gh and ssh. The jobs that run on the plain runner (the
kind run, the record and the risk job) install packages only from
`ci/requirements-promote.txt` of the trusted checkout, with
`pip install --require-hashes`. Renovate updates that file through its
`pip-compile` manager. To change a package, edit `ci/requirements-promote.in`
and run `pip-compile --generate-hashes --strip-extras` to write the `.txt`.
Renovate never automerges a change to the promote workflows, the promote
scripts or this file.

Each job that makes a result writes a SHA-256 digest of it as a job output:
the runtime image list, the record, the scanned record, the manifest-risk files
and the selection. The job that reads the result checks its downloaded copy
against that digest (`ci/promote.py check-digest`), and `ci/promote-prepare.sh`
refuses to continue on a mismatch. The digest is computed from the files, so
it can be compared after the download. The download step also uses
`digest-mismatch: error`.

### Approval

The `promote` environment asks the owner to approve every run that reaches the
push, also when the manifest-risk diff has no additions. GitHub cannot make an
environment ask only sometimes, and the deploy key must stay in that
environment. The review text tells the owner whether there are additions.
For the manifest-risk result, only the exact value `false` from a job that
passed counts as no additions. A missing value counts as additions. A failed
`risk` job fails the candidate.

### Starting a run

Open Actions, select Promote and choose Run workflow on `main`.

- **Weekly run.** Leave every input empty. This is the same as the schedule.
- **Dry run.** Set `dry_run`. The run does everything except the key, the push,
  the tag, the attestation and the release. The `dry-run` job does the same
  final checks as the `promote` job and prints what a real run would do. It
  does not ask for approval.
- **Fast path.** Write a reason in `fast_path_reason`. The run skips the soak
  and promotes the head of `main`. If any other commit since `stable` is younger
  than 7 days, the review text says that the approval covers the aggregate diff
  of all of them. The security gate and the revert check still apply.
- **First promotion.** Set `first_promotion`. It is allowed only when no
  `stable-YYYYMMDD` release exists, no `stable-*` tag exists, and `stable` is
  still at the commit it was created at (`INITIAL_STABLE` in
  `ci/promote.py`). A run without the flag refuses to promote without a
  baseline. The gate then blocks only on a KEV finding.
- **Key proof.** Set `prove_key`. The run does nothing else. In the `promote`
  environment it creates a throwaway tag `stable-probe-...` with the deploy key
  and deletes it in a step that always runs. In a job outside the environment
  it tries the same with the workflow token, and the job passes only if the
  push is rejected. If a probe tag stays behind (for example when the runner is
  lost), delete it by hand with a credential that the `stable-tags` ruleset lets
  through: `git push origin --delete refs/tags/stable-probe-key-<run id>-<attempt>`. The tag
  ruleset has the same bypass rule as the one for `stable`, and the probe never
  touches `stable`. The first job waits for the owner, like every job in that
  environment.

To approve, open the waiting run, read the summary of the `choose` job, then
choose Review deployments and approve.

### Reading a result

- The summary of `select` shows the candidates and their landing times.
- The summary of `choose` shows each candidate with its result and failed jobs.
  After it comes the review text.
- The artifacts `security-gate-report-N` and `risk-N` (N is the candidate
  number) hold the scan summary and the full manifest-risk files.
- A promoted run publishes release `stable-YYYYMMDD`. A second promotion on the
  same day gets the suffix `-2`, and so on. The release holds
  `promotion-record.json` (the scanned record), `manifest-risk.json` and
  `manifest-risk.md`. The release text carries the manifest-risk diff.
- Verify a record with
  `gh attestation verify promotion-record.json --repo <owner>/<repo>`.
  The next run does this itself with the record of the current `stable`, and
  also requires the source ref `refs/heads/main` and the GitHub Actions token
  issuer. It stops if the record does not match the commit of `stable`.

### Settings the workflow needs

- The repository setting for immutable releases must be on. The `promote` job
  checks it before it loads the key. If the token can read the setting and it
  is off, the job stops. If the token cannot read it, the job stops unless the
  repository variable `IMMUTABLE_RELEASES_CONFIRMED` is `true`. Set that
  variable after you turn the setting on. The job also fails after the publish
  if the release is not immutable.
- The `stable` and `stable-tags` rulesets, the `promote` environment and the
  secret `PROMOTE_DEPLOY_KEY` must exist.
- Optional: the secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
- `ci/promote-key.sh` holds GitHub's published SSH host key. If GitHub rotates
  it, the push fails until the file is updated.

`make test-promote` (part of `make test-scripts`) runs `tests/check-promote.py`.
It tests the candidate rule, the revert check, the fallback, the final checks
and the baseline logic with fixtures and a real git history. It also reads
both workflow files. It fails if an action is not pinned to a commit, if a job
that handles candidate data gets a secret or a write permission, or if a job
outside the `promote` environment can read the deploy key.

Not tested here: the workflows on GitHub Actions. The first run is a dry run.

## Image pulls in the integration tier

A public registry can refuse anonymous pulls from a shared runner address. To keep
the run steady, `ci/e2e/preload-images.sh` gives the kind node the Argo CD images,
for the version the cluster starts with and for the version at this commit:

1. It pulls each image, with up to 5 tries.
2. If a Docker Official Image from the AWS public registry is still refused, it
   pulls the same image from Docker Hub, then from `mirror.gcr.io`, and tags it
   with the original name. The digest is the same on all three. The log shows
   `FALLBACK`.
3. If every source fails, the run stops and names the image.

Images that Argo CD installs later, and Cilium's images, are not loaded this way.
They have pulled without trouble so far.

`tests/preload-images.sh` tests this logic with stand-in `docker` and `kind`
commands.

Clusters follow `stable`, which only the promote workflow moves. Every PR is
still checked against the example clusters before it merges, because a merge
to `main` is a promotion candidate:

1. `render.py` renders the platform for each example cluster in `clusters/`
   the way Argo CD would: the root `platform` Application, then every
   Application it creates, all the way down. Sources in this repo come from
   the PR's checkout, upstream charts are fetched at their pinned versions.
2. kubeconform validates every rendered object against the Kubernetes
   schemas, and custom resources against the CRDs the same charts ship.
   CustomResourceDefinitions themselves, and ClusterSecretStore (whose schema
   kubeconform cannot compile), are not checked.
3. `make diff-comment` shows what changes against `main`, per cluster, as a
   PR comment (`diff_comment.py`, `render-base.sh`, `post-comment.sh`). The
   full render is the workflow's `rendered-manifests` artifact.
4. `make test-integration` deploys it for real: a kind cluster, Cilium and Argo CD
   installed the way a node's genesis installs them (at the versions of the
   base commit: the PR's base, or `stable` in the promote workflow, so a bump
   is tested as an upgrade), then the `kind.yaml` example cluster
   pointed at the commit under test. It passes once every Application is
   Synced and Healthy and every pod ready, steadily for a minute, and Argo
   CD answers through Traefik with the platform's certificate, and the
   platform's own Prometheus has no warning or critical alert pending or
   firing, no scrape target down and no rule failing (`e2e/alerts.py`; a
   few are expected on kind, listed there). It fails as
   soon as something is known to be broken: a sync out of retries or an
   image that doesn't exist at once, other errors once they outlast what a
   healthy bring-up goes through (`GRACE` in `e2e/wait.py`). Files in
   `e2e/`.

   kind can't stand in for everything: GPUs, iSCSI, Longhorn and EBS
   storage, secret stores and the BYO CA, autoscaling and external-dns are
   only rendered and validated. The single node also has no
   `CriticalAddonsOnly` taint, and runs Debian where real nodes run
   AlmaLinux.

## Promotion record

The promotion record is one JSON file. It lists what a commit of this repo
contains, so a scan can check exactly that. `ci/promotion-record.schema.json`
is its schema, and `ci/promotion_record.py` builds it.

It holds:

- **images**: every image with one digest that its registry serves. The list is the union of two sources.
  - `rendered`: the images in the rendered example clusters. The script does not
    grep `image:`. It also reads images that a grep misses. These are:
    arguments (the cert-manager solver, the Prometheus operator config
    reloader), the GPU operator fields, and the image of a system-upgrade Plan
    (`rancher/rke2-upgrade`). A GPU operator component with `enabled: false` is
    skipped.
  - `runtime`: the images the containers report after the kind run. A
    container whose image is only an ID (`sha256:...`, which the kubelet shows
    for an image that a digest pins) takes its name from the repository in its
    `imageID`.
  - `digest` is always a digest that the registry served when the record was
    built. The security gate scans this digest and no other. The builder asks
    the registry for the digest of the image index, as
    `docker buildx imagetools inspect` prints it. It also asks for a digest
    that the manifest pins. If the registry does not serve it, the build fails.
  - `digestSource` says how the record got the digest. `registry`: the registry
    returned it for the tag. `pinned`: the reference names the digest and the
    registry served it. Either way, it says what the registry holds now. It
    does not prove that any node pulled it.
  - `runtimeDigests` holds the digests that running containers reported. They
    are information only and nothing scans them. The kind run loads its images
    from single-platform archives, so the `imageID` of a container can be a
    digest that no registry serves. `runtimeDiffers` is `true` when a runtime
    digest is not the `digest` of the entry. A multi-platform image often
    differs: the node reports the digest of one platform, and the entry holds
    the digest of the index. This is normal. Look at it when a digest that a
    manifest pins differs.
  - One entry exists for each repository and digest. A tag beside a digest is
    dropped.
- **charts**: name, version, repository and digest. The digest is the digest of
  the chart archive (the value in the repository index), or the OCI manifest
  digest.
- **notScanned**: what an image scan does not see. Each entry has a type, a
  name and a reason.
  - `grafana-plugin`: a plugin that the pod downloads at start.
  - `unresolved-image`: an image the registry does not have under that name.
    The GPU driver is one. The ClusterPolicy names `595.91.07`, and the
    operator adds the OS suffix on the node.
  - `test-only`: an image that only objects with `helm.sh/hook: test` use (the
    phases `test`, `test-success` and `test-failure`, and no other phase), and
    that no container of the kind run used. A Helm test pod runs only when
    someone runs `helm test`. Argo CD does not run it. Today this is the
    kubetest2 image (`kubekins-e2e`) in the `ebs-csi-driver-test` pod, the
    bats image in the Grafana test pod, and the busybox image in the
    nvidia-gpu-exporter test pod. An image that a workload or another hook also uses stays
    in `images`.
- **scanner**: name, version and database time. They stay `null`. The security
  gate fills them in.
- **schemaVersion**: `2`. Version 2 changed what `digest` and `digestSource`
  mean, and added `runtimeDigests`, `runtimeDiffers` and the `test-only` type.
  In version 1 the `digest` of a running image was the `imageID` of the node,
  and the gate could fail with MANIFEST_UNKNOWN. A version 1 record is not
  valid, so it cannot be a baseline. No `stable` record existed when the
  version changed, so no promotion is affected. Raise the number again when a
  field changes meaning, or when a required field is added.
- **scan**: absent until the security gate has run. See "Security gate".

To build it:

1. Run `make render`.
2. Run `make test-integration RUNTIME_IMAGES_OUT=out/runtime-images.json`.
   The kind run writes the images its containers report to that file.
3. Run `make promotion-record`. It needs docker buildx, helm and the network.
   It writes `out/promotion-record.json`. It stops if a digest cannot be found,
   except for an operator-built tag.
   The registry calls retry 5 times, with growing waits. No Docker Hub login is
   used, because this repo has none.

In CI, the `record` job does this after the `integration` job and uploads the
`promotion-record` artifact. It is not a required check. `make test-commit`
runs `tests/check-promotion-record.py`, which tests the builder with fixtures
and stand-in `docker` and `helm` commands.

## Security gate

`ci/security_gate.py` scans the images of a promotion record with Trivy, by the
`digest` of each entry (the digest that the registry serves), and
decides if the record may be promoted. Trivy runs from the pinned kube-devenv
image, as the kube-devenv scheduled scan does. The gate compares the scan with
the record of the current `stable`, so it blocks only what a promotion adds.

It blocks in two cases:

- **New**: an image that is not in the `stable` record has a fixable HIGH or
  CRITICAL finding that `stable` does not list for the same repository,
  vulnerability and package.
- **KEV**: any finding, of any severity, is on the CISA Known Exploited
  Vulnerabilities list. This holds for old findings and for findings without a
  fix.

All other findings are published as known. An image whose digest is in the
`stable` record never blocks for a new finding. A promotion that changes nothing
is not blocked by a vulnerability found later. The daily rescan reports those.

It fails closed. It blocks when:

- the Trivy database is older than 48 hours or dated in the future, cannot be
  downloaded, or Trivy cannot report its version
- an image of the record has no scan result, or its scan failed
- Trivy detects nothing in an image (no results and no operating system),
  unless the ignore file has an `image` entry for its repository
- the KEV file is missing, is not a CISA catalog, is older than 21 days or is
  dated in the future
- an ignore entry has a bad ID, has expired, has no reason, or expires more than
  90 days from today
- the baseline is not a valid record, its verdict is not `pass`, or it did not
  scan every image it lists

The baseline is always explicit. Pass `BASELINE_RECORD=<the stable record>`. If
no `stable` exists yet, pass `FIRST_PROMOTION=1` instead. With neither, or with
both, `make security-gate` fails.

The gate writes the Trivy version and the database time into `scanner`, and
adds a `scan` object to the record: the verdict, the reasons, the counts, and
every HIGH or CRITICAL finding (or KEV finding) with the status `blocking`,
`known` or `ignored`. The next gate reads these findings as its baseline.
The summary also goes to the job summary.

To run it:

1. Build `out/promotion-record.json`. See "Promotion record".
2. Run `make kev-catalog`. It downloads the CISA catalog to `out/kev.json`.
3. Run `make security-gate BASELINE_RECORD=<the stable record>`. For the first
   promotion, run `make security-gate FIRST_PROMOTION=1`. It needs
   `trivy` and the network. It writes `out/promotion-record-scanned.json` and
   `out/security-summary.md`, and it exits 1 when it blocks.

To accept a finding for a while, add a line to `ci/security-gate.trivyignore`:

    CVE-2026-0001 exp:2027-01-31 reason:no upstream fix, not reachable

A static binary such as `registry.k8s.io/pause` has no packages, so Trivy
detects nothing. An `image` entry exempts a repository (not a digest) from that
one failure:

    image registry.k8s.io/pause exp:2027-01-31 reason:static binary, no OS packages

`docker.io/library/busybox` is exempt in the same way. It has no OS release
and no package database, so Trivy has nothing to match. This means its
vulnerabilities are not scanned. The entry expires, and the owner decides at
each renewal.

The exemption does not hide findings. If the scan has results, the gate checks
them as usual. The exemptions a run used are in the job summary and in
`scan.exemptions` of the record.

The ID, the reason and the date are all required. The date must be within
90 days of today. `make check-trivyignore` (part of `make test-commit`) fails
on an expired or incomplete entry. The gate applies the file itself, so an
ignored finding stays visible in the record.

An ignore entry can silence a KEV finding. It is also the only way out when
`stable` holds a KEV finding, because the KEV rule blocks even a promotion that
changes nothing. Review each entry that names a KEV vulnerability.

`make test-security-gate` (part of `make test-scripts`) runs
`tests/check-security-gate.py`. It tests the decisions with synthetic results,
and the parsing with a trimmed real Trivy report and a stand-in `trivy`.

In CI, the `gate` job runs after `record` on pushes to `main` and manual runs,
not on PRs. It is not a required check. It runs with `FIRST_PROMOTION=1`, so
only a KEV finding blocks there. The promote workflow must pass
`BASELINE_RECORD=<the stable record>`. It must also run the gate from trusted
code (a checkout of `main`, not the candidate), because the candidate could
change the gate or the ignore file.
The optional secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (a read-only
token) log in to Docker Hub for the pulls, so the shared runner address is not
rate limited. Set both or neither. The login is written for `index.docker.io` only, so no other
registry receives it.

## Manifest-risk diff

Image scanning cannot see a chart update that adds a hook, a privileged
container or a wildcard role. `ci/manifest_risk.py` renders `stable` and a
candidate commit and keeps only the changes in these classes:

- `rbac`: a rule of a Role or ClusterRole, an aggregation rule or label, and
  the subjects and role of a binding.
- `webhook`: a webhook (failure policy, selectors, target, timeout, side
  effects, CA bundle), an admission policy, an APIService and a CRD
  conversion webhook.
- `hook`: an object with a Helm or Argo CD hook annotation, with the image
  repository, command and arguments of its containers. The image tag is left
  out, so a version bump of a hook image needs no approval. This is the
  accepted gap for tags below: the soak, the scan and the daily digest check
  cover them.
- `privileged`: privileged mode, added capabilities, privilege escalation,
  Unmasked `procMount`, Unconfined seccomp or AppArmor, `runAsUser: 0`,
  `hostPath` and local volumes, `hostNetwork`, `hostPID`, `hostIPC`,
  `hostPort`, and a namespace with the `privileged` Pod Security label. The
  script reads every mapping of an object, so it also finds these in the pod
  specs of custom resources.
- `source`: the `repoURL` and chart or path of an Argo CD Application (not
  `targetRevision`, which Renovate changes), and what an AppProject allows.
- `image`: an image repository that `stable` does not use on that cluster.
- `registry`: a new image repository outside `ci/registry-allowlist.yaml`.
  This catches a typosquat.

An addition is something one cluster has in the candidate and does not have in
`stable`. The comparison is per cluster. A rule that changes counts as one
removal and one addition. A removal never needs approval.

`ci/registry-allowlist.yaml` has one entry per registry. Each entry has a
reason. It can list path prefixes, so that `grafana/` is trusted on Docker Hub
and `grafanna/` is not. A prefix ends at a `/`.

To run it:

1. Run `make manifest-risk STABLE_REF=<stable commit>`. The default is `origin/stable`.
   The checked-out commit is the candidate. The run renders both sides, so it needs the network and helm.

The run writes two files to `out/manifest-risk/`. Both go to the run summary
and to the release.

- `manifest-risk.json` is the result. `needsApproval` is `true` when there is
  any addition, and `false` when the diff is empty or has only removals. The
  promote workflow reads this field. `additions` and `removals` list each item
  with its severity, class, object, detail and clusters, most severe first.
- `manifest-risk.md` is the text for the run summary. It shows the count of
  each class, then the most severe rows. It states how many rows it does not
  show, with the number of rows for each object. The JSON has every row up to
  5000 per list. The counts are always complete.

Every field in the Markdown is cleaned and cut to a fixed length. A cut value
ends with a hash of the whole value. The summary is cut to 900 000 bytes.

If `GITHUB_OUTPUT` is set, the script also writes `needs_approval` and
`additions` to it. It writes only a boolean and a number.

### Rules for the promote workflow

- The workflow must run this tool, `render.py`, `render-base.sh`, the
  `Makefile` and the allowlist from a trusted checkout (`main` or `stable`).
  It must never run them from the candidate tree. A candidate that changes
  them could hide its own additions. Render the candidate with the trusted
  `ci/`, as `render-base.sh` does for the base.
- If the `needs_approval` output is absent or empty, or the step exits with
  a non-zero code, approval is needed. Fail the job. Only the value `false`
  from a step that exited with code 0 means that no approval is needed.
- The step exits with code 2 if a render is missing or empty, if an object
  cannot be read, or if the allowlist is not valid. A broken render never
  looks like an empty diff.

### Known gaps

- A new tag of a repository that `stable` already uses is not an addition.
  The 7-day soak, the image scan and the daily digest check cover tags.
- Anything that only exists at runtime is not visible in a render: images that
  an operator builds on the node, and code that a container downloads at
  start.
- Argo CD ApplicationSets, AppProject destinations, Gatekeeper and Kyverno
  policies, NetworkPolicies, Service types, Ingress and Gateway routes, and
  ConfigMap and Secret contents are not read.
- The `privileged` class reads the pod fields above. A custom resource that
  names host access in a field of its own, for example a hostPath key under
  another name, is not found.

`make test-commit` runs `tests/check-manifest-risk.py`, which uses the fixtures
in `tests/fixtures/manifest-risk/`.

## Stable watch

`.github/workflows/stable-watch.yaml` watches `stable` every day at 20:00 UTC.
You can also start it by hand. The decisions are in `ci/stable_watch.py`. The
workflow only sets up the jobs. It uses the gate scan of `ci/security_gate.py`
and the digest lookups of `ci/promotion_record.py`.

### What a run does

1. The `fetch` job gets the record of the latest published `stable-YYYYMMDD`
   release. It verifies the attestation with `gh attestation verify`, with the
   same flags as the promote workflow. It checks that the record is for the
   commit that `stable` is at.
2. If no release exists yet, the run stops with a notice: stable has not been
   promoted yet. Nothing else runs and no issue changes. With no release there
   is no stale alarm either, even if `stable` is far behind `main`.
3. The `scan` job rescans every image of the record by its registry digest. It
   uses the code of `main` and the pinned kube-devenv image. No candidate code
   runs.
4. The `resolve` job asks the registries for the digest of every image and
   chart, and compares each with the record.
5. The `report` job decides which conditions are active. It opens, updates and
   closes the issues below. The run is red while a priority issue is open.
6. The `keepalive` job keeps the workflow enabled. See "Quiet repository".

### The issues

Every issue has the label `stable-watch`. A priority issue also has the label
`priority`. Each has a hidden marker in its first line. The workflow finds its
issues by title, marker, label and author (the Actions bot). An issue of
someone else with the same title is not touched.

| Issue | Opens when | Closes when |
|---|---|---|
| Known vulnerabilities in stable | always | never |
| Priority: an upstream tag or chart changed after review | a registry digest differs from the record | every digest matches again |
| Priority: a known exploited vulnerability in stable | a finding is on the CISA KEV list | no finding is on the list |
| Priority: stable is more than 21 days behind main | the oldest commit of `main` that `stable` lacks landed more than 21 days ago | `stable` is not behind by more than 21 days, for example after a promotion |
| Priority: the daily check of stable is incomplete | a part of the check could not finish, or a result cannot be trusted, in 2 runs in a row (at once if the attestation fails or the record does not fit `stable`) | every part finished |

The first issue is the rolling issue. The workflow updates its text in place
each day. It never opens a second one. If you close it, the next run opens it
again. It shows the scan time, the scanner and database time, the images
scanned, the counts, the findings that are new since the scan in the record,
the KEV findings, and the HIGH and CRITICAL findings with their fix versions.

A priority issue is closed with a comment that says why. It is never closed
without a comment. If the details of an open priority issue change, the
workflow edits the text and adds a comment.

### Fail closed

A result that is missing is never reported as clean. A condition is active,
clear or unknown. Unknown means the check could not run. An unknown condition
keeps its issue as it is, and it opens the incomplete issue.

The scan follows the gate rules. These make it incomplete:

- the Trivy database is older than 48 hours, or the scanner is missing
- an image has no scan result, or its scan failed
- Trivy detects nothing in an image that has no `image` entry in the ignore file
- the KEV file is missing, or older than 21 days
- an entry of `ci/security-gate.trivyignore` is invalid or expired

The rolling issue carries a hidden count of the incomplete runs in a row. One
outage on one night opens no issue, but the run is still red. A run that is
complete sets the count to 0. A failed attestation, an invalid record and a
record for another commit than `stable` are not outages, so they open the
incomplete issue at once. A KEV finding and drift always open their issues at
once.

A registry error makes the digest check incomplete, not clean. A lookup retries
five times before it counts as an error. A failed fetch, a failed
attestation check, a record for another commit than `stable`, a failed lag
lookup and a `stable` that is not an ancestor of `main` are incomplete too.

### Drift

The workflow resolves each image reference and each chart again. For an image
it asks the registry that the reference names, and no other. The record builder
falls back to a mirror for some Docker Official Images. The watch does not: if
the primary lookup fails, the digest is unresolved and the check is incomplete.
It is never drift and never clean.
For a chart it downloads the archive (or asks for the OCI manifest). It then
compares the result with the digest in the record.

An entry with `digestSource: pinned` has its digest in the reference. A tag
cannot move it. The check still asks the registry, so a digest that the
registry no longer serves shows as an error. The check cannot find a change by
tag for that entry.

Where several references of the same image shared one digest, the record keeps
`name@digest` as the reference. The tag is lost, so the check can only verify
that the registry still serves the digest. It cannot find a change of that tag.

### Stale stable

The lag is the age of the oldest commit on the first-parent line of `main` that
`stable` lacks. The age counts from the merge time of its pull request. If the
commit has no merged pull request, its age is unknown, because the author of a
push chooses the commit date. The check is then incomplete and the alarm does
not open. The alarm opens when the lag is more than 21 days.

### Permissions and secrets

- The top level has `permissions: {}`.
- `fetch`, `resolve` and `scan` have `contents: read`.
- `report` has `contents: read` and `issues: write`. It is the only job that
  writes issues. It has no registry token.
- `keepalive` has `actions: write` and nothing else.
- There is no deploy key and no other secret.
- `resolve` and `scan` log in to Docker Hub with the optional read-only token
  `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, as the `gate` job does. This only
  avoids rate limits. Set both or neither.
- The actions are pinned to the same commits as in `tiers.yaml`.
- Text from a registry or a finding is cut to a length limit and escaped
  (Markdown, HTML, mentions and bare URLs) before it goes into an issue. Issue titles are
  fixed text. No run block holds an expression with outside data.
- `resolve` is the one job that does not run in the kube-devenv image. It needs
  `docker buildx`, which the image does not have. Its script uses only the
  Python standard library, so it installs no package.

### Quiet repository

GitHub disables a scheduled workflow in a public repository when there is no
repository activity for 60 days. A repository that only gets a weekly promotion
and a few Renovate pull requests can reach that state in a quiet period.

The `keepalive` job calls `PUT /repos/{owner}/{repo}/actions/workflows/stable-watch.yaml/enable`
with the `GITHUB_TOKEN` (permission `actions: write`) on every run. It needs no
secret and makes no commit. If the call fails, the job fails and the run is red.

What was verified when this was written:

- The GitHub documentation states the 60-day rule for public repositories.
- The GitHub REST documentation describes the enable call. It takes the file
  name and needs the `Actions` write permission.
- The public action `liskin/gh-workflow-keepalive` uses the same call for the
  same purpose.

What is not proven: GitHub does not document that this call restarts the
60 days. Treat the reset as unproven. The proof is the watchdog.

The `stable-watch-alive` job in `tiers.yaml` is the watchdog. It runs on every
push to `main` (not on pull requests), and it is not a required check. A push
workflow is not disabled by inactivity. The job has `contents: read` and
`actions: read`. It runs `make stable-watch-watchdog`, which fails with an
error if the newest Stable watch run is older than 2 days. If `stable` has no
release yet, it skips with a notice. If it fails, do these steps:

1. Run `gh workflow enable stable-watch.yaml`.
2. Start the Stable watch workflow by hand.

A disabled workflow cannot enable itself.

### Reading an issue

If a priority issue is open, do these steps:

1. Open the issue and read the table.
2. If the issue is about drift, find what changed upstream. If the change is
   not expected, treat it as a possible attack. Do not promote until you know
   the cause.
3. If the issue is about a KEV finding, read the advisory. Update the image in
   `main` and promote it, or add an entry with a reason and an expiry date to
   `ci/security-gate.trivyignore`.
4. If the issue is about a stale `stable`, read why the last Promote runs did
   not pass.
5. If the issue is about an incomplete check, read the reasons. Fix the cause
   and start the workflow by hand. An outage clears by itself on the next run.

### Running the parts

`make test-stable-watch` (part of `make test-scripts`) runs
`tests/check-stable-watch.py`. It uses stand-ins for `gh`, `docker` and `helm`
and a git repository made in a temporary directory. It also reads the workflow
file and checks the permissions, the pinned actions, and that no run block
installs a package or holds an expression.

The live parts need the network:

1. Run `make stable-watch-resolve`. It reads `out/stable/promotion-record.json`
   and writes `out/resolved.json`. It needs `docker buildx` and `helm`.
2. Run `make kev-catalog`, then `make stable-watch-scan`. It writes
   `out/scan-results.json`. It needs `trivy`.

### Known gaps

- The daily scan reads the same image set as the record. It does not see an
  image that `main` added after the promotion.
- Code that a container downloads at start is in `notScanned` and is not
  scanned.
- The watch does not look at the `stable` branch itself. A push to `stable`
  that bypasses the promote workflow shows as a record for another commit.

## Example clusters

Each file in `clusters/` is a root `platform` Application, written the way a
consumer writes it. Between them they switch on every optional template:

| File | Shape |
|---|---|
| `homelab-gpu.yaml` | single node, NVIDIA GPU, Hubble, two democratic-csi backends |
| `aws.yaml` | kube-compute's `aws-cluster`: EBS, cluster-autoscaler + cloud controller manager, SSM secrets, BYO CA, external-dns, trusted internal CA |
| `proxmox.yaml` | kube-compute's `proxmox-cluster`: Vault/OpenBao secrets and BYO CA, Cluster API autoscaling, local-path + Longhorn, extra Traefik port, Grafana plugins |
| `azure-acme.yaml` | ACME certificates, Azure Key Vault secrets, Hubble off, no storage |
| `kind.yaml` | what `make test-integration` deploys: self-signed certificates, Hubble, local-path |

When a consumer turns on something none of these do, add it to the closest
one (or add a file).

## Helm capabilities

Charts that check `.Capabilities.APIVersions` see what a live cluster would
serve: every Kubernetes API from the published OpenAPI of the version in
`platform/platform-versions/values.yaml`, the APIs RKE2 and runtime-installed
controllers add (`RUNTIME_APIS` in `render.py`), and the CRDs that cluster's
own platform renders.

## Running it locally

```sh
pip install pyyaml        # plus helm 4 on PATH
python ci/render.py . out/head
```
