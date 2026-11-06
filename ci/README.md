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

Clusters sync this repo's `main` as soon as it moves, so every PR is checked
against example clusters before it merges:

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
   installed the way a node's genesis installs them (at `main`'s versions,
   so a bump is tested as an upgrade), then the `kind.yaml` example cluster
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

- **images**: every image with its digest. The list is the union of two sources.
  - `rendered`: the images in the rendered example clusters. The script does not
    grep `image:`. It also reads images that a grep misses. These are:
    arguments (the cert-manager solver, the Prometheus operator config
    reloader), the GPU operator fields, and the image of a system-upgrade Plan
    (`rancher/rke2-upgrade`). A GPU operator component with `enabled: false` is
    skipped.
  - `runtime`: the images the containers report after the kind run. The digest
    is the `imageID` the node pulled. It wins over the registry.
  - `digestSource` says where the digest came from. `runtime` is the digest of
    a running container. `registry` is what the registry returned for the tag
    when the record was built, or the digest written in the manifest.
    A `registry` digest says what the tag points at now. It does not prove that
    any node pulled it.
  - One entry exists for each repository and digest. A tag beside a digest is
    dropped.
- **charts**: name, version, repository and digest. The digest is the digest of
  the chart archive (the value in the repository index), or the OCI manifest
  digest.
- **notScanned**: what an image scan does not see. These are the Grafana
  plugins, which the pod downloads at start. They also include
  `unresolved-image` entries: images the registry does not have under that
  name. The GPU driver is one. The ClusterPolicy names `595.91.07`, and the
  operator adds the OS suffix on the node.
- **scanner**: name, version and database time. They stay `null`. The security
  gate fills them in.
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

`ci/security_gate.py` scans the images of a promotion record with Trivy and
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
