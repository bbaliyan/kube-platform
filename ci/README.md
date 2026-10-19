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
