# CI

Clusters sync this repo's `main` as soon as it moves, so every PR is checked
against example clusters before it merges (`.github/workflows/ci.yaml`):

1. `render.py` renders the platform for each example cluster in `clusters/`
   the way Argo CD would: the root `platform` Application, then every
   Application it creates, all the way down. Sources in this repo come from
   the PR's checkout, upstream charts are fetched at their pinned versions.
2. kubeconform validates every rendered object against the Kubernetes
   schemas, and custom resources against the CRDs the same charts ship.
   CustomResourceDefinitions themselves, and ClusterSecretStore (whose schema
   kubeconform cannot compile), are not checked.
3. `diff_comment.py` posts what changes against `main`, per cluster, as a PR
   comment. The full render is the workflow's `rendered-manifests` artifact.
4. The `e2e` job deploys it for real: a kind cluster, Cilium and Argo CD
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
| `kind.yaml` | what the e2e job deploys: self-signed certificates, Hubble, local-path |

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
