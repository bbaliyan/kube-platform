# kube-platform

Turns a bare RKE2 cluster into one you can run real applications on. Point
Argo CD at `bootstrap/` and it installs, and keeps in sync, everything an app
expects to already be there.

## What you get

| Need | Provided by | |
|---|---|---|
| Networking, load balancers | Cilium (kube-proxy replacement, node IPAM LB) | always |
| Network flow visibility | Hubble | opt-in |
| Ingress | Traefik; with a cluster domain, a wildcard certificate and routes to the UIs | always |
| Certificates | cert-manager: self-signed, your own CA, or ACME | always |
| Trusting an internal CA | trust-manager, distributing your CA to every namespace | CA opt-in |
| Secrets | External Secrets, reading Vault/OpenBao, AWS SSM or Azure Key Vault | store opt-in |
| Private git repos | Argo CD repo credentials, fetched from that vault | opt-in |
| Storage | AWS EBS, democratic-csi (TrueNAS iSCSI/NFS), Longhorn, local-path | pick any |
| Metrics, dashboards, alerts | Prometheus, Grafana, Alertmanager | always |
| Logs | Loki, collected by Alloy | always |
| GPUs | NVIDIA GPU Operator, plus a GPU exporter and dashboard | opt-in |
| Node autoscaling | cluster-autoscaler (Cluster API or AWS) | opt-in |
| DNS records | external-dns (Route53) | opt-in |
| Kubernetes upgrades | system-upgrade-controller and RKE2 upgrade Plans | always |
| OS update status | pending updates and reboots per node, as metrics | always |
| Cluster UI | Headlamp, plus Argo CD's | always |
| Scheduling priority | `platform` and `workload-critical` PriorityClasses | always |
| GitOps | Argo CD, managing itself | always |

## How it works

`bootstrap/` is a Helm chart of Argo CD Applications, one per component.
Upstream charts come in at pinned versions; anything this repo adds lives in
`platform/`. A cluster turns features on with parameters on its root
Application (see `bootstrap/values.yaml`).

Clusters follow `main`, so a merge reaches every cluster within minutes.

## Using it

Clusters built with [kube-compute](https://github.com/bbaliyan/kube-compute)
get the root Application automatically. To write one by hand, copy the
closest example from `ci/clusters/`.

## Upgrading

Every version lives in `platform/platform-versions/values.yaml` or the chart
that uses it. Renovate opens the PRs; merging one is the upgrade.

## CI

Every PR renders the platform for each example cluster, validates it, and
comments what would change. See [ci/README.md](ci/README.md).
