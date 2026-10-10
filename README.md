# kube-platform

Turns a bare RKE2 cluster into one you can run real applications on. Point
Argo CD at it and it installs, and keeps in sync, everything an app expects
to already be there.

## What you get

| Need | Provided by | Installed |
|---|---|---|
| Networking, load balancers | Cilium (kube-proxy replacement, node IPAM LB) | always |
| Network flow visibility | Hubble | `hubbleEnabled` |
| Ingress | Traefik | always |
| Wildcard certificate, routes to the UIs | cert-manager, Traefik | `clusterFqdnSuffix` |
| Certificates | cert-manager and its CSI driver: self-signed, your own CA, or ACME* | always |
| Trusting an internal CA | trust-manager, distributing your CA to every namespace | `trustedCaPemB64` |
| Secrets | External Secrets, reading Vault/OpenBao, AWS SSM or Azure Key Vault | store: `secretStoreType` |
| Private git repos | Argo CD repo credentials from that store; trust for a git server with an internal CA | `secretStoreType`; `argocdTlsCertHostname` |
| Storage | AWS EBS, democratic-csi (TrueNAS iSCSI/NFS), Longhorn, local-path | `storageProvisioners` |
| Metrics, dashboards, alerts | Prometheus, Grafana, Alertmanager | always |
| Logs | Loki, collected by Alloy | always |
| GPUs | NVIDIA GPU Operator, plus a GPU exporter and dashboard | `gpuOperatorEnabled` |
| Node autoscaling | cluster-autoscaler: Cluster API, or AWS with the cloud controller manager | `clusterAutoscalerEnabled` |
| DNS records | external-dns, publishing `DNSEndpoint` objects to Route53 | `externalDnsEnabled` |
| Kubernetes upgrades | system-upgrade-controller and RKE2 upgrade Plans | always |
| OS update status | pending updates and reboots per node, as metrics | always |
| Cluster UI | Headlamp, plus Argo CD's | always |
| Scheduling priority | `platform` and `workload-critical` PriorityClasses | always |
| GitOps | Argo CD, managing itself | always |

\* ACME uses Let's Encrypt with Cloudflare DNS-01: set the email in
`platform/pki-issuer/acme/` and provide a `cloudflare-api-token` Secret.

Every switch is a parameter on the root Application; `bootstrap/values.yaml`
lists them all.

## How it works

`bootstrap/` is a Helm chart of Argo CD Applications, one per component.
Upstream charts come in at pinned versions; anything this repo adds lives in
`platform/`.

Clusters follow `main`: a merge reaches every cluster within minutes. The
exception is the RKE2 upgrade Plans, which each cluster syncs by hand.

## Using it

Clusters built with [kube-compute](https://github.com/bbaliyan/kube-compute)
get the root Application automatically. To write one by hand, copy the
closest example from `ci/clusters/`. It must also load
`platform/platform-versions/values.yaml`, as they do.

## Upgrading

Versions are pinned in `platform/platform-versions/values.yaml`, in each
Application's `targetRevision` under `bootstrap/templates/`, and in the
`Chart.yaml` files under `platform/`. Renovate opens the PRs; merging one
upgrades every cluster. For RKE2 itself, then run
`argocd app sync system-upgrade-plans` on each cluster when you want it
upgraded.

## CI

Every PR renders the platform for each example cluster, validates it, and
comments what would change. See [ci/README.md](ci/README.md).
