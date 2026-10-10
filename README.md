# kube-platform

[![CI](https://github.com/bbaliyan/kube-platform/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/bbaliyan/kube-platform/actions/workflows/ci.yaml?query=branch%3Amain)

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
| Private git repos | Argo CD repo credentials from that store; trust for a git server with an internal CA | `secretStoreType`; `trustedCaPemB64` + `argocdTlsCertHostname` |
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

Versions are pinned in `platform/platform-versions/values.yaml`, in the
Applications' `targetRevision` (under `bootstrap/templates/` and
`platform/observability/templates/`), in `Chart.yaml` files, and as image
tags in values files and manifests under `platform/`. Renovate opens the
PRs; merging one upgrades every cluster.

For RKE2 itself, after merging, run `argocd app sync system-upgrade-plans`
on each cluster when you want it upgraded. A new RKE2 minor also needs the
kind node image (`KIND_NODE_VERSION` in `.github/workflows/ci.yaml`) on the
same minor, or e2e fails.

## CI

Every PR and every commit to `main` is checked on GitHub's runners:

- **render**: renders the platform for each example cluster in
  `ci/clusters/`, validates it against Kubernetes and CRD schemas, and
  comments on the PR what it changes on each.
- **e2e**: deploys the platform to a kind cluster and checks that every
  Application syncs and turns Healthy, every pod is ready, Argo CD answers
  through Traefik, and the platform's own Prometheus has no alert, scrape
  target or rule in trouble.

The badge above is `main`'s status. Each run's summary page shows the state
of every Application and Prometheus's alerts, and on a PR the rendered
diff. A failed e2e run uploads kind's logs as an artifact. See
[ci/README.md](ci/README.md) for details.
