# kube-platform

[![CI](https://github.com/bbaliyan/kube-platform/actions/workflows/tiers.yaml/badge.svg?branch=main)](https://github.com/bbaliyan/kube-platform/actions/workflows/tiers.yaml?query=branch%3Amain)

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

\* `certMode: acme` uses Let's Encrypt (or any ACME CA, `acmeServer`) with
Cloudflare DNS-01. Set `acmeEmail`, and either `acmeCloudflareTokenRef`
(with `secretStoreType`) to fetch the Cloudflare token from the secret
store, or create the Secret `cloudflare-api-token` (key `api-token`) in
`cert-manager` yourself.

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

## Observability storage

Each observability component has its own volume size, storage class and
retention. Every value is optional. The defaults are shown below.

| Key | Default | Meaning |
|---|---|---|
| `prometheus.retention` | `7d` | How long Prometheus keeps metrics. |
| `prometheus.retentionSize` | empty | Size limit. Prometheus drops its oldest data above it. Empty means no limit. |
| `prometheus.storage.size` | `20Gi` | Prometheus volume size. |
| `alertmanager.storage.size` | `2Gi` | Alertmanager volume size. |
| `grafana.storage.size` | `5Gi` | Grafana volume size. |
| `loki.retention` | `72h` | How long Loki keeps logs. |
| `loki.storage.size` | `10Gi` | Loki volume size. |
| `<component>.storage.storageClassName` | empty | Storage class of that component. Empty uses the top-level `storageClassName`. |

IOPS and throughput belong to the StorageClass, not to this chart. Define
the classes you need in the cluster and name one per component.

Set `retention` and `retentionSize` together. Prometheus drops data when
either limit is reached.

### Where a cluster sets the values

If the cluster has a workloads repo, put the values in
`platform-values/observability.yaml` at the root of that repo. Do not put
the file under the workloads path. The `workloads` Application applies
everything under that path as manifests.

```yaml
prometheus:
  retention: 30d
  retentionSize: 34GB
  storage: {size: 40Gi, storageClassName: fast}
loki:
  retention: 168h
  storage: {size: 20Gi}
```

A push to that repo changes the values. No Terraform run is needed.

- The file accepts only the keys in the table, plus the other documented
  keys in `platform/observability/values.yaml`. `values.schema.json` rejects
  any other key. A bad file makes the `observability` sync fail. Argo CD
  does not ignore it. CI runs the same check against sample files.
- If the file is missing, the Application renders with the defaults.
- Argo CD must be able to read the workloads repo. If the repo is private,
  add a repository credential. If Argo CD cannot reach the repo, the
  `observability` sync fails, even when the file does not exist.
- `observabilityExtraHelmValues` overrides the file. Argo CD gives
  `valuesObject` priority over `valueFiles`.
- The file is read only when kube-compute passes `workloadsRepoURL`. The
  bootstrap chart then adds the workloads repo as a second source named
  `workloads`. It sets `ignoreMissingValueFiles: true` on the chart source.
  Without a workloads repo there is no second source.

The channel is generic: `platform-values/<component>.yaml`. Only
`observability` uses it today.

### Resize a volume

A size increase needs `allowVolumeExpansion: true` on the StorageClass.

- Grafana: the claim expands in place.
- Prometheus and Alertmanager: the operator expands the claims.
- Loki: Kubernetes does not let a StatefulSet change its volume template.
  Follow the steps below.

Warning: in step 4, you must delete only the StatefulSet. Use
`--cascade=orphan`. Without it, the pod stops.

To grow the Loki volume:

1. Raise `loki.storage.size` in Git.
2. Verify that Argo CD shows the `loki` Application out of sync.
3. Patch the existing claim to the new size:
   `kubectl -n loki patch pvc storage-loki-0 -p '{"spec":{"resources":{"requests":{"storage":"20Gi"}}}}'`
4. Delete only the StatefulSet: `kubectl -n loki delete statefulset loki --cascade=orphan`
5. Verify that the claim shows the new size: `kubectl -n loki get pvc storage-loki-0`
6. Sync the `loki` Application. Argo CD recreates the StatefulSet with the new size.

### Loki retention and the claim

Loki deletes logs older than `loki.retention`. The platform turns on the
compactor's retention for this. A cluster that kept all its logs before
starts deleting logs older than the retention on its next sync.

Loki keeps its volume when the StatefulSet is scaled to 0 or deleted.

### Dropping unused metrics

The API server alone can be half of all series in Prometheus. Most of them
are histogram buckets that no stock rule or dashboard reads. Two keys under
`prometheus` drop series before they are stored. Both are optional.

| Key | Default | Meaning |
|---|---|---|
| `prometheus.dropUnusedControlPlaneMetrics` | `false` | If `true`, drops the series that no stock rule or dashboard uses. |
| `prometheus.extraDropMetrics` | `[]` | A list of regexes of metric names to drop, on top of the preset. |

Both keys apply to the same four components: the API server, etcd, the
controller manager and the scheduler. They add a `drop` rule to the
`metricRelabelings` of each component's ServiceMonitor. The chart's own
default rules stay in place. The preset lists are in
`platform/observability/drop-unused-control-plane-metrics.yaml`.

Prometheus anchors each regex on both ends. `apiserver_.*` drops every name
that starts with `apiserver_`. `apiserver_request` drops nothing.

The preset drops the `_bucket` series of the API server and etcd request
durations. The cluster then has no latency percentiles for them. The
`_sum` and `_count` series stay, so averages still work. The preset keeps
`apiserver_request_sli_duration_seconds` and `apiserver_request_total`,
which the stock alerts and dashboards use.

The preset also drops the Go runtime and process families (`go_gc_*`,
`go_memstats_*`, `process_open_*` and similar) and many informer, workqueue
and `rest_client` families of those four components. A custom dashboard or
rule on them shows no data.

The preset does not cover Cilium. It does not cover the unused `_bucket`
series of kubelet, Grafana, Argo CD, Prometheus, the operator and
Alertmanager either.

Warning: a dashboard or rule you write later can use a dropped metric. It
then shows no data. Verify the metric names against the preset first.

Warning: the platform joins all regexes with `|` into one rule per
component. A regex such as `up`, `.*` or `apiserver_request_total` silently
disables control-plane alerts (`KubeAPIDown`, the SLO burn alerts) and
dashboards. The render fails on a regex that does not compile. Verify that
each regex matches only the names you want to drop before you set it.

To turn it on, add this to `platform-values/observability.yaml`:

```yaml
prometheus:
  dropUnusedControlPlaneMetrics: true
  extraDropMetrics:
    - etcd_request_duration_seconds_(sum|count)
```

CI renders the platform with the preset on. It then collects every metric
name in the rendered PrometheusRules and dashboards, including this repo's
own. It fails if a preset regex matches one of them. A chart upgrade that
starts to use a dropped metric fails in CI before it reaches a cluster. The
check cannot see rules and dashboards that a cluster adds, or dashboards
that Grafana downloads at start.

## Upgrading

Versions are pinned in `platform/platform-versions/values.yaml`, in the
Applications' `targetRevision` (under `bootstrap/templates/` and
`platform/observability/templates/`), in `Chart.yaml` files, and as image
tags in values files and manifests under `platform/`. Renovate opens the
PRs; merging one upgrades every cluster.

For RKE2 itself, after merging, run `argocd app sync system-upgrade-plans`
on each cluster when you want it upgraded. A new RKE2 minor also needs the
kind node image (`kindNodeVersion` in `ci/e2e/versions.yaml`) on the
same minor, or `make test-integration` fails.

## The `stable` branch: protection and break-glass

Only the promote workflow moves `stable`. Two rulesets enforce this:

- `stable` blocks updates, force-push and deletion on the branch.
- `stable-tags` blocks creation, update and deletion of `stable-*` tags.

The only bypass actor is the repository deploy key `kube-platform-promote`.
Its private key is the secret `PROMOTE_DEPLOY_KEY` in the `promote`
environment. That environment allows the `main` branch only and needs the
owner's approval. The default `GITHUB_TOKEN` cannot be a bypass actor in a
user-owned repository, which is why a deploy key is used.

### Break-glass: move `stable` by hand

Use this only if the promote workflow cannot run and `stable` must change.

1. Open the repository Settings, then Rules, then Rulesets.
2. Open the ruleset `stable`.
3. Under Bypass list, add the role "Repository admin" with the mode "Always allow".
4. Save the ruleset.
5. Push the commit: `git push origin <sha>:stable`.
6. Open the ruleset `stable` again.
7. Remove the role "Repository admin" from the Bypass list.
8. Save the ruleset.
9. Verify the ruleset lists only the deploy key as a bypass actor.

Warning: do not leave the admin role on the Bypass list. The next promotion
record would no longer prove who moved `stable`.

## CI

Every PR and every commit to `main` is checked on GitHub's runners:

- **render**: renders the platform for each example cluster in
  `ci/clusters/`, validates it against Kubernetes and CRD schemas, and
  comments on the PR what it changes on each.
- **dropped metrics**: part of the same job. It fails if the metric drop
  preset matches a metric that a rule or dashboard uses. See "Dropping
  unused metrics".
- **e2e**: deploys the platform to a kind cluster and checks that every
  Application syncs and turns Healthy, every pod is ready, Argo CD answers
  through Traefik, and the platform's own Prometheus has no alert, scrape
  target or rule in trouble.

The badge above is `main`'s status. Each run's summary page shows the state
of every Application and Prometheus's alerts, and on a PR the rendered
diff. A failed e2e run uploads kind's logs as an artifact. See
[ci/README.md](ci/README.md) for details.
