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
| Node autoscaling | cluster-autoscaler on AWS, with the cloud controller manager | `clusterAutoscalerEnabled` |
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

`main` deploys to nothing by default. Clusters follow `stable`, a branch that
only the promote workflow moves. A commit reaches `stable` after a 7-day soak,
a security gate, a review of risky manifest changes and the owner's approval.
A change therefore reaches a cluster 7 to 14 days after it merges. A security
fix can use the fast path, which skips the soak but not the gates or the
approval. The exception is the RKE2 upgrade Plans, which each cluster syncs by
hand. See "Using stable".

This is why Renovate can wait only 1 day and automerge leaf apps. An automerge
puts a change on `main`, and `main` runs nowhere unless a consumer chooses it.
The 1-day wait limits PR churn from chart repositories that publish several
releases a day. The 7-day soak of `stable` gives others time to find a bad release before a
cluster runs it.

## Using it

Clusters built with [kube-compute](https://github.com/bbaliyan/kube-compute)
get the root Application automatically. To write one by hand, copy the
closest example from `ci/clusters/`. It must also load
`platform/platform-versions/values.yaml`, as they do.

## Using stable

`stable` is the branch that clusters follow. The example clusters in
`ci/clusters/` and the default `platformRevision` in `bootstrap/values.yaml`
use it. This section is for people who run the platform. `ci/README.md`
describes the promote workflow.

### What the contract guarantees

- Only the promote workflow moves `stable`. A ruleset blocks every other push,
  force-push and deletion.
- Every commit on `stable` passed the CI tiers, the security gate and the
  manifest-risk review, and the owner approved it. Each commit was on `main`
  for at least 7 days, unless the owner used the fast path with a written
  reason. The fast path skips only the soak.
- Every promotion publishes one release, `stable-YYYYMMDD`. A second promotion
  on the same day gets the suffix `-2`. The release cannot be changed after
  it is published.
- The release holds `promotion-record.json`, `manifest-risk.json` and
  `manifest-risk.md`. GitHub signs an attestation for the record. The record
  lists every image with its digest, every chart with its version and digest,
  what the scan could not see, and the scan result.

The contract does not promise that `stable` has no vulnerabilities. A finding
with no fix is published as known and does not block. The manifests name
images by tag, so an upstream tag can change after review. The daily watch
workflow compares the record with what the registries serve now.

### Verify a promotion

If you do not use the `gh` CLI yet, install it and sign in first.

1. Find the newest release: `gh release view --repo bbaliyan/kube-platform --json tagName --jq .tagName`.
2. Download its record. Replace `stable-YYYYMMDD` with the tag from step 1.

   ```sh
   gh release download stable-YYYYMMDD --repo bbaliyan/kube-platform --pattern promotion-record.json
   ```

3. Verify the attestation of the record.

   ```sh
   gh attestation verify promotion-record.json \
     --repo bbaliyan/kube-platform \
     --signer-workflow bbaliyan/kube-platform/.github/workflows/promote.yaml \
     --source-ref refs/heads/main \
     --cert-oidc-issuer https://token.actions.githubusercontent.com
   ```

4. If the command fails, do not trust the record. Open an issue.
5. Read the commit of the record: `jq -r .commit promotion-record.json`.
6. Read the commit of `stable`: `git ls-remote https://github.com/bbaliyan/kube-platform refs/heads/stable`.
7. If the two commits differ, repeat from step 1. If they still differ, open an issue.

The workflow runs the same command on the record of the current `stable` before
every promotion.

### Read the promotion record

Run the commands in the directory that holds `promotion-record.json`.

1. Show the verdict and the counts: `jq '.scan | {verdict, scannedAt, baselineCommit, counts}' promotion-record.json`.
2. Verify that `verdict` is `pass`. A record with another verdict was not promoted.
3. List the findings: `jq '.scan.findings[]' promotion-record.json`. They are all the HIGH and CRITICAL findings, and any finding on the CISA Known Exploited Vulnerabilities list.
4. Read the `status` of each finding. A promoted record has no `blocking` finding.
5. If the status is `known`, the finding has no fix yet, or the previous `stable` already had it.
6. If the status is `ignored`, the owner accepted it in `ci/security-gate.trivyignore`, with a reason and an expiry date.
7. List what the scan could not see: `jq '.notScanned' promotion-record.json`.
8. List the images: `jq -r '.images[] | .reference + " " + .digest' promotion-record.json`.

The record shows the state at the time of promotion. A vulnerability found
later is not in it.

### Read the known vulnerabilities issue

The issue "Known vulnerabilities in stable" lists the vulnerabilities in the
current `stable` as found today. The daily watch workflow creates and updates
it. Nobody should edit it by hand.

1. Open the issues of the repository and search for "Known vulnerabilities in stable".
2. Read the list. It updates after each daily run.
3. If a finding affects an image you run, open an issue. Say which one.

The same workflow opens a separate priority issue if an upstream image or
chart no longer matches the record, if a finding is on the CISA Known Exploited
Vulnerabilities list, or if `stable` is more than 21 days behind `main`.

### Follow main on purpose

You can point a cluster at `main`. A merge then reaches it within minutes.

You give up:

- the 7-day soak, so a new upstream release can reach you on the day Renovate
  merges it;
- the security gate and the manifest-risk review, so a change that adds a
  hook, a privileged container or a wildcard role reaches you unreviewed;
- the promotion record, so no signed list says what you run;
- the rolling vulnerability issue, which describes `stable` and not `main`.

To follow `main`:

1. If a tool such as kube-compute renders the root `platform` Application, change its input and render again. Otherwise open the Application.
2. Set `targetRevision` to `main` on both sources.
3. Set the parameter `platformRevision` to `main`.
4. Apply the change.

Set all three together. A mix would take the root from one branch and the
child Applications from the other.

### If stable looks wrong

If `stable` breaks a cluster, or a record does not match what you see, open an
issue in this repository. The owner has a runbook in the planning hub.

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

The channel is generic: `platform-values/<component>.yaml`. The
`observability` and `argocd` components use it today.

### Set Argo CD values from the workloads repo

A cluster with a workloads repo can set Argo CD's own configuration in
`platform-values/argocd.yaml`, for example single sign-on. The `argocd`
Application reads the file as a Helm values file for the `argo-cd` chart, so
the keys are the chart's, such as `configs.cm` and `configs.rbac`.

```yaml
configs:
  cm:
    url: https://argocd.example.com
    oidc.config: |
      name: Google
      issuer: https://accounts.google.com
      clientID: $argocd-google-oauth:clientID
      clientSecret: $argocd-google-oauth:clientSecret
  rbac:
    scopes: "[email]"
    policy.csv: |
      g, admin@example.com, role:admin
```

- Keep client secrets in a Secret in the `argocd` namespace. Label it
  `app.kubernetes.io/part-of=argocd`, and refer to it as `$<secret>:<key>`.
- `argocdExtraConfigs` overrides the file, and both override the defaults of
  this chart.
- If the file is missing, the Application renders as before.
- A cluster without a workloads repo is unchanged.
- Argo CD reads the workloads repo to render its own Application. If the repo
  credential breaks, the `argocd` Application cannot sync, but the running
  Argo CD keeps working. Keep the local `admin` account enabled as a way in.

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
