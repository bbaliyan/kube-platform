# os-updates

This chart reports the OS update state of each node. It does not install updates and it does not reboot nodes.

## How a node gets updates and reboots

1. The node image installs updates. On RHEL-family nodes, kube-compute enables `dnf-automatic-install.timer`. The timer runs daily and installs updates. It holds back the RKE2 packages, because the system upgrade controller owns the RKE2 version.
2. `dnf-automatic` is set to `reboot = never`. After a kernel or library update, the node keeps running the old code until someone reboots it.
3. The collector in this chart writes `os_updates.prom` every hour. It reports pending updates and `node_reboot_required`.
4. The alert `NodeRebootRequired` fires when a node has needed a reboot for 7 days. Reboots are manual. Drain the node, reboot it, and wait for it to become Ready.

## The collector

A DaemonSet runs one pod per node. The pod mounts the host root, runs the package scripts in a `chroot`, and writes the result to the textfile directory. node-exporter reads that directory.

`textfileDirectory` in `values.yaml` must match node-exporter's `--collector.textfile.directory` flag, relative to the host root. If they differ, `NodeOSUpdateMetricsMissing` fires.

## Alerts

| Alert | Fires when |
|---|---|
| `NodeOSUpdateMetricsMissing` | A node has no `os_updates.prom` file, or the file is older than 3 hours. |
| `NodeRebootRequired` | `node_reboot_required` has been 1 for 7 days. |
| `NodeSecurityUpdatesPending` | Debian-family nodes only: `apt_upgrades_pending` has security updates for 7 days. |
| `NodePackageListsStale` | Debian-family nodes only: the package lists are older than 3 days. |

RHEL-family nodes report `yum_upgrades_pending` without a security split. `NodeSecurityUpdatesPending` does not cover them.

## The Kubernetes version upgrade

`system-upgrade-plans` is a separate chart. It has no automated sync on purpose. Its Argo CD Application shows `OutOfSync` and `Missing` until an operator runs `argocd app sync system-upgrade-plans`. This lets each cluster roll the RKE2 version at a time of its choosing.
