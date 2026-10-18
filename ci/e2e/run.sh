#!/usr/bin/env bash
# Build a kind cluster the way a node's genesis does, point Argo CD at this
# commit and check that the platform syncs and comes up healthy. See ci/README.md.
# Set KEEP_CLUSTER=1 to leave the cluster behind.
set -euo pipefail

cd "$(dirname "$0")/../.."

pinned() {
  python3 -c "import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"
}
kind_version="$(pinned ci/e2e/versions.yaml kindVersion)"
kind_node_version="$(pinned ci/e2e/versions.yaml kindNodeVersion)"

revision="$(git rev-parse HEAD)"
k8s="$(pinned platform/platform-versions/values.yaml k8sVersion)"
case "$k8s" in "${kind_node_version%.*}".*) ;; *)
  echo "kindest/node $kind_node_version is not on the minor of k8sVersion $k8s"
  exit 1 ;;
esac

tmp="$(mktemp -d)"
# Its own kubeconfig, so no kubectl call here can reach another cluster.
export KUBECONFIG="$tmp/kubeconfig"
kind_bin="${KIND:-$tmp/kind}"

report_state() {
  kubectl get applications -n argocd || true
  kubectl get pods -A -o wide | awk 'NR == 1 || $4 != "Completed" && split($3, r, "/") && r[1] != r[2]' || true
  kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp | tail -50 || true
  "$kind_bin" export logs kind-logs >/dev/null || true
}

# The cluster's own pulls give up after one rate-limited answer for minutes, so
# the runner pulls with retries and hands the image to the node.
preload_images() {
  local image attempt
  grep -oE 'image: *"?[^" ]+' | sed -E 's/image: *"?//' | sort -u | while read -r image; do
    for attempt in 1 2 3 4 5; do
      docker pull -q "$image" >/dev/null && "$kind_bin" load docker-image "$image" >/dev/null && break
      [ "$attempt" -lt 5 ] && sleep $((attempt * 15))
    done
  done
}

cleanup() {
  status=$?
  [ "$status" -eq 0 ] || report_state
  [ "${KEEP_CLUSTER:-0}" = 1 ] || "$kind_bin" delete cluster >/dev/null 2>&1 || true
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT

if [ -z "${KIND:-}" ]; then
  base="https://github.com/kubernetes-sigs/kind/releases/download/${kind_version}"
  (cd "$tmp" && curl -sSfLO "$base/kind-linux-amd64" -O "$base/kind-linux-amd64.sha256sum" \
    && sha256sum -c kind-linux-amd64.sha256sum && install kind-linux-amd64 kind)
fi
"$kind_bin" create cluster --config ci/e2e/kind-config.yaml \
  --image "kindest/node:${kind_node_version}" --wait 0s

# What a node's first boot installs before Argo CD takes over: both charts
# applied as plain manifests. With GENESIS_REF set, at that commit's versions,
# so a version bump is tested as the upgrade it is on every cluster. kind's own
# local-path provisioner goes, so the platform's is the only one.
genesis_versions="$tmp/genesis-versions.yaml"
if [ -n "${GENESIS_REF:-}" ]; then
  git cat-file -e "$GENESIS_REF^{commit}" 2>/dev/null || git fetch -q --depth 1 origin "$GENESIS_REF"
  git show "$GENESIS_REF:platform/platform-versions/values.yaml" > "$genesis_versions"
else
  cp platform/platform-versions/values.yaml "$genesis_versions"
fi
version() { pinned "$genesis_versions" "$1"; }
helm template cilium cilium --repo https://helm.cilium.io/ \
    --version "$(version ciliumVersion)" \
    --namespace kube-system --include-crds -f ci/e2e/genesis-cilium.yaml \
  | kubectl apply --server-side -f - >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=5m
kubectl delete storageclass standard
kubectl delete clusterrole local-path-provisioner-role
kubectl delete clusterrolebinding local-path-provisioner-bind
kubectl delete namespace local-path-storage --wait=false
kubectl create namespace argocd
helm template argocd argo-cd --repo https://argoproj.github.io/argo-helm \
    --version "$(version argocdVersion)" \
    --namespace argocd --include-crds -f ci/e2e/genesis-argocd.yaml > "$tmp/argocd.yaml"
preload_images < "$tmp/argocd.yaml"
kubectl apply --server-side -n argocd -f "$tmp/argocd.yaml" >/dev/null
kubectl -n argocd rollout status deployment,statefulset --timeout=5m

# Argo CD fetches the commit from GitHub itself, which serves it from the
# PR's merge ref even when the PR comes from a fork.
python3 ci/e2e/point-at-commit.py ci/clusters/kind.yaml "$revision" | kubectl apply -f -

# Fails as soon as something is known to be broken; the timeout is only the
# backstop for a hang.
python3 ci/e2e/wait.py 600

# Cilium's load balancer, Traefik serving the platform's wildcard certificate
# (trusted here as its own CA, being self-signed), and the platform's route to
# Argo CD.
kubectl -n traefik get secret wildcard-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "$tmp/ca.crt"
ip="$(kubectl -n traefik get service traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
curl -sSf --retry 5 --retry-all-errors --cacert "$tmp/ca.crt" \
  --resolve "argocd.kind.test:443:$ip" https://argocd.kind.test/healthz

# What the platform's own monitoring says once it's up: a scrape target that's
# down or a rule that's true from the start.
python3 ci/e2e/alerts.py 180
