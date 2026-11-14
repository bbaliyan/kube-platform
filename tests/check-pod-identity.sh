#!/usr/bin/env bash
# Renders the bootstrap chart with and without awsPodIdentity and checks the
# AWS credential wiring of each workload: a projected token and env, no env
# for a workload without a role, and nothing at all when the switch is off.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

base=(
  --set awsRegion=eu-west-1 --set clusterName=c1 --set certMode=byo
  --set secretStoreType=aws-ssm --set clusterAutoscalerEnabled=true
  --set externalDnsEnabled=true --set externalDnsDomainFilter=x.internal --set dnsOwnerId=c1-eu
  --set 'storageProvisioners[0].name=ebs' --set 'storageProvisioners[0].type=aws-ebs'
)
roles=(
  --set awsPodIdentity.enabled=true
  --set awsPodIdentity.roles.ebsCsi=arn:aws:iam::example:role/ebs
  --set awsPodIdentity.roles.clusterAutoscaler=arn:aws:iam::example:role/ca
  --set awsPodIdentity.roles.externalDns=arn:aws:iam::example:role/dns
  --set awsPodIdentity.roles.externalSecrets=arn:aws:iam::example:role/eso
)

render() { # extra helm flags; writes {application name: its helm values} as JSON to $work/out
  local status=0
  helm template platform "$root/bootstrap" \
    --values "$root/platform/platform-versions/values.yaml" "${base[@]}" "$@" \
    >"$work/rendered" 2>"$work/err" || status=$?
  python3 - "$work/rendered" >"$work/out" <<'PY'
import json, sys, yaml
apps = {}
for d in yaml.safe_load_all(open(sys.argv[1])):
    if isinstance(d, dict) and d.get("kind") == "Application":
        helm = d["spec"].get("source", {}).get("helm", {})
        values = helm.get("valuesObject") or yaml.safe_load(helm.get("values", "")) or {}
        values["_parameters"] = {p["name"]: p["value"] for p in helm.get("parameters", [])}
        apps[d["metadata"]["name"]] = values
print(json.dumps(apps))
PY
  [ "$status" -eq 0 ] || cat "$work/err" >&2
  return "$status"
}

expect() { # name, python expression on `apps` that must be true
  if python3 -c "import json, sys; apps = json.load(open(sys.argv[1])); sys.exit(0 if ($2) else 1)" "$work/out"; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    cat "$work/out" "$work/err"
    failures=$((failures + 1))
  fi
}

ebs="apps['storage-provisioner-ebs']['aws-ebs-csi-driver']"
render
expect "off: no AWS token env or volume anywhere" \
  "'AWS_ROLE_ARN' not in json.dumps(apps) and 'aws-pod-identity' not in json.dumps(apps)"
expect "off: the EBS driver keeps its metadata sources" "'node' not in $ebs"
expect "off: the secret stores get no pod identity" \
  "apps['argocd-repo-creds']['_parameters']['awsPodIdentity'] == 'false' and apps['pki-issuer']['_parameters']['awsPodIdentity'] == 'false'"
expect "off: external-secrets has no role annotation" "'serviceAccount' not in apps['external-secrets']"

render "${roles[@]}"
expect "on: EBS controller has the role, token file and region" \
  "{e['name']: e['value'] for e in ${ebs}['controller']['env']} == {'AWS_ROLE_ARN': 'arn:aws:iam::example:role/ebs', 'AWS_WEB_IDENTITY_TOKEN_FILE': '/var/run/secrets/aws-pod-identity/token', 'AWS_REGION': 'eu-west-1'}"
expect "on: EBS controller mounts a projected token for sts.amazonaws.com" \
  "${ebs}['controller']['volumes'][0]['projected']['sources'][0]['serviceAccountToken']['audience'] == 'sts.amazonaws.com' and ${ebs}['controller']['volumeMounts'][0]['mountPath'] == '/var/run/secrets/aws-pod-identity'"
expect "on: EBS node reads metadata from Kubernetes" "${ebs}['node']['metadataSources'] == 'kubernetes'"
expect "on: cluster-autoscaler has the role and token file" \
  "apps['cluster-autoscaler']['extraEnv'] == {'AWS_ROLE_ARN': 'arn:aws:iam::example:role/ca', 'AWS_WEB_IDENTITY_TOKEN_FILE': '/var/run/secrets/aws-pod-identity/token'} and apps['cluster-autoscaler']['extraVolumes'][0]['name'] == 'aws-pod-identity'"
expect "on: external-dns has the role and token file" \
  "{e['name']: e['value'] for e in apps['external-dns']['env']}['AWS_ROLE_ARN'] == 'arn:aws:iam::example:role/dns' and apps['external-dns']['extraVolumeMounts'][0]['name'] == 'aws-pod-identity'"
expect "on: external-secrets service account carries the role" \
  "apps['external-secrets']['serviceAccount']['annotations'] == {'eks.amazonaws.com/role-arn': 'arn:aws:iam::example:role/eso'}"
expect "on: the secret stores use pod identity" \
  "apps['argocd-repo-creds']['_parameters']['awsPodIdentity'] == 'true' and apps['pki-issuer']['_parameters']['awsPodIdentity'] == 'true'"

render --set awsPodIdentity.enabled=true --set awsPodIdentity.roles.externalDns=arn:aws:iam::example:role/dns
expect "on, one role: only that workload gets env" \
  "'AWS_ROLE_ARN' in json.dumps(apps['external-dns']) and 'AWS_ROLE_ARN' not in json.dumps({k: v for k, v in apps.items() if k != 'external-dns'})"
expect "on, one role: the other workloads are unchanged" \
  "'node' not in $ebs and 'serviceAccount' not in apps['external-secrets'] and apps['argocd-repo-creds']['_parameters']['awsPodIdentity'] == 'false'"

render --set awsPodIdentity.roles.ebsCsi=arn:aws:iam::example:role/ebs
expect "roles without the switch change nothing" "'AWS_ROLE_ARN' not in json.dumps(apps)"

[ "$failures" -eq 0 ]
