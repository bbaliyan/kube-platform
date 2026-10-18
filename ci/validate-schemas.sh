#!/usr/bin/env bash
# Validate rendered manifests against the Kubernetes schemas and the CRDs the
# rendered charts ship. Usage: ci/validate-schemas.sh <rendered-dir>
set -euo pipefail

rendered="$(cd "${1:?usage: validate-schemas.sh <rendered-dir>}" && pwd)"
kubeconform_version="v$(kubeconform -v | sed 's/^v//')"
kube_version="$(python3 -c "import yaml; print(yaml.safe_load(open('platform/platform-versions/values.yaml'))['k8sVersion'].lstrip('v').split('+')[0])")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/schemas"

# Custom resources are checked against the CRDs the charts being deployed
# ship. The pinned catalog covers the system-upgrade-controller Plans, whose
# CRD the controller installs itself. Every other missing schema fails the
# check rather than being skipped.
curl -sSfL "https://raw.githubusercontent.com/yannh/kubeconform/${kubeconform_version}/scripts/openapi2jsonschema.py" -o "$work/openapi2jsonschema.py"
find "$rendered" -name 'CustomResourceDefinition_*.yaml' -print0 \
  | (cd "$work/schemas" && FILENAME_FORMAT='{fullgroup}-{kind}_{version}' xargs -0 python3 ../openapi2jsonschema.py >/dev/null)

kubeconform -strict -summary -output text \
  -kubernetes-version "$kube_version" \
  -skip CustomResourceDefinition,ClusterSecretStore \
  -schema-location default \
  -schema-location "$work/schemas/{{.Group}}-{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/63669a570e231d4f1f8396d229a1de512bcf0a34/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  "$rendered"
