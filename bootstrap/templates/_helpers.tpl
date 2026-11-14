{{- define "platform.nodeSelector" -}}
{{- with .Values.platformNodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{- define "platform.placement" -}}
{{- include "platform.nodeSelector" . }}
priorityClassName: platform
{{- end }}

{{/*
Second source of a component Application: the workloads repo, referenced as
$workloads so the component can read platform-values/<component>.yaml from it.
Rendered only when the cluster has a workloads repo.
*/}}
{{- define "platform.workloadsSource" -}}
repoURL: {{ .Values.workloadsRepoURL | quote }}
targetRevision: {{ .Values.workloadsRevision | quote }}
ref: workloads
{{- end }}

{{/* helm: lines that read platform-values/<component>.yaml; pass the component name. */}}
{{- define "platform.workloadsValueFile" -}}
valueFiles:
  - $workloads/platform-values/{{ . }}.yaml
ignoreMissingValueFiles: true
{{- end }}

{{/*
Pod identity (IRSA) without a webhook. The role ARN of one workload, or an empty
string when pod identity is off or that workload has no role. Pass
(dict "root" $ "role" "<key under awsPodIdentity.roles>").
*/}}
{{- define "platform.awsRole" -}}
{{- if .root.Values.awsPodIdentity.enabled -}}
{{- index .root.Values.awsPodIdentity.roles .role -}}
{{- end -}}
{{- end }}

{{/* The projected token the workload exchanges for AWS credentials. */}}
{{- define "platform.awsTokenVolume" -}}
- name: aws-pod-identity
  projected:
    sources:
      - serviceAccountToken:
          audience: sts.amazonaws.com
          expirationSeconds: 86400
          path: token
{{- end }}

{{- define "platform.awsTokenMount" -}}
- name: aws-pod-identity
  mountPath: /var/run/secrets/aws-pod-identity
  readOnly: true
{{- end }}

{{/* Env list items for a workload; pass (dict "root" $ "role" "<ARN>"). */}}
{{- define "platform.awsTokenEnv" -}}
- name: AWS_ROLE_ARN
  value: {{ .role | quote }}
- name: AWS_WEB_IDENTITY_TOKEN_FILE
  value: /var/run/secrets/aws-pod-identity/token
- name: AWS_REGION
  value: {{ required "awsRegion must be set when awsPodIdentity is enabled" .root.Values.awsRegion | quote }}
{{- end }}
