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
