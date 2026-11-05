{{/* A component's own storage class, else the shared one. Empty = the cluster default. */}}
{{- define "platform.storageClassName" -}}
{{- .own | default .shared -}}
{{- end }}

{{- define "platform.nodeSelector" -}}
{{- with .Values.platformNodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
The metricRelabelings list of one control-plane ServiceMonitor: the chart's own
defaults, then one rule that drops the preset's regexes and extraDropMetrics.
*/}}
{{- define "platform.controlPlaneMetricRelabelings" -}}
{{- $data := .root.Files.Get "drop-unused-control-plane-metrics.yaml" | fromYaml -}}
{{- $regexes := list -}}
{{- if .root.Values.prometheus.dropUnusedControlPlaneMetrics -}}
{{- $regexes = concat $data.all (get $data .component) -}}
{{- if ne .component "kubeEtcd" -}}
{{- $regexes = concat $regexes $data.kubernetes -}}
{{- end -}}
{{- end -}}
{{- $regexes = concat $regexes (.root.Values.prometheus.extraDropMetrics | default list) -}}
{{- $rules := concat (get $data.chartDefaults .component | default list) (list (dict "action" "drop" "sourceLabels" (list "__name__") "regex" (join "|" $regexes))) -}}
{{- toYaml $rules -}}
{{- end }}

{{/* True when any control-plane drop rule is wanted. */}}
{{- define "platform.dropsControlPlaneMetrics" -}}
{{- if or .Values.prometheus.dropUnusedControlPlaneMetrics .Values.prometheus.extraDropMetrics -}}true{{- end -}}
{{- end }}
