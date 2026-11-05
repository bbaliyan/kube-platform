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
