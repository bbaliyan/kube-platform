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
