{{- define "platform.nodeSelector" -}}
{{- with .Values.platformNodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
