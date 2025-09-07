{{- define "vouch.fullname" -}}
{{- include "vouch.name" . }}-{{ .Release.Name }}
{{- end }}

{{- define "vouch.name" -}}
{{- .Chart.Name | trunc 40 | trimSuffix "-" -}}
{{- end }}

{{- define "vouch.config" -}}
proxy:
  listen: {{ default "" .Values.proxy.listen | quote }}
  target: {{ default "" .Values.proxy.target | quote }}
  headers:
    secret: {{ default "" .Values.proxy.headers.secret | quote }}
    user: {{ default "" .Values.proxy.headers.user | quote }}
    roles: {{ default "" .Values.proxy.headers.roles | quote }}
    token: {{ default "" .Values.proxy.headers.token | quote }}
    anonymous: {{ default false .Values.proxy.headers.anonymous }}
token:
  keys:
    static: /app/jwks.json
    remote:
      endpoint: {{ default "" .Values.token.keys.remote.endpoint | quote }}
      interval: {{ default 0 .Values.token.keys.remote.interval }}
rules:
{{- range .Values.rules }}
  - when: {{ .when | quote }}
    mode: {{ .mode | quote }}
    user: {{ .user | quote }}
    roles: {{ .roles | quote }}
{{- end }}
{{- end }}
