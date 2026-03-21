{{/*
Expand the name of the chart.
*/}}
{{- define "vouch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "vouch.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "vouch.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vouch.labels" -}}
helm.sh/chart: {{ include "vouch.chart" . }}
{{ include "vouch.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vouch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vouch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "vouch.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vouch.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Static name for the internal CouchDB config
*/}}
{{- define "vouch.couchdb.configName" -}}
vouch-internal-header-config
{{- end -}}

{{/*
Constants for Vouch headers
*/}}
{{- define "vouch.userNameHeader" -}}
X-Vouch-UserName
{{- end -}}
{{- define "vouch.rolesHeader" -}}
X-Vouch-Roles
{{- end -}}

{{/*
Environment variables for the Vouch container
*/}}
{{- define "vouch.env" -}}
- name: VOUCH_LOG_LEVEL
  value: {{ .Values.vouch.config.logLevel | quote }}
- name: VOUCH_LOG_FORMAT
  value: {{ .Values.vouch.config.logFormat | quote }}
- name: VOUCH_HOST
  value: {{ .Values.vouch.config.host | quote }}
- name: VOUCH_PORT
  value: {{ .Values.vouch.config.port | quote }}
- name: VOUCH_TARGET
  value: {{ tpl .Values.vouch.config.target . | quote }}
- name: VOUCH_TOKEN_ROLES_CLAIM
  value: {{ .Values.vouch.config.tokenRolesClaim | quote }}
- name: VOUCH_USER_NAME_HEADER
  value: {{ include "vouch.userNameHeader" . | quote }}
- name: VOUCH_ROLES_HEADER
  value: {{ include "vouch.rolesHeader" . | quote }}
- name: VOUCH_KEYS_URL
  value: {{ required "A JWKS URL is required" .Values.vouch.config.keys.url | quote }}
- name: VOUCH_KEYS_TIMEOUT
  value: {{ .Values.vouch.config.keys.timeout | quote }}
- name: VOUCH_KEYS_MIN_REFRESH_INTERVAL
  value: {{ .Values.vouch.config.keys.minRefreshInterval | quote }}
- name: VOUCH_KEYS_MAX_REFRESH_INTERVAL
  value: {{ .Values.vouch.config.keys.maxRefreshInterval | quote }}
{{- if .Values.vouch.config.token.issuers }}
- name: VOUCH_TOKEN_ISSUERS
  value: {{ .Values.vouch.config.token.issuers | join "," | quote }}
{{- end }}
{{- if .Values.vouch.config.token.audiences }}
- name: VOUCH_TOKEN_AUDIENCES
  value: {{ .Values.vouch.config.token.audiences | join "," | quote }}
{{- end }}
{{- end -}}

{{/*
CouchDB configuration
*/}}
{{- define "vouch.couchdb.extraIni" -}}
10-vouch.ini: |
  [httpd]
  authentication_handlers = {chttpd_auth, proxy_authentication_handler}, {chttpd_auth, default_authentication_handler}

  [chttpd_auth]
  x_auth_username = {{ include "vouch.userNameHeader" . }}
  x_auth_roles = {{ include "vouch.rolesHeader" . }}
{{- end -}}
