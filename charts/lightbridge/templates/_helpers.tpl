{{/*
Expand the name of the chart.
*/}}
{{- define "lightbridge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the fully qualified app name.
*/}}
{{- define "lightbridge.fullname" -}}
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

{{- define "lightbridge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge.globalConfigMapName" -}}
{{- if .Values.global.configMapName }}
{{- .Values.global.configMapName }}
{{- else }}
{{- printf "%s-config" (include "lightbridge.fullname" .) }}
{{- end }}
{{- end }}

{{- define "lightbridge.globalTlsSecretName" -}}
{{- if .Values.global.tlsSecretName }}
{{- .Values.global.tlsSecretName }}
{{- else }}
{{- printf "%s-tls" (include "lightbridge.fullname" .) }}
{{- end }}
{{- end }}

{{- define "lightbridge.globalTlsJobName" -}}
{{- printf "%s-global-tls" (include "lightbridge.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge.globalTlsJobSAName" -}}
{{- printf "%s-global-tls-sa" (include "lightbridge.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge.globalTlsJobRoleName" -}}
{{- printf "%s-global-tls-role" (include "lightbridge.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge.globalTlsJobRoleBindingName" -}}
{{- printf "%s-global-tls-rolebinding" (include "lightbridge.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
