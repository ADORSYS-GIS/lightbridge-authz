{{/*
Expand the name of the chart.
*/}}
{{- define "lightbridge-authz.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "lightbridge-authz.fullname" -}}
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
{{- define "lightbridge-authz.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge-authz.labels" -}}
helm.sh/chart: {{ include "lightbridge-authz.chart" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "lightbridge-authz.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lightbridge-authz.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/controller: {{ include "lightbridge-authz.controllerName" . }}
{{- end }}

{{- define "lightbridge-authz.controllerName" -}}
{{- printf "%s-controller" (include "lightbridge-authz.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge-authz.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "lightbridge-authz.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "lightbridge-authz.configMapName" -}}
{{- if .Values.configMap.name }}
{{- .Values.configMap.name }}
{{- else if and .Values.global .Values.global.configMapName }}
{{- .Values.global.configMapName }}
{{- else if and .Values.global .Values.global.configMapNameTemplate }}
{{- tpl .Values.global.configMapNameTemplate . }}
{{- else }}
{{- printf "%s-config" (include "lightbridge-authz.fullname" .) }}
{{- end }}
{{- end }}

{{- define "lightbridge-authz.tlsSecretName" -}}
{{- if .Values.tls.secretName }}
{{- .Values.tls.secretName }}
{{- else if and .Values.global .Values.global.tlsSecretName }}
{{- .Values.global.tlsSecretName }}
{{- else if and .Values.global .Values.global.tlsSecretNameTemplate }}
{{- tpl .Values.global.tlsSecretNameTemplate . }}
{{- else }}
{{- printf "%s-tls" (include "lightbridge-authz.fullname" .) }}
{{- end }}
{{- end }}

{{- define "lightbridge-authz.tlsJobName" -}}
{{- printf "%s-tls-job" (include "lightbridge-authz.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge-authz.tlsJobServiceAccountName" -}}
{{- if .Values.tls.job.serviceAccount.name }}
{{- .Values.tls.job.serviceAccount.name }}
{{- else }}
{{- printf "%s-tls-job-sa" (include "lightbridge-authz.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "lightbridge-authz.tlsJobRoleName" -}}
{{- if .Values.tls.job.role.name }}
{{- .Values.tls.job.role.name }}
{{- else }}
{{- printf "%s-tls-job-role" (include "lightbridge-authz.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "lightbridge-authz.tlsJobRoleBindingName" -}}
{{- printf "%s-tls-job-rolebinding" (include "lightbridge-authz.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lightbridge-authz.useKnative" -}}
{{- .Capabilities.APIVersions.Has "serving.knative.dev/v1" -}}
{{- end }}

{{- define "lightbridge-authz.shouldUseKnative" -}}
{{- and (include "lightbridge-authz.useKnative" .) .Values.knative.enabled -}}
{{- end }}

{{- define "lightbridge-authz.mergeEnv" -}}
{{- $configPath := .configPath -}}
{{- $configFile := .configFile -}}
{{- $extra := .extra -}}
{{- $default := list (dict "name" "CONFIG_PATH" "value" (printf "%s/%s" $configPath $configFile)) -}}
{{- $envList := $default -}}
{{- if $extra -}}
  {{- if kindIs "slice" $extra -}}
    {{- range $item := $extra -}}
      {{- $envList = append $envList $item -}}
    {{- end -}}
  {{- else if kindIs "map" $extra -}}
    {{- range $name, $value := $extra -}}
      {{- $entry := dict "name" $name -}}
      {{- if kindIs "map" $value -}}
        {{- $entry = merge $entry $value -}}
      {{- else -}}
        {{- $entry = merge $entry (dict "value" $value) -}}
      {{- end -}}
      {{- $envList = append $envList $entry -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- $envList -}}
{{- end }}
