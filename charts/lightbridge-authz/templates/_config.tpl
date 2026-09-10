{{/*
=======================================================================================
  lightbridge.config.render — ONE config, many components.
=======================================================================================

  Renders a component's `/etc/lightbridge/config.yaml` from a single shared config OBJECT
  plus that component's own overrides, instead of every component carrying a full copy of
  the same YAML string.

  Why this exists
  ---------------
  The stack chart deploys the same binary six ways (api / opa / idp / budget aliases of
  charts/lightbridge-authz, plus charts/lightbridge-mcp and charts/lightbridge-authz-usage).
  Every one of them mounts a `config.yaml` whose oauth2 signing + claim_mappers, rbac
  role_permissions, database, federation and otel blocks are IDENTICAL. Helm gives an
  umbrella chart no way to write a value once and have every ALIAS see it — except
  `global`. So a values repo that overrides `configMaps.config.data.config.yaml` per
  component ends up maintaining N byte-identical copies, and every policy change (a new
  role permission, a new claim mapper) has to be applied N times, by hand, in N places.
  That is exactly what happened to ai-helm-values' `lightbridge-app.yaml`.

  The contract
  ------------
    global:
      lightbridge:
        sharedConfig:            # the ONE source of truth. Operator-supplied.
          oauth2: {...}          # A plain YAML OBJECT — never a string.
          database: {...}

    <component>:
      configOverrides: {}        # merged OVER sharedConfig (mergeOverwrite: maps merge
                                 # recursively, scalars and LISTS are replaced wholesale)
      configOmit: []             # dotted paths deleted AFTER the merge, for blocks a
                                 # component must NOT see at all (a merge can add a key,
                                 # it can never remove one)

  Precedence, and why `sharedConfig` REPLACES rather than merges
  --------------------------------------------------------------
  `global.lightbridge.sharedConfig` wins outright over this chart's own `.Values.sharedConfig`
  default when it is non-empty — it is NOT deep-merged with it. Helm would otherwise
  deep-merge the operator's object into this chart's dev-shaped placeholders and silently
  leak values like `oauth2.relying_party.state_encryption_key` ("AAAA…", a documented
  local-dev key) into a production render, for every key the operator did not happen to
  restate. The operator's config is authoritative or it is not used at all. `.Values.sharedConfig`
  is the standalone/dev default, so `helm install charts/lightbridge-authz` alone still
  produces a working local-dev deployment.

  Templating inside the config
  ----------------------------
  The merged object is passed through `tpl`, so values may contain Helm expressions (this
  preserves the pre-existing behaviour — bjw-s/common already ran `tpl` over the whole
  ConfigMap `data` map, and charts/lightbridge-mcp relies on it for
  `server.api.allowed_hosts`).

  Env placeholders
  ----------------
  The backend's config loader (`interpolate_env_vars`,
  crates/lightbridge-authz-core/src/config/mod.rs) substitutes `$VAR`, `${VAR}`,
  `${VAR-default}` and `${VAR:-default}` TEXTUALLY, before the YAML is parsed. `toYaml`
  emits such a value as an UNQUOTED plain scalar (`password: ${OPA_PASSWORD}`), so a secret
  containing a YAML metacharacter (`#`, `%`, a leading `*`/`&`/`!`, `: `) would corrupt the
  document at parse time — the hand-written strings this replaces were quoted by hand.
  The two `regexReplaceAll` passes below restore that quoting for exactly the scalars that
  carry a placeholder. Known limitation: a `key: ${VAR}` line appearing INSIDE a literal
  block scalar would also be quoted; no such value exists in this stack.
*/}}
{{- define "lightbridge.config.render" -}}
  {{- $ctx := . -}}
  {{- $shared := dig "lightbridge" "sharedConfig" dict ($ctx.Values.global | default dict) -}}
  {{- if empty $shared -}}
    {{- $shared = ($ctx.Values.sharedConfig | default dict) -}}
  {{- end -}}
  {{- $merged := mergeOverwrite (deepCopy $shared) (deepCopy ($ctx.Values.configOverrides | default dict)) -}}

  {{- /* Delete the dotted paths this component must not see. */ -}}
  {{- range $path := ($ctx.Values.configOmit | default list) -}}
    {{- $parts := splitList "." $path -}}
    {{- $cursor := $merged -}}
    {{- $reachable := true -}}
    {{- range $segment := (initial $parts) -}}
      {{- if and $reachable (kindIs "map" $cursor) (hasKey $cursor $segment) -}}
        {{- $cursor = index $cursor $segment -}}
      {{- else -}}
        {{- $reachable = false -}}
      {{- end -}}
    {{- end -}}
    {{- if and $reachable (kindIs "map" $cursor) -}}
      {{- $_ := unset $cursor (last $parts) -}}
    {{- end -}}
  {{- end -}}

  {{- $yaml := tpl (toYaml $merged) $ctx -}}
  {{- $yaml = regexReplaceAll "(?m)^([ \t]*(?:- )?[A-Za-z0-9_.\\-/]+: )((?:[^\"'|>\n][^\n]*)?\\$(?:\\{[^}\n]+\\}|[A-Za-z_][A-Za-z0-9_]*)[^\n]*)$" $yaml "${1}\"${2}\"" -}}
  {{- $yaml = regexReplaceAll "(?m)^([ \t]*- )((?:[^\"'|>\n][^\n]*)?\\$(?:\\{[^}\n]+\\}|[A-Za-z_][A-Za-z0-9_]*)[^\n]*)$" $yaml "${1}\"${2}\"" -}}
  {{- $yaml -}}
{{- end -}}

{{/*
  lightbridge.config.checksum — a stable hash of the config a component actually MOUNTS.

  `controllers.migrate.suffix` folds the mounted config into the migrate Job's name so a
  config-only change mints a new Job instead of colliding with a completed one's immutable
  spec.template (see the long comment on `controllers.migrate` in values.yaml, and #480).
  That suffix used to hash `configMaps.config.data` raw. That value is now a fixed one-line
  template — identical for every possible config — so hashing it raw would mint one Job name
  forever and re-run #480.

  This renders the ConfigMap's data exactly the way bjw-s/common does (`tpl` over the whole
  `data` map, classes/_configmap.tpl:33) and hashes THAT. Deliberately not
  `lightbridge.config.render` directly: a deployment is still free to set
  `configMaps.config.data` to a literal string, and the hash has to follow the bytes that end
  up in the pod either way.
*/}}
{{- define "lightbridge.config.checksum" -}}
{{- tpl (toYaml .Values.configMaps.config.data) . | sha256sum -}}
{{- end -}}
