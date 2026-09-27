{{/*
THE GATEWAY URL EVERY ENROLMENT TOKEN CARRIES, RESOLVED IN ONE PLACE (ADR-0808).

An adopter states the estate's hostname once, as `global.hostname` in the parent
chart. Helm hands `global` to every subchart, so this chart reads it without any
plumbing. `enrolment.gateway` resolves in this order:

  1. `enrolment.gateway`, when it is set: an explicit per-chart value still wins;
  2. `https://` + `global.hostname`, when `enrolment.gateway` is empty. NO PORT:
     the edge listener answers on 443;
  3. `https://gateway.yadgar.internal:18443`, when neither is set. That is the
     value `values.yaml` shipped before ADR-0808, so a render with no hostname
     anywhere is byte-identical to the render before it. The port is kind's
     host mapping for this organisation's development cluster, which is why it
     appears here and not in step 2.

`enrolment.gateway` defaults to empty in `values.yaml` because a non-empty
default cannot be told apart from a value somebody set, and step 1 would then
always win.

`global` MAY BE ABSENT OR NULL. This chart rendered on its own has no `global`
unless the caller passes one, and `global: null` in an overlay removes it; both
fall through to step 3.

The same order is written in `yadgarhq/platform`'s and `yadgarhq/gateway`'s
`_hostname.tpl`. The name carries this chart's prefix because helm template names
are global across the parent's whole tree, and the three must not collide.

  {{ include "iam.enrolmentGateway" (dict "local" .Values.enrolment.gateway "context" $) }}
*/}}
{{- define "iam.enrolmentGateway" -}}
{{- $global := .context.Values.global | default dict -}}
{{- $hostname := get $global "hostname" -}}
{{- if .local -}}
{{- .local -}}
{{- else if $hostname -}}
{{- printf "https://%s" $hostname -}}
{{- else -}}
https://gateway.yadgar.internal:18443
{{- end -}}
{{- end -}}
