{{ printf getAvailableFields }}
{{ range . }}
    {{- getVulnerabilitiesTable . | printf }}
    {{- getMisconfigurationTable . | printf }}
{{- end -}}