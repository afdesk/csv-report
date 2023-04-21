{{ printf getAvailableFields }}
{{ range . }}
{{- $target := .Target }}
{{- $class := .Class }}
{{- $vulnerabilityType := .Type }}
{{- if (and (eq (len .Vulnerabilities) 0) (eq (len .Misconfigurations) 0)) -}}
	{{- $target | escapeCsv }},{{ printf "%s" $class | escapeCsv }},{{ $vulnerabilityType | escapeCsv }},"","","","","","","","","","","",""
{{- else -}}
{{- range .Vulnerabilities }}
	{{- if isFieldAvailable "Target" }}
	    {{- $target | escapeCsv }},
	{{- end }}
	{{- if isFieldAvailable "Vulnerability Class" }}
	    {{- printf "%s" $class | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Target Type" }}
	    {{- $vulnerabilityType | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Vulnerability ID" }}
	    {{- .VulnerabilityID | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Severity" }}
	    {{- .Vulnerability.Severity | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "PackageName" }}
	    {{- .PkgName | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Installed Version" }}
	    {{- .InstalledVersion | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Fixed Version" }}
        {{- .FixedVersion | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Title" }}
        {{- if (eq (len .Title) 0) }}
            {{- printf "%s: %s - %s severity vulnerability" .PkgName .InstalledVersion .Vulnerability.Severity | escapeCsv }},
        {{- else }}
            {{- abbrev 100 .Title | escapeCsv }},
        {{- end }}
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Description" }}
	    {{- abbrev 500 .Vulnerability.Description | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Resolution" }}
        {{- if .FixedVersion }}
            {{- printf "Update %s to version %s or higher." .PkgName .FixedVersion | escapeCsv }},
        {{- else }}
            {{- printf "No resolution provided." | escapeCsv }},
        {{- end }}
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Reference" }}
	    {{- .PrimaryURL | escapeCsv }},
    {{- else -}}
	{{- end }}
	{{- if isFieldAvailable "Additional Reference" }}
        {{- $reference := false }}
        {{- range .References }}
            {{- if contains "nvd.nist.gov" . }}
                {{- . | escapeCsv }}
                {{- $reference = true }}
            {{- end }}
        {{- end }}
        {{- if not $reference }}
            {{- printf "" | escapeCsv }}
        {{- end }},
    {{- else -}}
	{{- end }}

	{{- $cvss := .CVSS | nvdV3Score -}}
	{{- $cvssRH := .CVSS | rhV3Score -}}
	{{- if $cvss }}

	{{- if isFieldAvailable "CVSS V3 Score" }}
            {{- $cvss | printf "%.1f" | escapeCsv  -}},
		    {{- end }}
	{{- if isFieldAvailable "CVSS V3 Vector" }}
            {{- .CVSS | nvdV3Vector | escapeCsv }}
		    {{- end }}
	{{- else if $cvssRH }}
	{{- if isFieldAvailable "CVSS V3 Score" }}
		    {{- $cvssRH | printf "%.1f" | escapeCsv -}},
		    {{- end }}
	{{- if isFieldAvailable "CVSS V3 Vector" }}
		    {{- .CVSS | rhV3Vector | escapeCsv }}
		    {{- end }}
	{{- end }}
{{ end }}
{{- range .Misconfigurations }}
	{{- $target | escapeCsv }},
	{{- printf "%s" $class | escapeCsv }},
	{{- $vulnerabilityType | escapeCsv }},
	{{- .ID | escapeCsv }},
	{{- .Severity | escapeCsv }},"","","",
	{{- abbrev 100 .Title | escapeCsv }},
	{{- printf "%s - %s" .Description .Message | abbrev 500 | escapeCsv }},
	{{- .Resolution | escapeCsv }},
	{{- .PrimaryURL | escapeCsv }},
	{{- $reference := false }}
	{{- range .References }}
		{{- if contains "docs.docker.com" . }}
			{{- . | escapeCsv }}
			{{- $reference = true }}
		{{- end }}
	{{- end }}
	{{- if not $reference }}
		{{- printf "" | escapeCsv }}
	{{- end }},"",""
{{ end }}
{{- end }}
{{- end -}}