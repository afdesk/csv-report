package main

import (
	"bytes"
	"encoding/xml"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"io"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"

	"golang.org/x/xerrors"
)

// CustomTemplateFuncMap is used to overwrite existing functions for testing.
var CustomTemplateFuncMap = map[string]interface{}{}

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate string) (*TemplateWriter, error) {
	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := os.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			return nil, xerrors.Errorf("error retrieving template from path: %w", err)
		}
		outputTemplate = string(buf)
	}
	var templateFuncMap template.FuncMap
	templateFuncMap = sprig.GenericFuncMap()
	templateFuncMap["escapeXML"] = func(input string) string {
		escaped := &bytes.Buffer{}
		if err := xml.EscapeText(escaped, []byte(input)); err != nil {
			//log.Logger.Error("error while escapeString to XML: %s", err)
			return input
		}
		return escaped.String()
	}
	templateFuncMap["endWithPeriod"] = func(input string) string {
		if !strings.HasSuffix(input, ".") {
			input += "."
		}
		return input
	}
	templateFuncMap["escapeString"] = func(input string) dbTypes.SourceID {
		return dbTypes.SourceID(input)
	}
	templateFuncMap["nvdV3Score"] = func(input dbTypes.VendorCVSS) float64 {
		return input["nvd"].V3Score
	}
	templateFuncMap["rhV3Score"] = func(input dbTypes.VendorCVSS) float64 {
		return input["redhat"].V3Score
	}
	templateFuncMap["nvdV3Vector"] = func(input dbTypes.VendorCVSS) string {
		return input["nvd"].V3Vector
	}
	templateFuncMap["rhV3Vector"] = func(input dbTypes.VendorCVSS) string {
		return input["redhat"].V3Vector
	}
	templateFuncMap["escapeCsv"] = func(input string) string {
		// First we safely double-quote the string
		quoted := strconv.Quote(input)
		// Then we encode escaped double-quotes \" as "" according to RFC4180
		return strings.ReplaceAll(quoted, "\\\"", "\"\"")
	}
	// Overwrite functions
	for k, v := range CustomTemplateFuncMap {
		templateFuncMap[k] = v
	}

	tmpl, err := template.New("output template").Funcs(templateFuncMap).Parse(outputTemplate)
	if err != nil {
		return nil, xerrors.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{Output: output, Template: tmpl}, nil
}

// Write writes result
func (tw TemplateWriter) Write(results types.Results) error {
	err := tw.Template.Execute(tw.Output, results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}

type Writer interface {
	Write(types.Results) error
}
