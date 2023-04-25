package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/afdesk/trivy-go-plugin/pkg/common"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	tempJsonFileName = "csv-report-temp.json"
	templateFileName = "csv.tpl"
)

func init() {
	var CustomTemplateFuncMap = map[string]interface{}{
		"escapeCsv": func(input string) string {
			quoted := strconv.Quote(input)
			return strings.ReplaceAll(quoted, "\\\"", "\"\"")
		},
		"escapeString": func(input string) dbTypes.SourceID {
			return dbTypes.SourceID(input)
		},
		"nvdV3Score": func(input dbTypes.VendorCVSS) float64 {
			return input["nvd"].V3Score
		},
		"rhV3Score": func(input dbTypes.VendorCVSS) float64 {
			return input["redhat"].V3Score
		},
		"nvdV3Vector": func(input dbTypes.VendorCVSS) string {
			return input["nvd"].V3Vector
		},
		"rhV3Vector": func(input dbTypes.VendorCVSS) string {
			return input["redhat"].V3Vector
		},
	}
	report.CustomTemplateFuncMap = CustomTemplateFuncMap
}
func main() {
	trivyCommand := os.Args[1 : len(os.Args)-1]
	outputFileName := os.Args[len(os.Args)-1]
	tempFileName := filepath.Join(os.TempDir(), tempJsonFileName)
	defer removeFile(tempFileName)

	if err := common.MakeTrivyJsonReport(trivyCommand, tempFileName); err != nil {
		log.Fatalf("failed to make trivy json report: %v", err)
	}

	jsonReport, err := getReportFromJson(tempFileName)
	if err != nil {
		log.Fatalf("failed to extract jsonReport from json: %v", err)
	}

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("failed to create file %v", err)
	}
	defer closeFile(outputFile)

	templatePath, err := common.GetPathToTemplate(templateFileName)
	if err != nil {
		log.Fatalf("failed to get template path: %v", err)
	}

	writer, err := report.NewTemplateWriter(outputFile, templatePath)
	if err != nil {
		log.Fatalf("failed to initialize template writer: %v", err)
	}
	if err := writer.Write(*jsonReport); err != nil {
		log.Fatalf("failed to write results: %v", err)
	}
}

func getReportFromJson(jsonFileName string) (*types.Report, error) {
	if !common.IsK8s() {
		return readJson[types.Report](jsonFileName)
	}

	k8sParsedReport, err := readJson[k8sReport.Report](jsonFileName)
	if err != nil {
		return nil, err
	}

	var resultsArr types.Results
	for _, vuln := range k8sParsedReport.Vulnerabilities {
		resultsArr = append(resultsArr, vuln.Results...)
	}
	for _, misc := range k8sParsedReport.Misconfigurations {
		resultsArr = append(resultsArr, misc.Results...)
	}
	rep := types.Report{
		Results: resultsArr,
	}
	return &rep, nil
}

func readJson[T any](jsonFileName string) (*T, error) {
	jsonFile, err := os.Open(jsonFileName)
	if err != nil {
		return nil, err
	}

	defer closeFile(jsonFile)

	var out T
	if err := json.NewDecoder(jsonFile).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func removeFile(file string) {
	if err := os.Remove(file); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}
func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}
