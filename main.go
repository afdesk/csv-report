package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
	scanType := trivyCommand[0]
	outputFileName := os.Args[len(os.Args)-1]

	tempDir := os.TempDir()
	tempFile, err := os.CreateTemp(tempDir, tempJsonFileName)
	if err != nil {
		log.Fatalf("failed to create temp file: %v", err)
	}
	defer removeAndCloseFile(tempFile)

	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempFile.Name())
	if err := exec.Command("trivy", cmdArgs...).Run(); err != nil {
		log.Fatalf("failed to build report: %v", err)
	}

	jsonReport, err := getReportFromJson(scanType, tempFile)
	if err != nil {
		log.Fatalf("failed to extract jsonReport from json: %v", err)
	}
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("failed to create file %v", err)
	}

	writer, err := report.NewTemplateWriter(outputFile, getPathToTemplate())
	if err != nil {
		log.Fatalf("failed to initialize template writer: %v", err)
	}
	if err := writer.Write(*jsonReport); err != nil {
		log.Fatalf("failed to write results: %v", err)
	}
}

func getReportFromJson(scanType string, jsonFile *os.File) (*types.Report, error) {
	if scanType != "k8s" {
		return readJson[types.Report](jsonFile)
	}

	k8sParsedReport, err := readJson[k8sReport.Report](jsonFile)
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

func readJson[T any](jsonFile *os.File) (*T, error) {
	var out T
	if err := json.NewDecoder(jsonFile).Decode(&out); err != nil {
		log.Fatalf("failed to open file %v", err)
	}
	return &out, nil
}

func getPathToTemplate() string {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	absolutePath := filepath.Join(exPath, templateFileName)
	return "@" + absolutePath
}

func removeAndCloseFile(file *os.File) {
	if err := os.Remove(file.Name()); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}

	if err := file.Close(); err != nil {
		log.Fatalf("failed to close file %v", err)
	}
}
