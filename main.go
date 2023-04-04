package main

import (
	"encoding/json"
	"io"
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
	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempJsonFileName)
	cmd := exec.Command("trivy", cmdArgs...)

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to build report: %v", err)
	}
	jsonReport, err := getReportFromJson(scanType, tempJsonFileName)
	if err != nil {
		log.Fatalf("failed to extract jsonReport from json: %v", err)
	}
	outputFile, err := createFile(outputFileName)
	if err != nil {
		log.Fatalf("failed to create file %v", err)
	}
	defer removeTempFile()
	writer, err := report.NewTemplateWriter(outputFile, getPathToTemplate())
	if err != nil {
		log.Fatalf("failed to initialize template writer: %v", err)
	}
	if err := writer.Write(*jsonReport); err != nil {
		log.Fatalf("failed to write results: %v", err)
	}
}

func getReportFromJson(scanType string, jsonFileName string) (*types.Report, error) {
	if scanType != "k8s" {
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

func createFile(fileName string) (outputFile io.Writer, err error) {
	outputFile, err = os.Create(fileName)
	if err != nil {
		return nil, err
	}
	return outputFile, nil
}

func readJson[T any](fileName string) (*T, error) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("failed to open file %v", err)
	}

	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			log.Fatalf("failed to close json file %v", err)
		}
	}(file)

	var out T
	if err := json.NewDecoder(file).Decode(&out); err != nil {
		log.Fatalf("failed to open file %v", err)
	}
	return &out, nil
}

func joinBaseDir(filename string) string {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	absolutePath := filepath.Join(exPath, filename)
	return absolutePath
}

func getPathToTemplate() string {
	absolutePath := joinBaseDir(templateFileName)
	return "@" + absolutePath
}

func removeTempFile() {
	absolutePath := joinBaseDir(tempJsonFileName)
	if _, err := os.Stat(absolutePath); err == nil {
		_ = os.Remove(absolutePath)
	}
}
