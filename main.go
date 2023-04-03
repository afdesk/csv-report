package main

import (
	"encoding/json"
	"fmt"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	tempJson     = "csv-report-temp.json"
	templateFile = "@csv.tpl"
)
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

func main() {
	report.CustomTemplateFuncMap = CustomTemplateFuncMap
	trivyCommand := os.Args[1 : len(os.Args)-1]
	scanType := trivyCommand[0]
	outputFileName := os.Args[len(os.Args)-1]
	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempJson)
	cmd := exec.Command("trivy", cmdArgs...)
	cmdErr := cmd.Run()
	if cmdErr != nil {
		log.Fatal(xerrors.Errorf("failed to build report: %w", cmdErr))
	}
	jsonReport, getResultsError := getReportFromJson(scanType, tempJson)
	if getResultsError != nil {
		log.Fatal(xerrors.Errorf("failed to extract jsonReport from json: %w", getResultsError))
	}
	outputFile, createFileError := createFile(outputFileName)
	if createFileError != nil {
		log.Fatal(createFileError)
	}
	var writer report.Writer
	var templateError error
	if writer, templateError = report.NewTemplateWriter(outputFile, templateFile); templateError != nil {
		log.Fatal(xerrors.Errorf("failed to initialize template writer: %w", templateError))
	}
	if writeError := writer.Write(*jsonReport); writeError != nil {
		log.Fatal(xerrors.Errorf("failed to write results: %w", writeError))
	}
}
func getReportFromJson(scanType string, jsonFileName string) (*types.Report, error) {
	switch scanType {
	case "k8s":
		k8sParsedReport, readK8sError := readJson[k8sReport.Report](jsonFileName)
		if readK8sError != nil {
			return nil, readK8sError
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
	default:
		commonReport, readCommonError := readJson[types.Report](jsonFileName)
		if readCommonError != nil {
			return nil, readCommonError
		}
		return commonReport, nil
	}
}
func createFile(fileName string) (outputFile io.Writer, err error) {
	outputFile, err = os.Create(fileName)
	if err != nil {
		return nil, xerrors.Errorf("failed to create file %w", err)
	}
	return outputFile, nil
}

func readJson[T any](fileName string) (*T, error) {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
		return *new(*T), err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal("failed to close json file %w", err)
		}
	}(file)

	var out T
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&out)
	if err != nil {
		fmt.Println(err)
		return *new(*T), err
	}
	return &out, nil
}
