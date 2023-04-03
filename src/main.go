package main

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
	"io"
	"log"
	"os"
	"os/exec"
)

var (
	tempJson     = "csv-report-temp.json"
	templateFile = "@csv.tpl"
)

func main() {
	trivyCommand := os.Args[1 : len(os.Args)-1]
	scanType := trivyCommand[0]
	outputFile := os.Args[len(os.Args)-1]
	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempJson)
	cmd := exec.Command("trivy", cmdArgs...)
	cmdErr := cmd.Run()
	if cmdErr != nil {
		log.Fatal(xerrors.Errorf("failed to build report: %w", cmdErr))
	}
	getResultsError, results := getResultsFromJson(scanType, tempJson)
	if getResultsError != nil {
		log.Fatal(xerrors.Errorf("failed to extract results from json: %w", getResultsError))
	}
	createFileError, f := createFile(outputFile)
	if createFileError != nil {
		log.Fatalln(createFileError)
	}
	var writer Writer
	var templateError error
	if writer, templateError = NewTemplateWriter(f, templateFile); templateError != nil {
		log.Fatal(xerrors.Errorf("failed to initialize template writer: %w", templateError))
	}
	if writeError := writer.Write(results); writeError != nil {
		log.Fatal(xerrors.Errorf("failed to write results: %w", writeError))
	}
}
func getResultsFromJson(scanType string, jsonFileName string) (error, types.Results) {
	switch scanType {
	case "k8s":
		readK8sError, k8sReport := readJson[report.Report](jsonFileName)
		if readK8sError != nil {
			return readK8sError, nil
		}
		var resultsArr types.Results
		for _, vuln := range k8sReport.Vulnerabilities {
			resultsArr = append(resultsArr, vuln.Results...)
		}
		for _, misc := range k8sReport.Misconfigurations {
			resultsArr = append(resultsArr, misc.Results...)
		}
		return nil, resultsArr
	default:
		readCommonError, commonReport := readJson[types.Report](jsonFileName)
		if readCommonError != nil {
			return readCommonError, nil
		}
		return nil, commonReport.Results
	}
}
func createFile(fileName string) (err error, outputFile io.Writer) {
	outputFile, err = os.Create(fileName)
	if err != nil {
		return xerrors.Errorf("failed to create file %w", err), nil
	}
	return nil, outputFile
}

func readJson[T any](fileName string) (error, *T) {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
		return err, *new(*T)
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
		return err, *new(*T)
	}
	return nil, &out
}
