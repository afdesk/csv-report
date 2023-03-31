package main

import (
	"encoding/json"
	"fmt"
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
	trivyCommand := os.Args[3 : len(os.Args)-1] // 0:trivy 1:csv-report
	outputFile := os.Args[len(os.Args)-1]

	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempJson)
	cmd := exec.Command("trivy", cmdArgs...)
	err := cmd.Run()
	if err != nil {
		log.Fatal(xerrors.Errorf("failed to build report: %w", err))
	}
	err, report := readJson(tempJson)
	if err != nil {
		return
	}
	createFileError, f := createFile(outputFile)
	if createFileError != nil {
		log.Fatalln(createFileError)
	}

	var writer Writer
	if writer, err = NewTemplateWriter(f, templateFile); err != nil {
		log.Fatal(xerrors.Errorf("failed to initialize template writer: %w", err))
	}
	if err := writer.Write(report); err != nil {
		log.Fatal(xerrors.Errorf("failed to write results: %w", err))
	}
}

func createFile(fileName string) (err error, outputFile io.Writer) {
	outputFile, err = os.Create(fileName)
	if err != nil {
		return xerrors.Errorf("Failed to create file %w", err), nil
	}
	return nil, outputFile
}

func readJson(fileName string) (error, types.Report) {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println(err)
		return err, types.Report{}
	}
	defer file.Close()

	var report types.Report
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		fmt.Println(err)
		return err, types.Report{}
	}
	return nil, report
}
