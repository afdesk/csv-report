package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	tempJsonFileName     = "csv-report-temp.json"
	tempTemplateFileName = "csv-report-template-temp.tpl"
	templateFileName     = "csv.tpl"
	availableFields      = []string{"Target", "Vulnerability Class", "Target Type", "Vulnerability ID", "Severity", "PackageName", "Installed Version", "Fixed Version", "Title", "Description", "Resolution", "Reference", "Additional Reference", "CVSS V3 Score", "CVSS V3 Vector"}
	availableFlags       = []string{"--csv-result", "--delimiter", "--include", "--exclude"}
	delimiter            = ","
)

func init() {
	if delimiter = getFlagValue("--delimiter"); delimiter == "" {
		delimiter = ","
	}
	initializeAvailableFields()
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
		"getAvailableFields": func() string {
			wrapped := make([]string, len(availableFields))
			for i, str := range availableFields {
				wrapped[i] = "\"" + str + "\""
			}
			return strings.Join(wrapped, delimiter)
		},
		"isFieldAvailable": func(field string) bool {
			return slices.Contains(availableFields, field)
		},
	}
	report.CustomTemplateFuncMap = CustomTemplateFuncMap
}

func main() {
	trivyCommand := excludePluginFlags(os.Args, availableFlags)[1:]
	outputFileName := getFlagValue("--csv-result")
	if outputFileName == "" {
		log.Println("--csv-result flag is not defined. Set default value result.csv")
		outputFileName = "result.csv"
	}
	tempFileName := getTempFile(tempJsonFileName)
	defer removeFile(tempFileName)

	cmdArgs := append(trivyCommand, "--format", "json", "--output", tempFileName)
	cmd := exec.Command("trivy", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to build report: %v", err)
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

	templatePath, err := getPathToTemplate()
	if err != nil {
		log.Fatalf("failed to get template path: %v", err)
	}
	if delimiter != "," {
		defer removeFile(templatePath)
	}
	writer, err := report.NewTemplateWriter(outputFile, "@"+templatePath)
	if err != nil {
		log.Fatalf("failed to initialize template writer: %v", err)
	}
	if err = writer.Write(*jsonReport); err != nil {
		log.Fatalf("failed to write results: %v", err)
	}
}

func getReportFromJson(jsonFileName string) (*types.Report, error) {
	if !isK8s() {
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

func getPathToTemplate() (string, error) {
	if delimiter == "," {
		ex, err := os.Executable()
		if err != nil {
			return "", nil
		}
		return filepath.Join(filepath.Dir(ex), templateFileName), nil
	}
	tempTemplate, err := getChangedDelimiterTemplate()
	if err != nil {
		return "", nil
	}
	return tempTemplate, nil
}

func getChangedDelimiterTemplate() (string, error) {
	tempTemplate := getTempFile(tempTemplateFileName)
	from, err := os.Open(templateFileName)
	if err != nil {
		return "", err
	}
	defer closeFile(from)

	to, err := os.OpenFile(tempTemplate, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return "", err
	}
	defer closeFile(to)

	_, err = io.Copy(to, from)
	if err != nil {
		return "", err
	}
	tempData, err := os.ReadFile(tempTemplate)
	if err != nil {
		return "", err
	}
	tempDataReplaced := regexp.MustCompile(`(,)`).ReplaceAllString(string(tempData), delimiter)
	if err = os.WriteFile(tempTemplate, []byte(tempDataReplaced), 0600); err != nil {
		return "", err
	}
	return tempTemplate, nil
}

func getTempFile(fileName string) string {
	return filepath.Join(os.TempDir(), fileName)
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

func isK8s() bool {
	if slices.Contains(os.Args, "kubernetes") || slices.Contains(os.Args, "k8s") {
		return true
	}
	return false
}

func getFlagValue(flag string) string {
	flagIndex := slices.Index(os.Args, flag)
	if flagIndex != -1 && (len(os.Args)-1) > flagIndex { // the flag exists and it is not the last argument
		return os.Args[flagIndex+1]
	}
	return ""
}

func excludePluginFlags(args []string, exclude []string) []string {
	result := make([]string, 0, len(args))
	var excludeIndices []int
	for i := 0; i < len(args); i++ {
		flagIndex := slices.Index(exclude, args[i])
		if flagIndex != -1 && len(args)-1 > flagIndex {
			excludeIndices = append(excludeIndices, i, i+1) // exclude flag and value
		}
	}
	for i, arg := range args {
		if slices.Index(excludeIndices, i) == -1 {
			result = append(result, arg)
		}
	}
	return result
}

func initializeAvailableFields() {
	includeFlagValue := getFlagValue("--include")
	excludeFlagValue := getFlagValue("--exclude")
	if includeFlagValue != "" && excludeFlagValue != "" {
		log.Fatalf("only one flag --include of --exclude allowed")
	}
	lowercaseFields := make([]string, len(availableFields))
	for i, field := range availableFields {
		lowercaseFields[i] = strings.ToLower(field)
	}
	includeFields := strings.Split(includeFlagValue, ",")
	if includeFlagValue != "" {
		var includedIndices []int
		for _, field := range includeFields {
			if ix := slices.Index(lowercaseFields, strings.ToLower(strings.TrimSpace(field))); ix != -1 {
				includedIndices = append(includedIndices, ix)
				continue
			}
			log.Fatalf("unresolved field %s", field)
		}
		sort.Ints(includedIndices)
		newSlice := make([]string, len(includedIndices))
		for i, index := range includedIndices {
			newSlice[i] = availableFields[index]
		}
		availableFields = newSlice
	}
	excludeFields := strings.Split(excludeFlagValue, ",")
	if excludeFlagValue != "" {
		var excludedIndices []int
		for _, field := range excludeFields {
			if ix := slices.Index(lowercaseFields, strings.ToLower(strings.TrimSpace(field))); ix != -1 {
				excludedIndices = append(excludedIndices, ix)
				continue
			}
			log.Fatalf("unresolved field %s", field)
		}
		sort.Ints(excludedIndices)
		for i, index := range excludedIndices {
			index -= i
			availableFields = append(availableFields[:index], availableFields[index+1:]...)
		}
	}
}
