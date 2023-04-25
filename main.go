package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	tempJsonFileName     = "csv-report-temp.json"
	tempTemplateFileName = "csv-report-template-temp.tpl"
	templateFileName     = "csv.tpl"
	availableFieldsNames = []string{
		"Target",
		"Vulnerability Class",
		"Target Type",
		"Vulnerability ID",
		"Severity",
		"PackageName",
		"Installed Version",
		"Fixed Version",
		"Title",
		"Description",
		"Resolution",
		"Reference",
		"Additional Reference",
		"CVSS V3 Score",
		"CVSS V3 Vector",
	}
	availableFieldsMap = map[string]bool{}
	availableFlags     = []string{"--csv-result", "--csv-delimiter", "--csv-include", "--csv-exclude"}
	delimiter          = ","
)

func init() {
	if delimiter = getFlagValue("--csv-delimiter"); delimiter == "" {
		delimiter = ","
	}
	initializeAvailableFields()
	availableFieldKeys := make([]string, 0, len(availableFieldsNames))
	for _, field := range availableFieldsNames {
		if availableFieldsMap[strings.ToLower(field)] {
			availableFieldKeys = append(availableFieldKeys, "\""+field+"\"")
		}
	}
	var CustomTemplateFuncMap = map[string]interface{}{
		"getAvailableFields": func() string {
			return strings.Join(availableFieldKeys, ",")
		},
		"getVulnerabilitiesTable":  getVulnerabilitiesTable,
		"getMisconfigurationTable": getMisconfigurationTable,
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
	includeFlagValue := getFlagValue("--csv-include")
	excludeFlagValue := getFlagValue("--csv-exclude")
	if includeFlagValue != "" && excludeFlagValue != "" {
		log.Fatalf("only one flag --csv-include of --csv-exclude allowed")
	}
	for _, name := range availableFieldsNames {
		availableFieldsMap[strings.ToLower(name)] = true
	}

	if includeFlagValue != "" {
		includeFields := strings.Split(includeFlagValue, ",")
		for _, name := range availableFieldsNames {
			availableFieldsMap[strings.ToLower(name)] = false
		}
		for _, field := range includeFields {
			if _, ok := availableFieldsMap[strings.ToLower(strings.TrimSpace(field))]; ok {
				availableFieldsMap[strings.ToLower(strings.TrimSpace(field))] = true
				continue
			}
			log.Fatalf("unresolved field %s", field)
		}
	}

	if excludeFlagValue != "" {
		excludeFields := strings.Split(excludeFlagValue, ",")

		for _, field := range excludeFields {
			if _, ok := availableFieldsMap[strings.ToLower(strings.TrimSpace(field))]; ok {
				availableFieldsMap[strings.ToLower(strings.TrimSpace(field))] = false
				continue
			}
			log.Fatalf("unresolved field %s", field)
		}
	}
}

func escapeCsv(input string) string {
	quoted := strconv.Quote(input)
	return strings.ReplaceAll(quoted, "\\\"", "\"\"")
}

func getVulnerabilitiesTable(result types.Result) string {
	var resultString strings.Builder
	if len(result.Vulnerabilities) == 0 {
		return ""
	}
	for _, vulnerability := range result.Vulnerabilities {
		writeCommonFields(result, &resultString, vulnerability)
		if availableFieldsMap["additional reference"] {
			refIndex := slices.IndexFunc(vulnerability.References, func(ref string) bool { return strings.Contains(ref, "nvd.nist.gov") })
			if refIndex != -1 {
				resultString.WriteString(vulnerability.References[refIndex] + delimiter)
			} else {
				resultString.WriteString("" + delimiter)
			}
		}

		cvssNvd := vulnerability.CVSS["nvd"]
		cvssRh := vulnerability.CVSS["redhat"]
		if availableFieldsMap["cvss v3 score"] {
			fieldValue := ""
			if cvssNvd.V3Score != 0 {
				fieldValue = strconv.FormatFloat(cvssNvd.V3Score, 'f', -1, 64)
			} else if cvssRh.V3Score != 0 {
				fieldValue = strconv.FormatFloat(cvssRh.V3Score, 'f', -1, 64)
			}
			resultString.WriteString(fieldValue + delimiter)
		}
		if availableFieldsMap["cvss v3 vector"] {
			fieldValue := ""
			if cvssRh.V3Vector != "" {
				fieldValue = cvssNvd.V3Vector
			} else if cvssNvd.V3Vector != "" {
				fieldValue = cvssNvd.V3Vector
			}
			resultString.WriteString(fieldValue + delimiter)
		}
		resultString.WriteString("\n")
	}
	return resultString.String()
}

func getMisconfigurationTable(result types.Result) string {
	var resultString strings.Builder
	if len(result.Misconfigurations) == 0 {
		return ""
	}
	for _, misc := range result.Misconfigurations {
		writeCommonFields(result, &resultString, misc)
		if availableFieldsMap["additional reference"] {
			refIndex := slices.IndexFunc(misc.References, func(ref string) bool { return strings.Contains(ref, "docs.docker.com") })
			if refIndex != -1 {
				resultString.WriteString(misc.References[refIndex] + delimiter)
			} else {
				resultString.WriteString("" + delimiter)
			}
		}
		resultString.WriteString("\n")
	}
	return resultString.String()
}

func getFieldValue[T types.DetectedMisconfiguration | types.DetectedVulnerability](dm T, fieldName string) string {
	r := reflect.ValueOf(dm)
	f := reflect.Indirect(r).FieldByName(fieldName)
	if f.IsValid() {
		return fmt.Sprintf("%v", f.Interface())
	}
	return ""
}

func writeCommonFields[T types.DetectedMisconfiguration | types.DetectedVulnerability](result types.Result, resultString *strings.Builder, vulnerability T) {
	if availableFieldsMap["target"] {
		resultString.WriteString(escapeCsv(result.Target) + delimiter)
	}
	if availableFieldsMap["vulnerability class"] {
		resultString.WriteString(escapeCsv(string(result.Class)) + delimiter)
	}
	if availableFieldsMap["target type"] {
		resultString.WriteString(escapeCsv(result.Target) + delimiter)
	}
	if availableFieldsMap["vulnerability id"] {
		id := getFieldValue(vulnerability, "VulnerabilityID")
		if id == "" {
			id = getFieldValue(vulnerability, "ID")
		}
		resultString.WriteString(escapeCsv(id) + delimiter)
	}
	if availableFieldsMap["severity"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "Severity")) + delimiter)
	}
	if availableFieldsMap["packagename"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "PkgName")) + delimiter)
	}
	if availableFieldsMap["installed version"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "InstalledVersion")) + delimiter)
	}
	if availableFieldsMap["fixed version"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "FixedVersion")) + delimiter)
	}
	if availableFieldsMap["title"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "Title")) + delimiter)
	}
	if availableFieldsMap["description"] {
		resultString.WriteString(escapeCsv(getFieldValue(vulnerability, "Description")) + delimiter)
	}
	if availableFieldsMap["resolution"] {
		resulution := "No resolution provided."
		if getFieldValue(vulnerability, "FixedVersion") != "" {
			resulution = fmt.Sprintf("Update %s to version %s or higher.", getFieldValue(vulnerability, "PkgName"), getFieldValue(vulnerability, "FixedVersion"))
		}
		resultString.WriteString(resulution + delimiter)
	}
	if availableFieldsMap["reference"] {
		resultString.WriteString(getFieldValue(vulnerability, "PrimaryURL") + delimiter)
	}
}
