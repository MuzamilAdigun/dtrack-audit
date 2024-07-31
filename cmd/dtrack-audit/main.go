package main

import (
	"fmt"
	"os"
	"strings"

	//	"reflect"
	//	"strings"
	"time"

	"github.com/ozontech/dtrack-audit/internal/dtrack"
)

func checkError(e error) {
	if e != nil {
		fmt.Printf("[Dtrack Audit Error]: %s\n", e)
		os.Exit(0)
	}
}
func checkErro(e error) {
	if e != nil {
		fmt.Printf("fichu: %s\n", e)
		//os.Exit(0)
	}
}

func main() {
	var err error

	config := &dtrack.Config{}
	dtrack.ParseFlagsAndEnvs(config)

	// We need at least apiKey and apiUrl to call Dtrack API
	if config.ApiKey == "" || config.ApiUrl == "" {
		dtrack.Usage()
		os.Exit(0)
	}

	apiClient := dtrack.ApiClient{ApiKey: config.ApiKey, ApiUrl: config.ApiUrl}

	// Try to find project by name or create it
	if config.AutoCreateProject && config.ProjectId == "" {
		config.ProjectId, err = apiClient.LookupOrCreateProject(config.ProjectName, config.ProjectVersion)
		checkError(err)
	}

	// ProjectId is also required to call Dtrack API and deal with projects
	if config.ProjectId == "" {
		dtrack.Usage()
		os.Exit(0)
	}

	uploadResult, err := apiClient.Upload(config.InputFileName, config.ProjectId)
	checkError(err)

	if uploadResult.Token != "" {
		fmt.Printf("SBOM file is successfully uploaded to DTrack API. Result token is %s\n", uploadResult.Token)
	}
	// In Sync mode we're waiting for findings from Dtrack
	if uploadResult.Token != "" && config.SyncMode {
		fmt.Println("In Sync mode we're waiting for findings from DTrack")
		err := apiClient.PollTokenBeingProcessed(
			uploadResult.Token, time.After(time.Duration(config.Timeout)*time.Second))
		checkError(err)

		findings, err := apiClient.GetFindings(config.ProjectId, config.SeverityFilter)
		checkError(err)
		s := 0
		x := 0
		fmt.Printf("%d vulnerabilities found!\n\n", len(findings))
		//Anal, err := apiClient.VulnAnalysis(f.Comp.Uuid, f.Vuln.Uuid, config.ProjectId)
		var finalString []string
		for _, f := range findings {
			urll, err := apiClient.VulURL(f.Vuln.Source, f.Vuln.VulnId)
			checkError(err)
			Analys, err := apiClient.VulnAnalysis(f.Comp.Uuid, f.Vuln.Uuid, config.ProjectId)
			//checkErro(err)
			var Ana string = "tt"
			switch Analys.AnalysisState {
			case "EXPLOITABLE":
				Ana = "[Untreated] Exploitable Vulnerability set as - " + Analys.AnalysisState
				s++
			case "IN_TRIAGE":
				Ana = "[Untreated] Investigation is in progress set as - " + Analys.AnalysisState
				s++
			case "NOT_SET":
				Ana = "[Treated] Analysis has not commenced set as - " + Analys.AnalysisState
				s++
			case "NOT_AFFECTED":
				Ana = "[Treated] set as - " + Analys.AnalysisState
				x++
			case "RESOLVED":
				Ana = "[Treated] Vulnerability resolved  as - " + Analys.AnalysisState
				x++
			case "FALSE_POSITIVE":
				Ana = "[Treated] Vulnerability was identified through faulty logic or data set as - " + Analys.AnalysisState
				x++

			default:
				Ana = "[Untreated] Analysis has not commenced"
				s++
			}

			finalString = append(finalString, fmt.Sprintf(
				" > %s:  %s\n   Component: %s %s\n   More info: %s\n   State: %s\n\n",
				f.Vuln.Severity, f.Vuln.Title, f.Comp.Name, f.Comp.Version, urll, Ana))

		}
		strings.Join(finalString[:], "")
		fmt.Print(finalString)
		fmt.Printf("\n\n")
		if x > 0 {
			fmt.Printf("%d Treated vulnerabilities !\n\n", x)

		}

		if s > 0 {
			fmt.Printf("%d Untreated vulnerabilities !\n\n", s)
			os.Exit(1)

		}

	}
}
