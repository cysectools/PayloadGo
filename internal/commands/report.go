package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"payloadgo/internal/engine"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report [file]",
	Short: "Generate reports from scan results",
	Long:  `Generate various reports from previously saved scan results.`,
	Args:  cobra.ExactArgs(1),
	Run:   runReport,
}

func NewReportCommand() *cobra.Command {
	reportCmd.Flags().StringP("format", "f", "html", "output format (html, pdf, txt)")
	reportCmd.Flags().StringP("output", "o", "", "output file")
	reportCmd.Flags().StringP("template", "e", "", "custom template file")
	reportCmd.Flags().BoolP("summary", "s", false, "generate summary only")
	return reportCmd
}

func runReport(cmd *cobra.Command, args []string) {
	filename := args[0]
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")
	template, _ := cmd.Flags().GetString("template")
	summary, _ := cmd.Flags().GetBool("summary")

	// Load results
	results, err := loadResults(filename)
	if err != nil {
		color.Red("❌ Error loading results: %v", err)
		return
	}

	// Generate output filename if not provided
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("report_%s.%s", timestamp, format)
	}

	// Generate report
	switch format {
	case "html":
		generateHTMLReport(results, outputFile, template, summary)
	case "pdf":
		generatePDFReport(results, outputFile, template, summary)
	case "txt":
		generateTXTReport(results, outputFile, summary)
	default:
		color.Red("❌ Unknown format: %s", format)
		return
	}

	color.Green("📄 Report generated: %s", outputFile)
}

func loadResults(filename string) ([]engine.TestResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []engine.TestResult
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&results)

	return results, err
}

func generateHTMLReport(results []engine.TestResult, outputFile, template string, summary bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		color.Red("❌ Error creating report file: %v", err)
		return
	}
	defer file.Close()

	// Group by vulnerability type
	vulnTypes := make(map[string][]engine.TestResult)
	for _, result := range results {
		vulnTypes[result.VulnType] = append(vulnTypes[result.VulnType], result)
	}

	file.WriteString(`<!DOCTYPE html>
<html>
<head>
    <title>PayloadGo Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #007bff; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vuln-section { margin: 20px 0; }
        .vuln-type { color: #dc3545; font-size: 1.2em; font-weight: bold; margin-bottom: 10px; }
        .vulnerability { background: #fff; border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .payload { font-family: monospace; background: #e9ecef; padding: 8px; border-radius: 3px; word-break: break-all; }
        .url { color: #007bff; word-break: break-all; }
        .stats { display: flex; gap: 20px; margin: 10px 0; }
        .stat { background: #e9ecef; padding: 10px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; color: #007bff; }
        .stat-label { font-size: 0.9em; color: #6c757d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PayloadGo Vulnerability Report</h1>
        <p>Generated on ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-number">` + fmt.Sprintf("%d", len(results)) + `</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">` + fmt.Sprintf("%d", len(vulnTypes)) + `</div>
                <div class="stat-label">Vulnerability Types</div>
            </div>
        </div>
    </div>`)

	if summary {
		// Generate summary by type
		for vulnType, vulns := range vulnTypes {
			file.WriteString(fmt.Sprintf(`
    <div class="vuln-section">
        <div class="vuln-type">%s (%d instances)</div>`, vulnType, len(vulns)))

			for _, vuln := range vulns {
				file.WriteString(fmt.Sprintf(`
        <div class="vulnerability">
            <p><strong>Payload:</strong> <span class="payload">%s</span></p>
            <p><strong>URL:</strong> <span class="url">%s</span></p>
            <p><strong>Status:</strong> %d | <strong>Time:</strong> %dms</p>
        </div>`, vuln.Payload, vuln.URL, vuln.StatusCode, vuln.ResponseTime.Milliseconds()))
			}

			file.WriteString(`
    </div>`)
		}
	} else {
		// Generate detailed report
		for vulnType, vulns := range vulnTypes {
			file.WriteString(fmt.Sprintf(`
    <div class="vuln-section">
        <div class="vuln-type">%s (%d instances)</div>`, vulnType, len(vulns)))

			for _, vuln := range vulns {
				file.WriteString(fmt.Sprintf(`
        <div class="vulnerability">
            <p><strong>Payload:</strong> <span class="payload">%s</span></p>
            <p><strong>URL:</strong> <span class="url">%s</span></p>
            <p><strong>Status:</strong> %d | <strong>Time:</strong> %dms</p>`,
					vuln.Payload, vuln.URL, vuln.StatusCode, vuln.ResponseTime.Milliseconds()))

				if vuln.Response != "" {
					file.WriteString(fmt.Sprintf(`
            <p><strong>Response:</strong></p>
            <pre style="background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto;">%s</pre>`, vuln.Response))
				}

				file.WriteString(`
        </div>`)
			}

			file.WriteString(`
    </div>`)
		}
	}

	file.WriteString(`
</body>
</html>`)
}

func generatePDFReport(results []engine.TestResult, outputFile, template string, summary bool) {
	// For now, generate HTML and suggest using browser print to PDF
	htmlFile := outputFile + ".html"
	generateHTMLReport(results, htmlFile, template, summary)
	color.Yellow("📄 HTML report generated. Use browser print to PDF: %s", htmlFile)
}

func generateTXTReport(results []engine.TestResult, outputFile string, summary bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		color.Red("❌ Error creating report file: %v", err)
		return
	}
	defer file.Close()

	file.WriteString("PayloadGo Vulnerability Report\n")
	file.WriteString("============================\n\n")
	file.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	file.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", len(results)))

	// Group by type
	vulnTypes := make(map[string][]engine.TestResult)
	for _, result := range results {
		vulnTypes[result.VulnType] = append(vulnTypes[result.VulnType], result)
	}

	for vulnType, vulns := range vulnTypes {
		file.WriteString(fmt.Sprintf("%s (%d instances)\n", vulnType, len(vulns)))
		file.WriteString(strings.Repeat("-", len(vulnType)+20) + "\n\n")

		for i, vuln := range vulns {
			file.WriteString(fmt.Sprintf("%d. Payload: %s\n", i+1, vuln.Payload))
			file.WriteString(fmt.Sprintf("   URL: %s\n", vuln.URL))
			file.WriteString(fmt.Sprintf("   Status: %d | Time: %dms\n", vuln.StatusCode, vuln.ResponseTime.Milliseconds()))

			if !summary && vuln.Response != "" {
				file.WriteString("   Response:\n")
				file.WriteString("   " + strings.Replace(vuln.Response, "\n", "\n   ", -1) + "\n")
			}

			file.WriteString("\n")
		}
	}
}
