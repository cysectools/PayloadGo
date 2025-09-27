package commands

import (
	"encoding/json"
	"fmt"
	"html"
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PayloadGo Vulnerability Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="25" cy="25" r="1" fill="white" opacity="0.1"/><circle cx="75" cy="75" r="1" fill="white" opacity="0.1"/><circle cx="50" cy="10" r="0.5" fill="white" opacity="0.1"/><circle cx="10" cy="60" r="0.5" fill="white" opacity="0.1"/><circle cx="90" cy="40" r="0.5" fill="white" opacity="0.1"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
            opacity: 0.3;
        }
        
        .header h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .content {
            padding: 40px;
        }
        
        .summary {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            border-left: 5px solid #667eea;
        }
        
        .summary h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat {
            background: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
            border: 1px solid #e9ecef;
        }
        
        .stat:hover {
            transform: translateY(-2px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 1em;
            color: #6c757d;
            font-weight: 500;
        }
        
        .vuln-section {
            margin: 30px 0;
        }
        
        .vuln-type {
            color: #dc3545;
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 20px;
            padding: 15px 20px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
            border-radius: 10px;
            display: inline-block;
        }
        
        .vulnerability {
            background: white;
            border: 1px solid #e9ecef;
            margin: 15px 0;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            transition: all 0.3s ease;
            border-left: 4px solid #667eea;
        }
        
        .vulnerability:hover {
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            transform: translateY(-1px);
        }
        
        .vulnerability p {
            margin-bottom: 12px;
        }
        
        .vulnerability strong {
            color: #2c3e50;
            font-weight: 600;
        }
        
        .payload {
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 12px 15px;
            border-radius: 8px;
            word-break: break-all;
            border: 1px solid #dee2e6;
            font-size: 0.9em;
            line-height: 1.4;
        }
        
        .url {
            color: #667eea;
            word-break: break-all;
            text-decoration: none;
            font-weight: 500;
        }
        
        .url:hover {
            text-decoration: underline;
        }
        
        .response {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Fira Code', 'Monaco', 'Consolas', monospace;
            white-space: pre-wrap;
            border: 1px solid #dee2e6;
            font-size: 0.85em;
            line-height: 1.4;
        }
        
        .severity-high {
            border-left-color: #dc3545;
        }
        
        .severity-medium {
            border-left-color: #ffc107;
        }
        
        .severity-low {
            border-left-color: #28a745;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
                border-radius: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ PayloadGo Vulnerability Report</h1>
            <p>Generated on ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <h2>📊 Executive Summary</h2>
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
                <div class="vuln-type">🔍 %s (%d instances)</div>`, vulnType, len(vulns)))

			for _, vuln := range vulns {
				// Properly escape HTML content to prevent XSS
				escapedPayload := html.EscapeString(vuln.Payload)
				escapedURL := html.EscapeString(vuln.URL)

				file.WriteString(fmt.Sprintf(`
                <div class="vulnerability">
                    <p><strong>💻 Payload:</strong> <span class="payload">%s</span></p>
                    <p><strong>🌐 URL:</strong> <span class="url">%s</span></p>
                    <p><strong>📊 Status:</strong> %d | <strong>⏱️ Time:</strong> %dms</p>
                </div>`, escapedPayload, escapedURL, vuln.StatusCode, vuln.ResponseTime.Milliseconds()))
			}

			file.WriteString(`
            </div>`)
		}
	} else {
		// Generate detailed report
		for vulnType, vulns := range vulnTypes {
			file.WriteString(fmt.Sprintf(`
            <div class="vuln-section">
                <div class="vuln-type">🔍 %s (%d instances)</div>`, vulnType, len(vulns)))

			for _, vuln := range vulns {
				// Properly escape HTML content to prevent XSS
				escapedPayload := html.EscapeString(vuln.Payload)
				escapedURL := html.EscapeString(vuln.URL)
				escapedResponse := html.EscapeString(vuln.Response)

				file.WriteString(fmt.Sprintf(`
                <div class="vulnerability">
                    <p><strong>💻 Payload:</strong> <span class="payload">%s</span></p>
                    <p><strong>🌐 URL:</strong> <span class="url">%s</span></p>
                    <p><strong>📊 Status:</strong> %d | <strong>⏱️ Time:</strong> %dms</p>`,
					escapedPayload, escapedURL, vuln.StatusCode, vuln.ResponseTime.Milliseconds()))

				if vuln.Response != "" {
					file.WriteString(fmt.Sprintf(`
                    <p><strong>📄 Response:</strong></p>
                    <div class="response">%s</div>`, escapedResponse))
				}

				file.WriteString(`
                </div>`)
			}

			file.WriteString(`
            </div>`)
		}
	}

	file.WriteString(`
        </div>
        
        <div class="footer">
            <p>🛡️ Generated by PayloadGo - Professional Vulnerability Testing Tool</p>
            <p>For security professionals and bug bounty hunters</p>
        </div>
    </div>
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
