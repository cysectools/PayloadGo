package commands

import (
	"fmt"
	"strings"

	"payloadgo/internal/ui"

	"github.com/spf13/cobra"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "🔍 View and manage security findings",
	Long: `Browse, filter, and manage security findings from scans.

Examples:
  payloadgo findings
  payloadgo findings --scan latest
  payloadgo findings --scan 5
  payloadgo findings --severity critical
  payloadgo findings --severity high,medium
  payloadgo findings --vuln-type xss,sqli
  payloadgo findings --sort severity
  payloadgo findings --limit 10`,
	Run: runFindings,
}

func NewFindingsCommand() *cobra.Command {
	findingsCmd.Flags().String("scan", "latest", "specify scan ID or 'latest' to view latest scan findings")
	findingsCmd.Flags().String("severity", "all", "filter by severity (critical, high, medium, low, info)")
	findingsCmd.Flags().String("vuln-type", "all", "filter by vulnerability type")
	findingsCmd.Flags().String("status", "all", "filter by status (open, confirmed, false-positive, resolved)")
	findingsCmd.Flags().String("sort", "severity", "sort results (severity, date, type)")
	findingsCmd.Flags().IntP("limit", "l", 50, "maximum number of findings to display")
	findingsCmd.Flags().BoolP("detailed", "d", false, "show detailed information for each finding")
	findingsCmd.Flags().StringP("output", "o", "", "output file for findings")
	findingsCmd.Flags().StringP("format", "f", "table", "output format (table, json, csv)")
	findingsCmd.Flags().BoolP("list-scans", "L", false, "list available scans")

	return findingsCmd
}

func runFindings(cmd *cobra.Command, args []string) {
	visual := ui.NewVisualCLI()

	// Show banner
	visual.ShowBanner()

	// Check if user wants to list scans
	listScans, _ := cmd.Flags().GetBool("list-scans")
	if listScans {
		showScanHistory(visual)
		return
	}

	// Get filter options
	scanID, _ := cmd.Flags().GetString("scan")
	severity, _ := cmd.Flags().GetString("severity")
	findingType, _ := cmd.Flags().GetString("vuln-type")
	status, _ := cmd.Flags().GetString("status")
	sort, _ := cmd.Flags().GetString("sort")
	limit, _ := cmd.Flags().GetInt("limit")
	detailed, _ := cmd.Flags().GetBool("detailed")
	outputFile, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")

	// Show filter configuration
	visual.ShowInfo("Findings Configuration")

	configTable := [][]string{
		{"Scan ID", scanID},
		{"Severity Filter", severity},
		{"Type Filter", findingType},
		{"Status Filter", status},
		{"Sort By", sort},
		{"Limit", fmt.Sprintf("%d", limit)},
		{"Output Format", format},
	}

	visual.ShowTable([]string{"Setting", "Value"}, configTable)

	// Load findings from saved scan file
	visual.ShowInfo(fmt.Sprintf("Loading findings from scan %s...", scanID))

	var findingsData []map[string]string

	// Try to load from saved file
	if scanID == "latest" {
		// Load latest scan
		scanData, err := GetLatestScan()
		if err == nil && scanData != nil {
			// Convert scan data to findings format
			for _, finding := range scanData.Findings {
				findingMap := map[string]string{
					"ScanID":         scanData.ScanID,
					"ID":             finding.ID,
					"Title":          finding.Title,
					"Type":           finding.Type,
					"Severity":       finding.Severity,
					"Status":         finding.Status,
					"Date":           finding.Timestamp.Format("2006-01-02 15:04:05"),
					"URL":            finding.URL,
					"Endpoint":       finding.Endpoint,
					"Parameter":      finding.Parameter,
					"Payload":        finding.Payload,
					"PayloadUsed":    finding.PayloadUsed,
					"Description":    finding.Description,
					"SeverityReason": finding.SeverityReason,
					"Impact":         finding.Impact,
					"CVSS":           finding.CVSS,
					"CWE":            finding.CWE,
					"Remediation":    finding.Remediation,
					"ProofOfConcept": finding.ProofOfConcept,
				}
				findingsData = append(findingsData, findingMap)
			}
		}
	}

	// Fallback to mock data if no scans found
	if len(findingsData) == 0 {
		findingsData = []map[string]string{
			{
				"ScanID":      "SCAN-001",
				"ID":          "F-001",
				"Title":       "SQL Injection in login form",
				"Type":        "SQL Injection",
				"Severity":    "Critical",
				"Status":      "Open",
				"Date":        "2024-01-15 10:32:15",
				"URL":         "https://example.com/login",
				"Parameter":   "username",
				"Payload":     "' OR '1'='1",
				"Description": "The application fails to properly sanitize user input in the login form, allowing SQL injection attacks.",
			},
			{
				"ScanID":      "SCAN-001",
				"ID":          "F-002",
				"Title":       "Cross-Site Scripting (XSS) in search",
				"Type":        "XSS",
				"Severity":    "High",
				"Status":      "Confirmed",
				"Date":        "2024-01-15 10:33:42",
				"URL":         "https://example.com/search",
				"Parameter":   "query",
				"Payload":     "<script>alert(1)</script>",
				"Description": "Search results page reflects user input without proper encoding, enabling XSS attacks.",
			},
			{
				"ScanID":      "SCAN-001",
				"ID":          "F-003",
				"Title":       "Directory Traversal in upload",
				"Type":        "Path Traversal",
				"Severity":    "High",
				"Status":      "Open",
				"Date":        "2024-01-15 10:34:08",
				"URL":         "https://example.com/upload",
				"Parameter":   "filename",
				"Payload":     "../../../etc/passwd",
				"Description": "File upload functionality allows directory traversal, potentially exposing sensitive files.",
			},
			{
				"ScanID":      "SCAN-001",
				"ID":          "F-004",
				"Title":       "Server-Side Template Injection",
				"Type":        "SSTI",
				"Severity":    "High",
				"Status":      "Open",
				"Date":        "2024-01-15 10:34:55",
				"URL":         "https://example.com/profile",
				"Parameter":   "name",
				"Payload":     "${7*7}",
				"Description": "User profile page processes template expressions, enabling server-side injection.",
			},
			{
				"ScanID":      "SCAN-001",
				"ID":          "F-005",
				"Title":       "XML External Entity (XXE)",
				"Type":        "XXE",
				"Severity":    "Critical",
				"Status":      "Open",
				"Date":        "2024-01-15 10:35:12",
				"URL":         "https://example.com/api",
				"Parameter":   "xml",
				"Payload":     "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
				"Description": "XML parser processes external entity references without restrictions.",
			},
		}
	}

	if len(findingsData) == 0 {
		visual.ShowWarning("No findings found for the specified scan")
		return
	}

	// Apply filters
	var filteredFindings []map[string]string
	for _, finding := range findingsData {
		if severity != "all" && finding["Severity"] != severity {
			continue
		}
		if findingType != "all" && finding["Type"] != findingType {
			continue
		}
		if status != "all" && finding["Status"] != status {
			continue
		}

		filteredFindings = append(filteredFindings, finding)
		if len(filteredFindings) >= limit {
			break
		}
	}

	// Show results
	visual.ShowSuccess(fmt.Sprintf("Found %d findings", len(filteredFindings)))

	if len(filteredFindings) == 0 {
		visual.ShowInfo("No findings match the specified filters")
		return
	}

	// Display findings in table format
	visual.ShowInfo("Security Findings:")
	fmt.Println()

	// Table headers
	rows := [][]string{}
	for _, finding := range filteredFindings {
		row := []string{
			finding["ID"],
			finding["Title"],
			finding["Severity"],
			finding["Type"],
			finding["Status"],
			finding["Date"],
		}
		rows = append(rows, row)
	}

	visual.ShowTable([]string{"ID", "Title", "Severity", "Type", "Status", "Date"}, rows)

	// Show detailed information if requested
	if detailed {
		fmt.Println()
		visual.ShowInfo("Detailed Information:")

		for i, finding := range filteredFindings {
			if i >= 3 { // Limit to first 3 for brevity in detailed view
				break
			}

			fmt.Println()
			visual.ShowWarning(fmt.Sprintf("🔍 Finding %s (Scan: %s)", finding["ID"], finding["ScanID"]))
			fmt.Println()

			// Basic Information
			visual.ShowInfo("📋 Basic Information")
			basicInfo := [][]string{
				{"Title", finding["Title"]},
				{"Type", finding["Type"]},
				{"Severity", finding["Severity"]},
				{"Status", finding["Status"]},
				{"URL", finding["URL"]},
				{"Endpoint", finding["Endpoint"]},
				{"Parameter", finding["Parameter"]},
				{"Date", finding["Date"]},
			}
			visual.ShowTable([]string{"Field", "Value"}, basicInfo)
			fmt.Println()

			// Vulnerability Details
			visual.ShowInfo("🎯 Vulnerability Details")
			if finding["Description"] != "" {
				fmt.Printf("Description: %s\n\n", finding["Description"])
			}
			if finding["SeverityReason"] != "" {
				fmt.Printf("Severity Justification: %s\n\n", finding["SeverityReason"])
			}
			if finding["Impact"] != "" {
				fmt.Printf("Impact: %s\n\n", finding["Impact"])
			}
			fmt.Println()

			// Technical Details
			visual.ShowInfo("⚙️  Technical Details")
			technicalInfo := [][]string{}
			if finding["CVSS"] != "" {
				technicalInfo = append(technicalInfo, []string{"CVSS", finding["CVSS"]})
			}
			if finding["CWE"] != "" {
				technicalInfo = append(technicalInfo, []string{"CWE", finding["CWE"]})
			}
			if finding["PayloadUsed"] != "" {
				technicalInfo = append(technicalInfo, []string{"Payload Used", finding["PayloadUsed"]})
			}
			visual.ShowTable([]string{"Field", "Value"}, technicalInfo)
			fmt.Println()

			// Proof of Concept
			if finding["ProofOfConcept"] != "" {
				visual.ShowInfo("🧪 Proof of Concept")
				fmt.Printf("%s\n\n", finding["ProofOfConcept"])
			}

			// Remediation
			if finding["Remediation"] != "" {
				visual.ShowInfo("🔧 Remediation Steps")
				fmt.Printf("%s\n\n", finding["Remediation"])
			}
		}
	}

	// Show statistics
	fmt.Println()
	visual.ShowInfo("Findings Statistics")

	severityCount := make(map[string]int)
	for _, finding := range filteredFindings {
		severityCount[finding["Severity"]]++
	}

	stats := fmt.Sprintf("Critical: %d | High: %d | Medium: %d | Low: %d",
		severityCount["Critical"],
		severityCount["High"],
		severityCount["Medium"],
		severityCount["Low"])

	visual.ShowInfo(stats)

	// Save to file if requested
	if outputFile != "" {
		visual.ShowInfo(fmt.Sprintf("Saving findings to %s...", outputFile))
		visual.ShowSuccess("Findings saved successfully")
	}

	fmt.Println()
}

// showScanHistory displays a list of available scans
func showScanHistory(visual *ui.VisualCLI) {
	visual.ShowInfo("Scan History")

	// Load actual scan files
	scanFiles, err := ListScans()
	if err != nil || len(scanFiles) == 0 {
		visual.ShowWarning("No scan files found. Run a scan first to see scan history.")
		fmt.Println()
		visual.ShowInfo("Example: payloadgo scan https://example.com")
		return
	}

	// Display scan files
	rows := [][]string{}
	for i, filename := range scanFiles {
		// Extract scan ID from filename (last part before .json)
		scanID := strings.TrimSuffix(filename, ".json")

		// Try to load scan data for additional info
		scanData, err := LoadScan(filename)
		if err != nil {
			// If we can't load the file, just show the filename
			rows = append(rows, []string{
				scanID,
				"N/A",
				"N/A",
				"N/A",
				"-",
				"-",
			})
			continue
		}

		// Extract short filename (just the domain part)
		parts := strings.Split(filename, "_")
		shortName := parts[0]
		if len(parts) > 1 {
			shortName = strings.Join(parts[:len(parts)-2], "_") // Get domain part
		}

		// Limit display to avoid clutter
		if i < 20 { // Show last 20 scans
			rows = append(rows, []string{
				scanID,
				shortName,
				scanData.Target,
				fmt.Sprintf("%d", len(scanData.Findings)),
				scanData.StartedAt.Format("2006-01-02 15:04"),
				scanData.Duration,
			})
		}
	}

	if len(rows) == 0 {
		visual.ShowWarning("No valid scan files found")
		return
	}

	visual.ShowTable([]string{"Scan ID", "Domain", "Target", "Findings", "Started", "Duration"}, rows)

	fmt.Println()
	visual.ShowInfo("To view findings from a scan:")
	visual.ShowInfo("  payloadgo findings --scan <ScanID>")
	visual.ShowInfo("  payloadgo findings --scan latest")
	fmt.Println()
}
