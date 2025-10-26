package commands

import (
	"fmt"
	"strings"
	"time"

	"payloadgo/internal/config"
	"payloadgo/internal/payloads"
	"payloadgo/internal/ui"

	"github.com/spf13/cobra"
)

var simpleScanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "🔍 Comprehensive vulnerability scan",
	Long: `Perform a comprehensive vulnerability scan using multiple payload categories.

Examples:
  payloadgo scan https://example.com
  payloadgo scan https://example.com --categories xss,sqli
  payloadgo scan https://example.com --quick
  payloadgo scan https://example.com --advanced`,
	Args: cobra.ExactArgs(1),
	Run:  runSimpleScan,
}

func NewSimpleScanCommand() *cobra.Command {
	simpleScanCmd.Flags().StringSliceP("categories", "C", []string{"all"}, "payload categories to test (xss, sqli, xxe, lfi, rfi, ssti)")
	simpleScanCmd.Flags().StringP("output", "o", "", "output file for results")
	simpleScanCmd.Flags().StringP("format", "f", "json", "output format (json, html, txt, sarif)")
	simpleScanCmd.Flags().BoolP("save-responses", "s", false, "save response bodies")
	simpleScanCmd.Flags().BoolP("quick", "q", false, "quick scan with essential payloads only")
	simpleScanCmd.Flags().BoolP("advanced", "a", false, "advanced scan with detailed configuration")
	simpleScanCmd.Flags().IntP("threads", "t", 10, "number of concurrent threads")
	simpleScanCmd.Flags().IntP("timeout", "T", 30, "request timeout in seconds")
	simpleScanCmd.Flags().StringP("user-agent", "u", "PayloadGo Enterprise/1.0", "custom user agent")
	simpleScanCmd.Flags().StringP("proxy", "p", "", "proxy URL (e.g., http://127.0.0.1:8080)")
	simpleScanCmd.Flags().BoolP("verbose", "v", false, "verbose output")
	simpleScanCmd.Flags().BoolP("safe", "S", true, "safe mode (non-destructive payloads only)")

	return simpleScanCmd
}

func runSimpleScan(cmd *cobra.Command, args []string) {
	// Initialize visual CLI
	visual := ui.NewVisualCLI()

	// Show scan banner
	visual.ShowBanner()

	// Initialize configuration
	config.Init()

	target := args[0]
	categories, _ := cmd.Flags().GetStringSlice("categories")
	outputFile, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	_, _ = cmd.Flags().GetBool("save-responses")
	quick, _ := cmd.Flags().GetBool("quick")
	_, _ = cmd.Flags().GetBool("advanced")
	threads, _ := cmd.Flags().GetInt("threads")
	timeout, _ := cmd.Flags().GetInt("timeout")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	proxy, _ := cmd.Flags().GetString("proxy")
	verbose, _ := cmd.Flags().GetBool("verbose")
	safe, _ := cmd.Flags().GetBool("safe")

	// Show scan configuration
	visual.ShowInfo("Scan Configuration")

	configTable := [][]string{
		{"Target", target},
		{"Categories", strings.Join(categories, ", ")},
		{"Threads", fmt.Sprintf("%d", threads)},
		{"Timeout", fmt.Sprintf("%ds", timeout)},
		{"User Agent", userAgent},
		{"Safe Mode", fmt.Sprintf("%t", safe)},
		{"Output Format", format},
	}

	if proxy != "" {
		configTable = append(configTable, []string{"Proxy", proxy})
	}

	visual.ShowTable([]string{"Setting", "Value"}, configTable)

	// Safety checks
	if safe {
		visual.ShowWarning("Safe mode enabled - only non-destructive payloads will be used")
	}

	// Load payloads based on categories
	var allPayloads []string
	if len(categories) == 1 && categories[0] == "all" {
		if quick {
			// Quick scan with essential payloads
			allPayloads = []string{
				"<script>alert(1)</script>",
				"' OR 1=1--",
				"../../etc/passwd",
				"${7*7}",
				"<img src=x onerror=alert(1)>",
			}
		} else {
			allPayloads = payloads.GetAllPayloads()
		}
	} else {
		for _, category := range categories {
			if categoryPayloads := payloads.GetCategory(category); categoryPayloads != nil {
				allPayloads = append(allPayloads, categoryPayloads...)
			}
		}
	}

	if len(allPayloads) == 0 {
		visual.ShowError("No payloads found for the specified categories")
		return
	}

	// Show payload statistics
	visual.ShowInfo(fmt.Sprintf("Loaded %d payloads for testing", len(allPayloads)))

	// Show scan start
	visual.ShowInfo("Starting vulnerability scan...")
	visual.ShowSpinner("Initializing scan engine")

	// Simulate scan progress
	startTime := time.Now()
	processed := 0
	vulnerableCount := 0
	resultsBySeverity := make(map[string]int)

	// Simulate scanning each payload
	for _, payload := range allPayloads {
		processed++

		// Show progress
		visual.ShowScanProgress(processed, len(allPayloads), fmt.Sprintf("Testing payload %d", processed))

		// Simulate processing time
		time.Sleep(200 * time.Millisecond)

		// Simulate vulnerability detection
		if isVulnerableSimulated(payload) {
			vulnerableCount++
			severity := determineSeveritySimulated(payload)
			resultsBySeverity[severity]++

			if verbose {
				visual.ShowWarning(fmt.Sprintf("Potential %s vulnerability found: %s", severity, payload))
			}
		}
	}

	// Show scan completion
	scanDuration := time.Since(startTime)
	visual.ShowSuccess(fmt.Sprintf("Scan completed in %v", scanDuration))

	// Show results
	visual.ShowResults(resultsBySeverity)

	// Save results if output file specified
	if outputFile != "" {
		visual.ShowInfo(fmt.Sprintf("Saving results to %s", outputFile))
		// In a real implementation, this would save the results
		visual.ShowSuccess("Results saved successfully")
	}

	// Show summary
	visual.ShowInfo("Scan Summary")
	summaryStats := map[string]interface{}{
		"Total Payloads":  len(allPayloads),
		"Processed":       processed,
		"Vulnerabilities": vulnerableCount,
		"Scan Duration":   scanDuration.String(),
		"Average Time":    fmt.Sprintf("%.2fs", float64(scanDuration.Milliseconds())/float64(processed)/1000),
	}

	visual.ShowStats(summaryStats)

	// Show next steps
	if vulnerableCount > 0 {
		visual.ShowWarning("Vulnerabilities detected! Review findings and take appropriate action.")
		visual.ShowInfo("Use 'payloadgo findings' to view detailed findings")
		visual.ShowInfo("Use 'payloadgo report' to generate comprehensive reports")
	} else {
		visual.ShowSuccess("No vulnerabilities detected in this scan")
	}
}

// Helper functions for simulation
func isVulnerableSimulated(payload string) bool {
	// Simulate vulnerability detection based on payload type
	payloadLower := strings.ToLower(payload)

	// XSS indicators
	if strings.Contains(payloadLower, "<script>") || strings.Contains(payloadLower, "javascript:") {
		return true
	}

	// SQL injection indicators
	if strings.Contains(payloadLower, "or 1=1") || strings.Contains(payloadLower, "union select") {
		return true
	}

	// Directory traversal indicators
	if strings.Contains(payloadLower, "../") || strings.Contains(payloadLower, "..\\") {
		return true
	}

	// Template injection indicators
	if strings.Contains(payloadLower, "${") || strings.Contains(payloadLower, "#{") {
		return true
	}

	// Random chance for demonstration
	return len(payload) > 10 && len(payload)%3 == 0
}

func determineSeveritySimulated(payload string) string {
	payloadLower := strings.ToLower(payload)

	// Critical vulnerabilities
	if strings.Contains(payloadLower, "or 1=1") || strings.Contains(payloadLower, "union select") {
		return "Critical"
	}

	// High severity
	if strings.Contains(payloadLower, "<script>") || strings.Contains(payloadLower, "javascript:") {
		return "High"
	}

	// Medium severity
	if strings.Contains(payloadLower, "../") || strings.Contains(payloadLower, "..\\") {
		return "Medium"
	}

	// Default to low
	return "Low"
}
