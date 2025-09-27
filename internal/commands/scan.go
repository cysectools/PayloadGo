package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"payloadgo/internal/config"
	"payloadgo/internal/engine"
	"payloadgo/internal/payloads"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Comprehensive vulnerability scan",
	Long:  `Perform a comprehensive vulnerability scan using multiple payload categories.`,
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

func NewScanCommand() *cobra.Command {
	scanCmd.Flags().StringSliceP("categories", "C", []string{"all"}, "payload categories to test")
	scanCmd.Flags().StringP("output", "o", "", "output file for results")
	scanCmd.Flags().StringP("format", "f", "json", "output format (json, html, txt)")
	scanCmd.Flags().BoolP("save-responses", "s", false, "save response bodies")
	return scanCmd
}

func runScan(cmd *cobra.Command, args []string) {
	config.Init()

	target := args[0]
	categories, _ := cmd.Flags().GetStringSlice("categories")
	outputFile, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	saveResponses, _ := cmd.Flags().GetBool("save-responses")

	// Load payloads based on categories
	var allPayloads []string
	if len(categories) == 1 && categories[0] == "all" {
		allPayloads = payloads.GetAllPayloads()
	} else {
		for _, category := range categories {
			if payloads := payloads.GetCategory(category); payloads != nil {
				allPayloads = append(allPayloads, payloads...)
			} else {
				color.Red("❌ Unknown category: %s", category)
				return
			}
		}
	}

	// Create engine
	eng, err := engine.NewEngine(
		config.AppConfig.Threads,
		time.Duration(config.AppConfig.Timeout)*time.Second,
		config.AppConfig.UserAgent,
		config.AppConfig.Proxy,
	)
	if err != nil {
		color.Red("❌ Error creating engine: %v", err)
		return
	}

	// Start scanning
	color.Cyan("🔍 Starting comprehensive scan on: %s", target)
	color.Cyan("📦 Payloads: %d", len(allPayloads))
	color.Cyan("🧵 Threads: %d", config.AppConfig.Threads)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()
	results := eng.RunConcurrent(ctx, target, allPayloads, "url", "", "")

	var vulnerableResults []engine.TestResult
	for result := range results {
		eng.PrintResult(result, config.AppConfig.Verbose)
		if result.Vulnerable {
			vulnerableResults = append(vulnerableResults, result)
		}
	}

	duration := time.Since(startTime)
	stats := eng.GetStats()

	// Print summary
	color.Green("\n✅ Scan completed!")
	color.Green("📊 Results: %d tested, %d vulnerable, %d errors",
		stats.Tested, stats.Vulnerable, stats.Errors)
	color.Green("⏱️  Duration: %v", duration)

	// Save results if requested
	if outputFile != "" {
		saveResults(vulnerableResults, outputFile, format, saveResponses)
	}
}

func saveResults(results []engine.TestResult, filename, format string, saveResponses bool) {
	file, err := os.Create(filename)
	if err != nil {
		color.Red("❌ Error creating output file: %v", err)
		return
	}
	defer file.Close()

	switch format {
	case "json":
		saveJSON(results, file, saveResponses)
	case "html":
		saveHTML(results, file, saveResponses)
	case "txt":
		saveTXT(results, file, saveResponses)
	default:
		color.Red("❌ Unknown format: %s", format)
		return
	}

	color.Green("💾 Results saved to: %s", filename)
}

func saveJSON(results []engine.TestResult, file *os.File, saveResponses bool) {
	file.WriteString("[\n")
	for i, result := range results {
		if i > 0 {
			file.WriteString(",\n")
		}
		file.WriteString("  {\n")
		file.WriteString(fmt.Sprintf("    \"payload\": %q,\n", result.Payload))
		file.WriteString(fmt.Sprintf("    \"url\": %q,\n", result.URL))
		file.WriteString(fmt.Sprintf("    \"status_code\": %d,\n", result.StatusCode))
		file.WriteString(fmt.Sprintf("    \"vulnerable\": %t,\n", result.Vulnerable))
		file.WriteString(fmt.Sprintf("    \"vuln_type\": %q,\n", result.VulnType))
		file.WriteString(fmt.Sprintf("    \"response_time_ms\": %d,\n", result.ResponseTime.Milliseconds()))
		if saveResponses {
			file.WriteString(fmt.Sprintf("    \"response\": %q\n", result.Response))
		} else {
			file.WriteString("    \"response\": null\n")
		}
		file.WriteString("  }")
	}
	file.WriteString("\n]\n")
}

func saveHTML(results []engine.TestResult, file *os.File, saveResponses bool) {
	file.WriteString(`<!DOCTYPE html>
<html>
<head>
    <title>PayloadGo Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .vulnerability { background: #f8f9fa; border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .payload { font-family: monospace; background: #e9ecef; padding: 5px; border-radius: 3px; }
        .vuln-type { color: #dc3545; font-weight: bold; }
        .url { color: #007bff; word-break: break-all; }
        .response { background: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <h1>PayloadGo Scan Results</h1>
    <p>Found <strong>` + fmt.Sprintf("%d", len(results)) + `</strong> potential vulnerabilities</p>`)

	for _, result := range results {
		file.WriteString(`
    <div class="vulnerability">
        <h3><span class="vuln-type">` + result.VulnType + `</span></h3>
        <p><strong>Payload:</strong> <span class="payload">` + result.Payload + `</span></p>
        <p><strong>URL:</strong> <span class="url">` + result.URL + `</span></p>
        <p><strong>Status Code:</strong> ` + fmt.Sprintf("%d", result.StatusCode) + `</p>
        <p><strong>Response Time:</strong> ` + fmt.Sprintf("%dms", result.ResponseTime.Milliseconds()) + `</p>`)

		if saveResponses && result.Response != "" {
			file.WriteString(`
        <p><strong>Response:</strong></p>
        <div class="response">` + result.Response + `</div>`)
		}

		file.WriteString(`
    </div>`)
	}

	file.WriteString(`
</body>
</html>`)
}

func saveTXT(results []engine.TestResult, file *os.File, saveResponses bool) {
	file.WriteString("PayloadGo Scan Results\n")
	file.WriteString("=====================\n\n")
	file.WriteString(fmt.Sprintf("Found %d potential vulnerabilities\n\n", len(results)))

	for i, result := range results {
		file.WriteString(fmt.Sprintf("%d. %s\n", i+1, result.VulnType))
		file.WriteString(fmt.Sprintf("   Payload: %s\n", result.Payload))
		file.WriteString(fmt.Sprintf("   URL: %s\n", result.URL))
		file.WriteString(fmt.Sprintf("   Status: %d\n", result.StatusCode))
		file.WriteString(fmt.Sprintf("   Time: %dms\n", result.ResponseTime.Milliseconds()))

		if saveResponses && result.Response != "" {
			file.WriteString("   Response:\n")
			file.WriteString("   " + strings.Replace(result.Response, "\n", "\n   ", -1) + "\n")
		}

		file.WriteString("\n")
	}
}
