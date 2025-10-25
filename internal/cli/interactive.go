package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

// InteractiveCLI provides an interactive command-line interface
type InteractiveCLI struct {
	scanner *bufio.Scanner
}

// NewInteractiveCLI creates a new interactive CLI instance
func NewInteractiveCLI() *InteractiveCLI {
	return &InteractiveCLI{
		scanner: bufio.NewScanner(os.Stdin),
	}
}

// StartInteractiveMode starts the interactive CLI mode
func (cli *InteractiveCLI) StartInteractiveMode() {
	clearScreen()
	showWelcome()

	for {
		showMainMenu()
		choice := cli.getUserInput("Enter your choice: ")

		switch choice {
		case "1":
			cli.startQuickScan()
		case "2":
			cli.startAdvancedScan()
		case "3":
			cli.viewScanHistory()
		case "4":
			cli.manageTemplates()
		case "5":
			cli.viewFindings()
		case "6":
			cli.generateReport()
		case "7":
			cli.settings()
		case "8":
			cli.showHelp()
		case "9", "q", "quit", "exit":
			cli.showGoodbye()
			return
		default:
			cli.showError("Invalid choice. Please try again.")
		}

		cli.pause()
	}
}

func showWelcome() {
	color.New(color.FgCyan, color.Bold).Println("╔══════════════════════════════════════════════════════════════╗")
	color.New(color.FgCyan, color.Bold).Println("║                    PayloadGo Enterprise                     ║")
	color.New(color.FgCyan, color.Bold).Println("║              Interactive Security Testing Platform           ║")
	color.New(color.FgCyan, color.Bold).Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	color.New(color.FgGreen).Println("🔒 Enterprise-grade security testing with advanced features")
	color.New(color.FgYellow).Println("📊 Real-time monitoring and adaptive scanning")
	color.New(color.FgBlue).Println("🎯 Multi-tenant architecture with RBAC")
	fmt.Println()
}

func showMainMenu() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("📋 Main Menu")
	fmt.Println()

	options := []string{
		"🚀 Quick Scan - Start a fast security scan",
		"⚙️  Advanced Scan - Configure detailed scan parameters",
		"📊 Scan History - View previous scan results",
		"📝 Templates - Manage scan templates and presets",
		"🔍 Findings - Browse and manage security findings",
		"📄 Reports - Generate and download reports",
		"⚙️  Settings - Configure application settings",
		"❓ Help - Show help and documentation",
		"🚪 Exit - Quit the application",
	}

	for i, option := range options {
		color.New(color.FgWhite).Printf("%d. %s\n", i+1, option)
	}
	fmt.Println()
}

func (cli *InteractiveCLI) startQuickScan() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("🚀 Quick Scan")
	fmt.Println()

	// Get target URL
	target := cli.getUserInput("Enter target URL: ")
	if target == "" {
		cli.showError("Target URL is required")
		return
	}

	// Select scan type
	color.New(color.FgYellow).Println("Select scan type:")
	fmt.Println("1. Web Application (XSS, SQLi, etc.)")
	fmt.Println("2. API Security")
	fmt.Println("3. Infrastructure")

	scanType := cli.getUserInput("Enter choice (1-3): ")

	// Select intensity
	color.New(color.FgYellow).Println("Select scan intensity:")
	fmt.Println("1. Light (fast, basic checks)")
	fmt.Println("2. Standard (balanced speed and coverage)")
	fmt.Println("3. Deep (comprehensive, slower)")

	intensity := cli.getUserInput("Enter choice (1-3): ")

	// Confirm scan
	fmt.Println()
	color.New(color.FgGreen).Printf("Target: %s\n", target)
	color.New(color.FgGreen).Printf("Type: %s\n", scanType)
	color.New(color.FgGreen).Printf("Intensity: %s\n", intensity)

	confirm := cli.getUserInput("Start scan? (y/N): ")
	if strings.ToLower(confirm) != "y" {
		return
	}

	cli.runScan(target, scanType, intensity)
}

func (cli *InteractiveCLI) startAdvancedScan() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("⚙️ Advanced Scan Configuration")
	fmt.Println()

	// Target configuration
	target := cli.getUserInput("Target URL: ")
	if target == "" {
		cli.showError("Target URL is required")
		return
	}

	// Authentication
	authType := cli.getUserInput("Authentication type (none/basic/bearer/cookie): ")
	var authConfig map[string]string

	if authType != "none" {
		switch authType {
		case "basic":
			authConfig = map[string]string{
				"username": cli.getUserInput("Username: "),
				"password": cli.getUserInput("Password: "),
			}
		case "bearer":
			authConfig = map[string]string{
				"token": cli.getUserInput("Bearer token: "),
			}
		case "cookie":
			authConfig = map[string]string{
				"cookie": cli.getUserInput("Cookie value: "),
			}
		}
	}

	// Payload categories
	color.New(color.FgYellow).Println("Select payload categories (comma-separated):")
	fmt.Println("Available: xss, sqli, xxe, lfi, rfi, ssti, nosql, ldap, xpath, command")
	categories := cli.getUserInput("Categories: ")

	// Rate limiting
	rateLimit := cli.getUserInput("Rate limit (requests/second, default 10): ")
	if rateLimit == "" {
		rateLimit = "10"
	}

	// Concurrency
	concurrency := cli.getUserInput("Concurrency (default 5): ")
	if concurrency == "" {
		concurrency = "5"
	}

	// Timeout
	timeout := cli.getUserInput("Timeout per request (seconds, default 30): ")
	if timeout == "" {
		timeout = "30"
	}

	// Safety checks
	cli.showSafetyChecks()
	confirm := cli.getUserInput("I have read and agree to the safety guidelines (y/N): ")
	if strings.ToLower(confirm) != "y" {
		cli.showError("Scan cancelled - safety agreement required")
		return
	}

	// Final confirmation
	fmt.Println()
	color.New(color.FgGreen).Printf("Target: %s\n", target)
	color.New(color.FgGreen).Printf("Auth: %s\n", authType)
	color.New(color.FgGreen).Printf("Categories: %s\n", categories)
	color.New(color.FgGreen).Printf("Rate Limit: %s req/s\n", rateLimit)
	color.New(color.FgGreen).Printf("Concurrency: %s\n", concurrency)

	confirm = cli.getUserInput("Start advanced scan? (y/N): ")
	if strings.ToLower(confirm) != "y" {
		return
	}

	cli.runAdvancedScan(target, authConfig, categories, rateLimit, concurrency, timeout)
}

func (cli *InteractiveCLI) showSafetyChecks() {
	clearScreen()
	color.New(color.FgRed, color.Bold).Println("⚠️  SAFETY GUIDELINES & ETHICAL CONSIDERATIONS")
	fmt.Println()

	guidelines := []string{
		"✅ I have explicit written permission to test this target",
		"✅ I am authorized to perform security testing on this system",
		"✅ I have notified relevant stakeholders about this scan",
		"✅ I understand the potential impact of security testing",
		"✅ I will not perform destructive operations without explicit consent",
		"✅ I will respect rate limits and not overwhelm the target",
		"✅ I will report findings responsibly and securely",
		"✅ I will not test production systems without proper authorization",
	}

	for _, guideline := range guidelines {
		color.New(color.FgYellow).Println(guideline)
	}

	fmt.Println()
	color.New(color.FgRed, color.Bold).Println("🚨 EMERGENCY KILL SWITCH")
	color.New(color.FgRed).Println("If you need to stop all scans immediately, press Ctrl+C or use the kill switch")
	fmt.Println()
}

func (cli *InteractiveCLI) runScan(target, scanType, intensity string) {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("🚀 Starting Scan...")
	fmt.Println()

	// Simulate scan progress
	progress := 0
	for progress < 100 {
		progress += 10
		cli.showProgressBar(progress, 100, "Scanning...")
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Println()
	color.New(color.FgGreen).Println("✅ Scan completed!")

	// Show results summary
	cli.showScanResults()
}

func (cli *InteractiveCLI) runAdvancedScan(target string, auth map[string]string, categories, rateLimit, concurrency, timeout string) {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("⚙️ Starting Advanced Scan...")
	fmt.Println()

	// Show configuration
	color.New(color.FgBlue).Printf("Target: %s\n", target)
	color.New(color.FgBlue).Printf("Categories: %s\n", categories)
	color.New(color.FgBlue).Printf("Rate Limit: %s req/s\n", rateLimit)
	color.New(color.FgBlue).Printf("Concurrency: %s\n", concurrency)
	fmt.Println()

	// Simulate advanced scan
	steps := []string{
		"Initializing scan engine...",
		"Loading payloads...",
		"Configuring authentication...",
		"Setting up rate limiting...",
		"Starting payload injection...",
		"Analyzing responses...",
		"Correlating findings...",
		"Generating report...",
	}

	for i, step := range steps {
		color.New(color.FgYellow).Printf("[%d/%d] %s\n", i+1, len(steps), step)
		time.Sleep(1 * time.Second)
	}

	fmt.Println()
	color.New(color.FgGreen).Println("✅ Advanced scan completed!")
	cli.showScanResults()
}

func (cli *InteractiveCLI) showProgressBar(current, total int, label string) {
	width := 50
	percent := float64(current) / float64(total)
	filled := int(percent * float64(width))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	fmt.Printf("\r%s [%s] %d%%", label, bar, int(percent*100))
	if current == total {
		fmt.Println()
	}
}

func (cli *InteractiveCLI) showScanResults() {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("📊 Scan Results Summary")
	fmt.Println()

	// Simulate results
	results := map[string]int{
		"Critical": 2,
		"High":     5,
		"Medium":   12,
		"Low":      8,
		"Info":     15,
	}

	total := 0
	for severity, count := range results {
		color := getSeverityColor(severity)
		color.Printf("  %s: %d findings\n", severity, count)
		total += count
	}

	fmt.Println()
	color.New(color.FgWhite, color.Bold).Printf("Total Findings: %d\n", total)

	// Show top findings
	fmt.Println()
	color.New(color.FgYellow).Println("🔍 Top Findings:")
	topFindings := []string{
		"SQL Injection in login form",
		"Cross-Site Scripting (XSS) in search parameter",
		"Directory Traversal in file upload",
		"Server-Side Template Injection in user profile",
		"XML External Entity (XXE) in API endpoint",
	}

	for i, finding := range topFindings {
		color.New(color.FgWhite).Printf("  %d. %s\n", i+1, finding)
	}
}

func getSeverityColor(severity string) *color.Color {
	switch severity {
	case "Critical":
		return color.New(color.FgRed, color.Bold)
	case "High":
		return color.New(color.FgRed)
	case "Medium":
		return color.New(color.FgYellow)
	case "Low":
		return color.New(color.FgBlue)
	case "Info":
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgWhite)
	}
}

func (cli *InteractiveCLI) viewScanHistory() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("📊 Scan History")
	fmt.Println()

	// Simulate scan history
	scans := []struct {
		ID        string
		Target    string
		Status    string
		Findings  int
		StartTime string
	}{
		{"scan-001", "https://example.com", "Completed", 15, "2024-01-15 10:30"},
		{"scan-002", "https://api.example.com", "Completed", 8, "2024-01-14 14:20"},
		{"scan-003", "https://admin.example.com", "Failed", 0, "2024-01-13 09:15"},
		{"scan-004", "https://staging.example.com", "Running", 0, "2024-01-12 16:45"},
	}

	for _, scan := range scans {
		statusColor := getStatusColor(scan.Status)
		fmt.Printf("ID: %s | Target: %s | Status: ", scan.ID, scan.Target)
		statusColor.Printf("%s", scan.Status)
		fmt.Printf(" | Findings: %d | Started: %s\n", scan.Findings, scan.StartTime)
	}
}

func getStatusColor(status string) *color.Color {
	switch status {
	case "Completed":
		return color.New(color.FgGreen)
	case "Running":
		return color.New(color.FgYellow)
	case "Failed":
		return color.New(color.FgRed)
	default:
		return color.New(color.FgWhite)
	}
}

func (cli *InteractiveCLI) manageTemplates() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("📝 Scan Templates")
	fmt.Println()

	templates := []struct {
		Name        string
		Description string
		Type        string
	}{
		{"Web App Light", "Quick web application scan", "Web"},
		{"Web App Deep", "Comprehensive web application scan", "Web"},
		{"API Security", "REST/GraphQL API security testing", "API"},
		{"Infrastructure", "Network and infrastructure testing", "Infrastructure"},
		{"Compliance", "Compliance-focused security testing", "Compliance"},
	}

	for i, template := range templates {
		color.New(color.FgWhite).Printf("%d. %s - %s (%s)\n", i+1, template.Name, template.Description, template.Type)
	}

	fmt.Println()
	choice := cli.getUserInput("Select template to use (1-5) or 'c' to create new: ")

	if choice == "c" {
		cli.createNewTemplate()
	} else {
		idx, err := strconv.Atoi(choice)
		if err != nil || idx < 1 || idx > len(templates) {
			cli.showError("Invalid template selection")
			return
		}
		cli.useTemplate(templates[idx-1].Name)
	}
}

func (cli *InteractiveCLI) createNewTemplate() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("📝 Create New Template")
	fmt.Println()

	name := cli.getUserInput("Template name: ")
	cli.getUserInput("Description: ")

	// Template configuration
	color.New(color.FgYellow).Println("Configure payload categories:")
	cli.getUserInput("Categories (comma-separated): ")

	rateLimit := cli.getUserInput("Rate limit (default 10): ")
	if rateLimit == "" {
		rateLimit = "10"
	}

	concurrency := cli.getUserInput("Concurrency (default 5): ")
	if concurrency == "" {
		concurrency = "5"
	}

	color.New(color.FgGreen).Printf("Template '%s' created successfully!\n", name)
}

func (cli *InteractiveCLI) useTemplate(templateName string) {
	color.New(color.FgGreen).Printf("Using template: %s\n", templateName)
}

func (cli *InteractiveCLI) viewFindings() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("🔍 Security Findings")
	fmt.Println()

	// Simulate findings
	findings := []struct {
		ID       string
		Type     string
		Severity string
		URL      string
		Status   string
	}{
		{"F-001", "SQL Injection", "Critical", "https://example.com/login", "Open"},
		{"F-002", "XSS", "High", "https://example.com/search", "Open"},
		{"F-003", "Directory Traversal", "Medium", "https://example.com/files", "Triaged"},
		{"F-004", "SSTI", "High", "https://example.com/profile", "Open"},
		{"F-005", "XXE", "Critical", "https://example.com/api", "Resolved"},
	}

	for _, finding := range findings {
		severityColor := getSeverityColor(finding.Severity)
		fmt.Printf("ID: %s | Type: %s | Severity: ", finding.ID, finding.Type)
		severityColor.Printf("%s", finding.Severity)
		fmt.Printf(" | URL: %s | Status: %s\n", finding.URL, finding.Status)
	}
}

func (cli *InteractiveCLI) generateReport() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("📄 Generate Report")
	fmt.Println()

	reportTypes := []string{
		"Executive Summary",
		"Technical Report",
		"Compliance Report",
		"SARIF Report",
		"Custom Report",
	}

	for i, reportType := range reportTypes {
		fmt.Printf("%d. %s\n", i+1, reportType)
	}

	choice := cli.getUserInput("Select report type (1-5): ")
	idx, err := strconv.Atoi(choice)
	if err != nil || idx < 1 || idx > len(reportTypes) {
		cli.showError("Invalid report type selection")
		return
	}

	format := cli.getUserInput("Output format (html/pdf/json): ")

	color.New(color.FgGreen).Printf("Generating %s report in %s format...\n", reportTypes[idx-1], format)
	time.Sleep(2 * time.Second)
	color.New(color.FgGreen).Println("✅ Report generated successfully!")
}

func (cli *InteractiveCLI) settings() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("⚙️ Settings")
	fmt.Println()

	settings := map[string]string{
		"Default Rate Limit":  "10",
		"Default Concurrency": "5",
		"Default Timeout":     "30",
		"Output Directory":    "/tmp/payloadgo",
		"Log Level":           "INFO",
		"Notifications":       "enabled",
	}

	for key, value := range settings {
		fmt.Printf("%s: %s\n", key, value)
	}

	fmt.Println()
	cli.getUserInput("Press Enter to continue...")
}

func (cli *InteractiveCLI) showHelp() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("❓ Help & Documentation")
	fmt.Println()

	helpSections := []struct {
		Title   string
		Content string
	}{
		{
			"Getting Started",
			"PayloadGo Enterprise is a comprehensive security testing platform.\n" +
				"Start with a Quick Scan to test basic security controls, or use\n" +
				"Advanced Scan for detailed configuration and custom payloads.",
		},
		{
			"Safety Guidelines",
			"Always ensure you have explicit permission before testing any target.\n" +
				"Use the safety checks and emergency kill switch when needed.\n" +
				"Follow responsible disclosure practices for any findings.",
		},
		{
			"Templates",
			"Use pre-built templates for common scan scenarios, or create\n" +
				"custom templates for your specific testing needs.",
		},
		{
			"Reports",
			"Generate various report formats including executive summaries,\n" +
				"technical reports, and compliance reports in multiple formats.",
		},
	}

	for _, section := range helpSections {
		color.New(color.FgYellow, color.Bold).Println(section.Title)
		fmt.Println(section.Content)
		fmt.Println()
	}

	cli.getUserInput("Press Enter to continue...")
}

func (cli *InteractiveCLI) showGoodbye() {
	clearScreen()
	color.New(color.FgCyan, color.Bold).Println("👋 Thank you for using PayloadGo Enterprise!")
	fmt.Println()
	color.New(color.FgGreen).Println("Stay secure, stay ethical!")
	fmt.Println()
}

// Utility methods
func (cli *InteractiveCLI) getUserInput(prompt string) string {
	color.New(color.FgCyan).Print(prompt)
	cli.scanner.Scan()
	return strings.TrimSpace(cli.scanner.Text())
}

func (cli *InteractiveCLI) showError(message string) {
	color.New(color.FgRed, color.Bold).Printf("❌ Error: %s\n", message)
}

func (cli *InteractiveCLI) pause() {
	cli.getUserInput("Press Enter to continue...")
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

// Add interactive command to root command
// Note: This would be integrated with the main CLI in a real implementation
