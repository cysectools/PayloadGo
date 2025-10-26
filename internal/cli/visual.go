package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// VisualCLI provides enhanced visual CLI capabilities
type VisualCLI struct {
	primaryColor *color.Color
	successColor *color.Color
	warningColor *color.Color
	errorColor   *color.Color
	infoColor    *color.Color
	accentColor  *color.Color
	dimColor     *color.Color
}

// NewVisualCLI creates a new visual CLI instance
func NewVisualCLI() *VisualCLI {
	return &VisualCLI{
		primaryColor: color.New(color.FgCyan, color.Bold),
		successColor: color.New(color.FgGreen, color.Bold),
		warningColor: color.New(color.FgYellow, color.Bold),
		errorColor:   color.New(color.FgRed, color.Bold),
		infoColor:    color.New(color.FgBlue, color.Bold),
		accentColor:  color.New(color.FgMagenta, color.Bold),
		dimColor:     color.New(color.FgWhite, color.Faint),
	}
}

// ShowBanner displays the PayloadGo Enterprise banner
func (v *VisualCLI) ShowBanner() {
	// Clear screen
	fmt.Print("\033[2J\033[H")

	// ASCII Art Banner
	banner := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗  █████╗ ██╗   ██╗██╗     ██████╗  ██████╗ ██╗    ██╗ ██████╗     ║
║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██║    ██╔═══██╗██╔═══██╗██║    ██║██╔═══██╗    ║
║    ██████╔╝███████║ ╚████╔╝ ██║    ██║   ██║██║   ██║██║ █╗ ██║██║   ██║    ║
║    ██╔═══╝ ██╔══██║  ╚██╔╝  ██║    ██║   ██║██║   ██║██║███╗██║██║   ██║    ║
║    ██║     ██║  ██║   ██║   ██║    ╚██████╔╝╚██████╔╝╚███╔███╔╝╚██████╔╝    ║
║    ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝     ║
║                                                                              ║
║                           🚀 ENTERPRISE EDITION 🚀                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝`

	v.primaryColor.Println(banner)
	fmt.Println()

	// Version and build info
	v.infoColor.Print("Version: ")
	fmt.Print("1.0.0 Enterprise")
	v.infoColor.Print(" | Build: ")
	fmt.Print("2024.01.15")
	v.infoColor.Print(" | Platform: ")
	fmt.Print("Multi-Platform")
	fmt.Println()

	// Tagline
	v.accentColor.Println("🔒 Enterprise-Grade Security Testing Platform")
	v.dimColor.Println("   Modular • Observable • Safe-by-Default • Auditable")
	fmt.Println()
}

// ShowWelcome displays a professional welcome message
func (v *VisualCLI) ShowWelcome() {
	v.successColor.Println("🎉 Welcome to PayloadGo Enterprise!")
	fmt.Println()

	// Feature highlights
	features := []string{
		"🔍 Advanced vulnerability detection with ML-powered confidence scoring",
		"🛡️  Multi-tenant architecture with role-based access control",
		"📊 Comprehensive reporting with executive and technical formats",
		"⚡ Adaptive concurrency with circuit breaker protection",
		"🔒 Safe-by-default design with ethical guidelines enforcement",
		"📈 Real-time monitoring and observability",
		"🌐 Modern web UI and interactive CLI",
		"🔧 Enterprise integrations and API-first design",
	}

	for _, feature := range features {
		v.dimColor.Print("   ")
		fmt.Println(feature)
		time.Sleep(100 * time.Millisecond) // Animate the display
	}

	fmt.Println()
}

// ShowMainMenu displays the enhanced main menu
func (v *VisualCLI) ShowMainMenu() {
	fmt.Println()
	v.primaryColor.Println("📋 MAIN MENU")
	fmt.Println()

	menuItems := []struct {
		icon    string
		title   string
		desc    string
		command string
	}{
		{"🚀", "Quick Scan", "Start a fast security scan with default settings", "scan --quick"},
		{"⚙️", "Advanced Scan", "Configure detailed scan parameters and options", "scan --advanced"},
		{"📊", "Interactive Mode", "Launch the interactive CLI with guided workflows", "interactive"},
		{"🌐", "Web Dashboard", "Start the web UI dashboard", "server --web"},
		{"📄", "Generate Report", "Create reports from previous scan results", "report"},
		{"🔍", "View Findings", "Browse and manage security findings", "findings"},
		{"📈", "Metrics", "View performance and security metrics", "metrics"},
		{"⚙️", "Settings", "Configure application settings", "config"},
		{"❓", "Help", "Show help and documentation", "help"},
		{"🚪", "Exit", "Exit the application", "exit"},
	}

	for i, item := range menuItems {
		v.primaryColor.Printf("%d. %s %s", i+1, item.icon, item.title)
		v.dimColor.Printf(" - %s", item.desc)
		fmt.Println()
	}

	fmt.Println()
	v.accentColor.Print("Enter your choice (1-10): ")
}

// ShowScanProgress displays an animated progress bar
func (v *VisualCLI) ShowScanProgress(current, total int, status string) {
	percentage := float64(current) / float64(total) * 100
	barWidth := 50
	filled := int(percentage / 100 * float64(barWidth))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	fmt.Printf("\r%s [%s] %.1f%% (%d/%d) %s",
		v.primaryColor.Sprint("Scanning"),
		bar,
		percentage,
		current,
		total,
		v.infoColor.Sprint(status))

	if current == total {
		fmt.Println()
	}
}

// ShowResults displays scan results in a professional format
func (v *VisualCLI) ShowResults(results map[string]int) {
	fmt.Println()
	v.successColor.Println("✅ SCAN COMPLETED")
	fmt.Println()

	// Results summary
	v.infoColor.Println("📊 Results Summary:")
	fmt.Println()

	severityColors := map[string]*color.Color{
		"Critical": v.errorColor,
		"High":     v.errorColor,
		"Medium":   v.warningColor,
		"Low":      v.infoColor,
		"Info":     v.dimColor,
	}

	total := 0
	for severity, count := range results {
		if severityColors[severity] != nil {
			severityColors[severity].Printf("   %s: %d findings\n", severity, count)
		}
		total += count
	}

	fmt.Println()
	v.primaryColor.Printf("Total Findings: %d\n", total)
	fmt.Println()

	// Top findings
	if total > 0 {
		v.warningColor.Println("🔍 Top Findings:")
		topFindings := []string{
			"SQL Injection in login form",
			"Cross-Site Scripting (XSS) in search parameter",
			"Directory Traversal in file upload",
			"Server-Side Template Injection in user profile",
			"XML External Entity (XXE) in API endpoint",
		}

		for i, finding := range topFindings {
			if i < 5 {
				v.dimColor.Printf("   %d. %s\n", i+1, finding)
			}
		}
	}
}

// ShowError displays errors in a professional format
func (v *VisualCLI) ShowError(message string) {
	fmt.Println()
	v.errorColor.Printf("❌ Error: %s\n", message)
	fmt.Println()
}

// ShowSuccess displays success messages
func (v *VisualCLI) ShowSuccess(message string) {
	fmt.Println()
	v.successColor.Printf("✅ %s\n", message)
	fmt.Println()
}

// ShowWarning displays warning messages
func (v *VisualCLI) ShowWarning(message string) {
	fmt.Println()
	v.warningColor.Printf("⚠️  Warning: %s\n", message)
	fmt.Println()
}

// ShowInfo displays informational messages
func (v *VisualCLI) ShowInfo(message string) {
	fmt.Println()
	v.infoColor.Printf("ℹ️  %s\n", message)
	fmt.Println()
}

// ShowTable displays data in a formatted table
func (v *VisualCLI) ShowTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		v.dimColor.Println("No data to display")
		return
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}

	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	v.primaryColor.Print("┌")
	for i, width := range widths {
		if i > 0 {
			v.primaryColor.Print("┬")
		}
		v.primaryColor.Print(strings.Repeat("─", width+2))
	}
	v.primaryColor.Println("┐")

	// Print header row
	v.primaryColor.Print("│")
	for i, header := range headers {
		if i > 0 {
			v.primaryColor.Print("│")
		}
		fmt.Printf(" %-*s ", widths[i], header)
	}
	v.primaryColor.Println("│")

	// Print separator
	v.primaryColor.Print("├")
	for i, width := range widths {
		if i > 0 {
			v.primaryColor.Print("┼")
		}
		v.primaryColor.Print(strings.Repeat("─", width+2))
	}
	v.primaryColor.Println("┤")

	// Print data rows
	for _, row := range rows {
		v.primaryColor.Print("│")
		for i, cell := range row {
			if i > 0 {
				v.primaryColor.Print("│")
			}
			fmt.Printf(" %-*s ", widths[i], cell)
		}
		v.primaryColor.Println("│")
	}

	// Print footer
	v.primaryColor.Print("└")
	for i, width := range widths {
		if i > 0 {
			v.primaryColor.Print("┴")
		}
		v.primaryColor.Print(strings.Repeat("─", width+2))
	}
	v.primaryColor.Println("┘")
}

// ShowSpinner displays an animated spinner
func (v *VisualCLI) ShowSpinner(message string) {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

	for i := 0; i < 20; i++ {
		fmt.Printf("\r%s %s %s",
			spinner[i%len(spinner)],
			v.infoColor.Sprint(message),
			strings.Repeat(" ", 20))
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println()
}

// ShowCountdown displays a countdown timer
func (v *VisualCLI) ShowCountdown(seconds int, message string) {
	for i := seconds; i > 0; i-- {
		fmt.Printf("\r%s %s %d seconds remaining...",
			v.warningColor.Sprint("⏰"),
			message,
			i)
		time.Sleep(1 * time.Second)
	}
	fmt.Println()
}

// ShowStats displays real-time statistics
func (v *VisualCLI) ShowStats(stats map[string]interface{}) {
	fmt.Println()
	v.primaryColor.Println("📈 Real-time Statistics")
	fmt.Println()

	for key, value := range stats {
		v.infoColor.Printf("   %s: ", key)
		fmt.Printf("%v\n", value)
	}
	fmt.Println()
}

// ShowHelp displays enhanced help information
func (v *VisualCLI) ShowHelp() {
	fmt.Println()
	v.primaryColor.Println("❓ HELP & DOCUMENTATION")
	fmt.Println()

	helpSections := []struct {
		title   string
		content string
	}{
		{
			"Getting Started",
			"PayloadGo Enterprise is a comprehensive security testing platform.\n" +
				"Start with a Quick Scan for basic testing, or use Advanced Scan for\n" +
				"detailed configuration and custom payloads.",
		},
		{
			"Safety Guidelines",
			"Always ensure you have explicit permission before testing any target.\n" +
				"Use the safety checks and emergency kill switch when needed.\n" +
				"Follow responsible disclosure practices for any findings.",
		},
		{
			"Key Features",
			"• Multi-tenant architecture with RBAC\n" +
				"• ML-powered confidence scoring\n" +
				"• Comprehensive reporting (Executive, Technical, SARIF)\n" +
				"• Real-time monitoring and metrics\n" +
				"• Interactive CLI and Web UI\n" +
				"• Enterprise integrations and API",
		},
		{
			"Quick Commands",
			"• payloadgo scan --target https://example.com\n" +
				"• payloadgo interactive\n" +
				"• payloadgo server --web\n" +
				"• payloadgo report --format html\n" +
				"• payloadgo findings --severity critical",
		},
	}

	for _, section := range helpSections {
		v.accentColor.Println(section.title)
		fmt.Println(section.content)
		fmt.Println()
	}

	v.infoColor.Println("📚 For complete documentation, visit: https://docs.payloadgo.com")
	v.infoColor.Println("💬 Community support: https://github.com/payloadgo/payloadgo/discussions")
	v.infoColor.Println("🏢 Enterprise support: support@payloadgo.com")
}

// ShowGoodbye displays a professional goodbye message
func (v *VisualCLI) ShowGoodbye() {
	fmt.Println()
	v.successColor.Println("👋 Thank you for using PayloadGo Enterprise!")
	fmt.Println()
	v.dimColor.Println("Stay secure, stay ethical!")
	fmt.Println()
	v.accentColor.Println("🔒 PayloadGo Enterprise - Secure, Scalable, Enterprise-Ready")
	fmt.Println()
}
