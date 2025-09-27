package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"payloadgo/internal/config"
	"payloadgo/internal/engine"
	"payloadgo/internal/payloads"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Interactive menu for PayloadGo",
	Long:  `Launch an interactive menu to guide you through using PayloadGo without needing to remember command-line flags.`,
	Run:   runMenu,
}

func NewMenuCommand() *cobra.Command {
	return menuCmd
}

// RunMenu is the public function that can be called from CLI
func RunMenu() {
	runMenu(nil, nil)
}

func runMenu(cmd *cobra.Command, args []string) {
	config.Init()

	reader := bufio.NewReader(os.Stdin)

	for {
		showMainMenu()

		fmt.Print("Choose an option: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			runInteractiveFuzzMenu(reader)
		case "2":
			runInteractiveScanMenu(reader)
		case "3":
			runInteractiveReportMenu(reader)
		case "4":
			showSettings(reader)
		case "5":
			showHelp(reader)
		case "6":
			color.Green("👋 Thanks for using PayloadGo! Stay safe out there.")
			os.Exit(0)
		default:
			color.Red("❌ Invalid option. Please try again.")
		}

		fmt.Println("\n" + strings.Repeat("-", 50))
	}
}

func showMainMenu() {
	color.Cyan("\n🚀 PayloadGo - Professional Payload Testing Tool")
	color.Cyan("=" + strings.Repeat("=", 45))
	fmt.Println()
	color.White("1. 🔍 Quick Fuzz Test")
	color.White("2. 🛡️  Comprehensive Scan")
	color.White("3. 📊 Generate Report")
	color.White("4. ⚙️  Settings")
	color.White("5. ❓ Help")
	color.White("6. 🚪 Exit")
	fmt.Println()
}

func runInteractiveFuzzMenu(reader *bufio.Reader) {
	color.Cyan("\n🔍 Quick Fuzz Test")
	color.Cyan("=" + strings.Repeat("=", 20))

	// Get target URL
	fmt.Print("Enter target URL (with TEST placeholder): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" {
		color.Red("❌ Target URL is required!")
		return
	}

	if !strings.Contains(target, "TEST") {
		color.Yellow("⚠️  Warning: URL doesn't contain 'TEST' placeholder. Adding it...")
		if strings.Contains(target, "?") {
			target += "&test=TEST"
		} else {
			target += "?test=TEST"
		}
	}

	// Get payload category
	fmt.Println("\nAvailable payload categories:")
	categories := payloads.GetCategories()
	for i, cat := range categories {
		fmt.Printf("  %d. %s\n", i+1, strings.ToUpper(cat))
	}
	fmt.Print("Choose category (1-", len(categories), "): ")
	catChoice, _ := reader.ReadString('\n')
	catChoice = strings.TrimSpace(catChoice)

	catIndex, err := strconv.Atoi(catChoice)
	if err != nil || catIndex < 1 || catIndex > len(categories) {
		color.Red("❌ Invalid category choice!")
		return
	}

	selectedCategory := categories[catIndex-1]
	payloadList := payloads.GetCategory(selectedCategory)

	// Get threads
	fmt.Print("Number of threads (default 5): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	threads := 5
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			threads = t
		}
	}

	// Get timeout
	fmt.Print("Timeout in seconds (default 10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 10
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = t
		}
	}

	// Confirm and run
	color.Cyan("\n📋 Fuzz Test Configuration:")
	color.White("Target: %s", target)
	color.White("Category: %s (%d payloads)", strings.ToUpper(selectedCategory), len(payloadList))
	color.White("Threads: %d", threads)
	color.White("Timeout: %ds", timeout)

	fmt.Print("\n▶️  Start fuzzing? (y/N): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		color.Yellow("❌ Fuzzing cancelled.")
		return
	}

	// Run fuzzing
	runFuzzWithParams(target, selectedCategory, threads, timeout)
}

func runInteractiveScanMenu(reader *bufio.Reader) {
	color.Cyan("\n🛡️  Comprehensive Scan")
	color.Cyan("=" + strings.Repeat("=", 22))

	// Get target URL
	fmt.Print("Enter target URL (with TEST placeholder): ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" {
		color.Red("❌ Target URL is required!")
		return
	}

	if !strings.Contains(target, "TEST") {
		color.Yellow("⚠️  Warning: URL doesn't contain 'TEST' placeholder. Adding it...")
		if strings.Contains(target, "?") {
			target += "&test=TEST"
		} else {
			target += "?test=TEST"
		}
	}

	// Get categories
	fmt.Println("\nAvailable payload categories:")
	categories := payloads.GetCategories()
	for i, cat := range categories {
		fmt.Printf("  %d. %s\n", i+1, strings.ToUpper(cat))
	}
	fmt.Print("Choose categories (comma-separated, e.g., 1,2,3 or 'all'): ")
	catChoice, _ := reader.ReadString('\n')
	catChoice = strings.TrimSpace(catChoice)

	var selectedCategories []string
	if catChoice == "all" {
		selectedCategories = categories
	} else {
		parts := strings.Split(catChoice, ",")
		for _, part := range parts {
			if index, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && index >= 1 && index <= len(categories) {
				selectedCategories = append(selectedCategories, categories[index-1])
			}
		}
	}

	if len(selectedCategories) == 0 {
		color.Red("❌ No valid categories selected!")
		return
	}

	// Get output format
	fmt.Println("\nOutput formats:")
	fmt.Println("  1. JSON")
	fmt.Println("  2. HTML")
	fmt.Println("  3. TXT")
	fmt.Print("Choose format (1-3, default 1): ")
	formatChoice, _ := reader.ReadString('\n')
	formatChoice = strings.TrimSpace(formatChoice)

	format := "json"
	switch formatChoice {
	case "2":
		format = "html"
	case "3":
		format = "txt"
	}

	// Get output file
	fmt.Print("Output file (optional): ")
	outputFile, _ := reader.ReadString('\n')
	outputFile = strings.TrimSpace(outputFile)

	// Get threads
	fmt.Print("Number of threads (default 10): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	threads := 10
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			threads = t
		}
	}

	// Confirm and run
	color.Cyan("\n📋 Scan Configuration:")
	color.White("Target: %s", target)
	color.White("Categories: %s", strings.Join(selectedCategories, ", "))
	color.White("Format: %s", strings.ToUpper(format))
	if outputFile != "" {
		color.White("Output: %s", outputFile)
	}
	color.White("Threads: %d", threads)

	fmt.Print("\n▶️  Start scanning? (y/N): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		color.Yellow("❌ Scanning cancelled.")
		return
	}

	// Run scanning
	runScanWithParams(target, selectedCategories, format, outputFile, threads)
}

func runInteractiveReportMenu(reader *bufio.Reader) {
	color.Cyan("\n📊 Generate Report")
	color.Cyan("=" + strings.Repeat("=", 18))

	// Get input file
	fmt.Print("Enter results file path: ")
	inputFile, _ := reader.ReadString('\n')
	inputFile = strings.TrimSpace(inputFile)

	if inputFile == "" {
		color.Red("❌ Input file is required!")
		return
	}

	// Check if file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		color.Red("❌ File does not exist: %s", inputFile)
		return
	}

	// Get output format
	fmt.Println("\nOutput formats:")
	fmt.Println("  1. HTML")
	fmt.Println("  2. PDF")
	fmt.Println("  3. TXT")
	fmt.Print("Choose format (1-3, default 1): ")
	formatChoice, _ := reader.ReadString('\n')
	formatChoice = strings.TrimSpace(formatChoice)

	format := "html"
	switch formatChoice {
	case "2":
		format = "pdf"
	case "3":
		format = "txt"
	}

	// Get output file
	fmt.Print("Output file (optional): ")
	outputFile, _ := reader.ReadString('\n')
	outputFile = strings.TrimSpace(outputFile)

	// Get summary option
	fmt.Print("Generate summary only? (y/N): ")
	summaryChoice, _ := reader.ReadString('\n')
	summaryChoice = strings.TrimSpace(strings.ToLower(summaryChoice))
	summary := summaryChoice == "y" || summaryChoice == "yes"

	// Confirm and run
	color.Cyan("\n📋 Report Configuration:")
	color.White("Input: %s", inputFile)
	color.White("Format: %s", strings.ToUpper(format))
	if outputFile != "" {
		color.White("Output: %s", outputFile)
	}
	color.White("Summary: %t", summary)

	fmt.Print("\n▶️  Generate report? (y/N): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "y" && confirm != "yes" {
		color.Yellow("❌ Report generation cancelled.")
		return
	}

	// Run report generation
	runReportWithParams(inputFile, format, outputFile, summary)
}

func showSettings(reader *bufio.Reader) {
	color.Cyan("\n⚙️  Settings")
	color.Cyan("=" + strings.Repeat("=", 10))

	fmt.Println("Current configuration:")
	color.White("Threads: %d", config.AppConfig.Threads)
	color.White("Timeout: %ds", config.AppConfig.Timeout)
	color.White("User Agent: %s", config.AppConfig.UserAgent)
	if config.AppConfig.Proxy != "" {
		color.White("Proxy: %s", config.AppConfig.Proxy)
	} else {
		color.White("Proxy: None")
	}
	color.White("Verbose: %t", config.AppConfig.Verbose)

	fmt.Print("\nPress Enter to continue...")
	reader.ReadString('\n')
}

func showHelp(reader *bufio.Reader) {
	color.Cyan("\n❓ Help")
	color.Cyan("=" + strings.Repeat("=", 6))

	fmt.Println("PayloadGo is a professional payload testing tool for bug bounty hunters.")
	fmt.Println()
	fmt.Println("Features:")
	color.Green("• Concurrent payload testing with worker pools")
	color.Green("• Advanced vulnerability detection")
	color.Green("• Professional reporting (JSON, HTML, TXT)")
	color.Green("• Rate limiting and proxy support")
	color.Green("• Interactive menu system")
	fmt.Println()
	fmt.Println("Payload Categories:")
	categories := payloads.GetCategories()
	for _, cat := range categories {
		color.White("• %s", strings.ToUpper(cat))
	}
	fmt.Println()
	fmt.Println("For command-line usage, use:")
	color.Yellow("  payloadgo fuzz --help")
	color.Yellow("  payloadgo scan --help")
	color.Yellow("  payloadgo report --help")

	fmt.Print("\nPress Enter to continue...")
	reader.ReadString('\n')
}

// Helper functions to run the actual operations
func runFuzzWithParams(target, category string, threads, timeout int) {
	color.Cyan("🚀 Starting fuzzing...")

	// Load payloads
	payloadList := payloads.GetCategory(category)
	if len(payloadList) == 0 {
		color.Red("❌ No payloads found for category: %s", category)
		return
	}

	// Create engine
	eng, err := engine.NewEngine(
		threads,
		time.Duration(timeout)*time.Second,
		config.AppConfig.UserAgent,
		config.AppConfig.Proxy,
	)
	if err != nil {
		color.Red("❌ Error creating engine: %v", err)
		return
	}

	// Start fuzzing
	color.Cyan("📦 Payloads: %d", len(payloadList))
	color.Cyan("🧵 Threads: %d", threads)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()
	results := eng.RunConcurrent(ctx, target, payloadList, "url", "", "")

	vulnerableCount := 0
	for result := range results {
		eng.PrintResult(result, config.AppConfig.Verbose)
		if result.Vulnerable {
			vulnerableCount++
		}
	}

	duration := time.Since(startTime)
	color.Green("\n✅ Fuzzing completed!")
	color.Green("📊 Results: %d tested, %d vulnerable, %d errors",
		len(payloadList), vulnerableCount, 0)
	color.Green("⏱️  Duration: %v", duration)
}

func runScanWithParams(target string, categories []string, format, outputFile string, threads int) {
	color.Cyan("🔍 Starting comprehensive scan...")

	// Load payloads based on categories
	var allPayloads []string
	for _, category := range categories {
		if payloads := payloads.GetCategory(category); payloads != nil {
			allPayloads = append(allPayloads, payloads...)
		}
	}

	if len(allPayloads) == 0 {
		color.Red("❌ No payloads found for selected categories")
		return
	}

	// Create engine
	eng, err := engine.NewEngine(
		threads,
		time.Duration(config.AppConfig.Timeout)*time.Second,
		config.AppConfig.UserAgent,
		config.AppConfig.Proxy,
	)
	if err != nil {
		color.Red("❌ Error creating engine: %v", err)
		return
	}

	// Start scanning
	color.Cyan("📦 Payloads: %d", len(allPayloads))
	color.Cyan("🧵 Threads: %d", threads)

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
		saveResults(vulnerableResults, outputFile, format, false)
	}
}

func runReportWithParams(inputFile, format, outputFile string, summary bool) {
	color.Cyan("📊 Generating report...")

	// Load results
	results, err := loadResults(inputFile)
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
		generateHTMLReport(results, outputFile, "", summary)
	case "pdf":
		generatePDFReport(results, outputFile, "", summary)
	case "txt":
		generateTXTReport(results, outputFile, summary)
	default:
		color.Red("❌ Unknown format: %s", format)
		return
	}

	color.Green("📄 Report generated: %s", outputFile)
}
