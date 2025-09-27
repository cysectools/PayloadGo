package commands

import (
	"bufio"
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

var fuzzCmd = &cobra.Command{
	Use:   "fuzz [target]",
	Short: "Fuzz a target URL with payloads",
	Long:  `Fuzz a target URL with various payload categories for vulnerability testing.`,
	Args:  cobra.ExactArgs(1),
	Run:   runFuzz,
}

func NewFuzzCommand() *cobra.Command {
	fuzzCmd.Flags().StringP("payloads", "P", "", "payload file or category (xss, sqli, xxe, etc.)")
	fuzzCmd.Flags().StringP("method", "m", "GET", "HTTP method (GET, POST)")
	fuzzCmd.Flags().StringP("data", "d", "", "POST data")
	fuzzCmd.Flags().StringP("headers", "H", "", "custom headers (key:value,key:value)")
	fuzzCmd.Flags().BoolP("interactive", "i", false, "interactive mode")
	return fuzzCmd
}

func runFuzz(cmd *cobra.Command, args []string) {
	config.Init()

	target := args[0]
	payloadFile, _ := cmd.Flags().GetString("payloads")
	// method, _ := cmd.Flags().GetString("method")
	// data, _ := cmd.Flags().GetString("data")
	// headers, _ := cmd.Flags().GetString("headers")
	interactive, _ := cmd.Flags().GetBool("interactive")

	// Interactive mode
	if interactive {
		runInteractiveFuzz(target)
		return
	}

	// Load payloads
	payloadList, err := loadPayloads(payloadFile)
	if err != nil {
		color.Red("❌ Error loading payloads: %v", err)
		return
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

	// Start fuzzing
	color.Cyan("🚀 Starting fuzzing on: %s", target)
	color.Cyan("📦 Payloads: %d", len(payloadList))
	color.Cyan("🧵 Threads: %d", config.AppConfig.Threads)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	go func() {
		reader := bufio.NewReader(os.Stdin)
		reader.ReadString('\n')
		cancel()
	}()

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
	// stats := eng.GetStats()

	color.Green("\n✅ Fuzzing completed!")
	color.Green("📊 Results: %d tested, %d vulnerable, %d errors",
		len(payloadList), vulnerableCount, 0)
	color.Green("⏱️  Duration: %v", duration)
}

func runInteractiveFuzz(target string) {
	reader := bufio.NewReader(os.Stdin)

	color.Cyan("🎯 Interactive Fuzzing Mode")
	color.Cyan("Target: %s", target)

	// Get payload file
	fmt.Print("📄 Payload file (or category: xss, sqli, xxe, all): ")
	payloadInput, _ := reader.ReadString('\n')
	payloadInput = strings.TrimSpace(payloadInput)

	// Load payloads
	payloadList, err := loadPayloads(payloadInput)
	if err != nil {
		color.Red("❌ Error loading payloads: %v", err)
		return
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

	fmt.Print("▶️  Press Enter to begin fuzzing...")
	reader.ReadString('\n')

	// Start fuzzing
	color.Cyan("🚀 Starting fuzzing...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := eng.RunConcurrent(ctx, target, payloadList, "url", "", "")

	vulnerableCount := 0
	for result := range results {
		eng.PrintResult(result, true)
		if result.Vulnerable {
			vulnerableCount++
		}
	}

	// stats := eng.GetStats()
	color.Green("\n✅ Fuzzing completed! Found %d potential vulnerabilities", vulnerableCount)
}

func loadPayloads(input string) ([]string, error) {
	if input == "" {
		return payloads.GetAllPayloads(), nil
	}

	// Check if it's a category
	if category := payloads.GetCategory(input); category != nil {
		return category, nil
	}

	// Try to load from file
	return payloads.LoadFromFile(input)
}
