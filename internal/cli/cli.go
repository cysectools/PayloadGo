package cli

import (
	"fmt"

	"payloadgo/internal/commands"
	"payloadgo/internal/config"
	"payloadgo/internal/ui"

	"github.com/spf13/cobra"
)

func Execute() {
	// Create visual CLI instance
	visual := ui.NewVisualCLI()

	rootCmd := &cobra.Command{
		Use:   "payloadgo",
		Short: "🚀 PayloadGo Enterprise - Security Testing Platform",
		Long: `PayloadGo Enterprise is a comprehensive, enterprise-grade security testing platform.

🔒 Enterprise Features:
  • Multi-tenant architecture with RBAC
  • ML-powered confidence scoring
  • Comprehensive reporting (Executive, Technical, SARIF)
  • Real-time monitoring and metrics
  • Interactive CLI and Web UI
  • Enterprise integrations and API

🛡️ Safety & Ethics:
  • Safe-by-default design
  • Ethical guidelines enforcement
  • Emergency kill switch
  • Immutable audit logging

📊 Advanced Capabilities:
  • Adaptive concurrency control
  • Circuit breaker protection
  • False positive reduction
  • Browser instrumentation
  • Correlation engine`,
		Run: func(cmd *cobra.Command, args []string) {
			// Show enhanced banner and welcome
			visual.ShowBanner()
			visual.ShowWelcome()

			// Interactive menu loop
			for {
				// Show main menu
				visual.ShowMainMenu()

				// Get user choice
				var choice string
				fmt.Scanln(&choice)

				// Handle menu selection
				switch choice {
				case "1":
					visual.ShowInfo("Starting Quick Scan...")
					visual.ShowInfo("Please run: payloadgo scan <target> --quick")
				case "2":
					visual.ShowInfo("Starting Advanced Scan...")
					visual.ShowInfo("Please run: payloadgo scan <target> --advanced")
				case "3":
					visual.ShowInfo("Interactive mode - currently uses guided workflows in each command")
				case "4":
					visual.ShowInfo("Starting Web Dashboard...")
					visual.ShowInfo("Please run: payloadgo server --web")
				case "5":
					visual.ShowInfo("Generating Report...")
					visual.ShowInfo("Please run: payloadgo report")
				case "6":
					visual.ShowInfo("View Findings - feature coming soon")
				case "7":
					visual.ShowInfo("Metrics - feature coming soon")
				case "8":
					visual.ShowInfo("Settings - feature coming soon")
				case "9":
					visual.ShowHelp()
					visual.ShowSuccess("Press Enter to return to main menu...")
					var input string
					fmt.Scanln(&input)
				case "10":
					visual.ShowGoodbye()
					return
				default:
					visual.ShowError("Invalid choice. Please enter a number between 1-10.")
				}

				if choice != "10" {
					fmt.Println()
				}
			}
		},
	}

	// Add subcommands
	rootCmd.AddCommand(commands.NewFuzzCommand())
	rootCmd.AddCommand(commands.NewSimpleScanCommand()) // Enhanced visual scan
	rootCmd.AddCommand(commands.NewReportCommand())
	rootCmd.AddCommand(commands.NewServerCommand())     // Web server
	rootCmd.AddCommand(commands.NewFindingsCommand())   // Findings view
	rootCmd.AddCommand(commands.NewVisualHelpCommand()) // Enhanced help
	rootCmd.AddCommand(commands.NewVersionCommand())    // Version information
	rootCmd.AddCommand(commands.NewMenuCommand())

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.payloadgo.yaml)")
	rootCmd.PersistentFlags().IntP("threads", "t", 10, "number of concurrent threads")
	rootCmd.PersistentFlags().IntP("timeout", "T", 10, "request timeout in seconds")
	rootCmd.PersistentFlags().StringP("proxy", "p", "", "proxy URL (e.g., http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().StringP("user-agent", "u", "PayloadGo/1.0", "custom user agent")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Bind flags to viper
	config.BindFlags(rootCmd)

	rootCmd.Execute()
}
