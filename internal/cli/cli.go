package cli

import (
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

			// Show main menu
			visual.ShowMainMenu()

			// For now, fall back to the original menu
			// In a full implementation, this would handle the menu selection
			commands.RunMenu()
		},
	}

	// Add subcommands
	rootCmd.AddCommand(commands.NewFuzzCommand())
	rootCmd.AddCommand(commands.NewSimpleScanCommand()) // Enhanced visual scan
	rootCmd.AddCommand(commands.NewReportCommand())
	rootCmd.AddCommand(commands.NewServerCommand())     // Web server
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
