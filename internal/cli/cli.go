package cli

import (
	"payloadgo/internal/commands"
	"payloadgo/internal/config"

	"github.com/spf13/cobra"
)

func Execute() {
	rootCmd := &cobra.Command{
		Use:   "payloadgo",
		Short: "Professional payload testing tool for bug bounty hunters",
		Long: `PayloadGo is a professional-grade payload testing tool designed for bug bounty hunters.
It provides concurrent testing, intelligent response analysis, and comprehensive reporting.`,
		Run: func(cmd *cobra.Command, args []string) {
			// If no subcommand is provided, show the interactive menu
			commands.RunMenu()
		},
	}

	// Add subcommands
	rootCmd.AddCommand(commands.NewFuzzCommand())
	rootCmd.AddCommand(commands.NewScanCommand())
	rootCmd.AddCommand(commands.NewReportCommand())
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
