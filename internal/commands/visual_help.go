package commands

import (
	"payloadgo/internal/ui"

	"github.com/spf13/cobra"
)

var visualHelpCmd = &cobra.Command{
	Use:   "help",
	Short: "❓ Show help and documentation",
	Long:  `Display comprehensive help and documentation for PayloadGo Enterprise.`,
	Run:   runVisualHelp,
}

func NewVisualHelpCommand() *cobra.Command {
	return visualHelpCmd
}

func runVisualHelp(cmd *cobra.Command, args []string) {
	visual := ui.NewVisualCLI()
	visual.ShowHelp()
}
