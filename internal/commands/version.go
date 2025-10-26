package commands

import (
	"fmt"
	"runtime"
	"time"

	"payloadgo/internal/ui"

	"github.com/spf13/cobra"
)

var (
	Version   = "1.0.0"
	BuildDate = time.Now().Format("2006-01-02")
	GitCommit = "dev"
	GoVersion = runtime.Version()
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "📋 Show version information",
	Long:  `Display detailed version and build information for PayloadGo Enterprise.`,
	Run:   runVersion,
}

func NewVersionCommand() *cobra.Command {
	return versionCmd
}

func runVersion(cmd *cobra.Command, args []string) {
	visual := ui.NewVisualCLI()

	// Show version banner
	visual.ShowBanner()

	// Version information
	visual.ShowInfo("Version Information")

	versionInfo := [][]string{
		{"Version", Version},
		{"Build Date", BuildDate},
		{"Git Commit", GitCommit},
		{"Go Version", GoVersion},
		{"Platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
		{"Compiler", runtime.Compiler},
	}

	visual.ShowTable([]string{"Component", "Value"}, versionInfo)

	// Feature highlights
	visual.ShowInfo("Enterprise Features")
	features := []string{
		"🔒 Multi-tenant architecture with RBAC",
		"🤖 ML-powered confidence scoring",
		"📊 Comprehensive reporting (Executive, Technical, SARIF)",
		"📈 Real-time monitoring and metrics",
		"🌐 Interactive CLI and Web UI",
		"🔧 Enterprise integrations and API",
		"🛡️ Safe-by-default design",
		"⚡ Adaptive concurrency control",
		"🔍 Browser instrumentation",
		"📋 Immutable audit logging",
	}

	for _, feature := range features {
		visual.ShowInfo(feature)
	}

	// License and support information
	visual.ShowInfo("License & Support")
	visual.ShowInfo("📄 Licensed under MIT License")
	visual.ShowInfo("📚 Documentation: https://docs.payloadgo.com")
	visual.ShowInfo("💬 Community: https://github.com/payloadgo/payloadgo/discussions")
	visual.ShowInfo("🏢 Enterprise Support: support@payloadgo.com")
	visual.ShowInfo("🔒 Security Issues: security@payloadgo.com")
}
