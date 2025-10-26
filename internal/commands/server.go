package commands

import (
	"fmt"
	"net/http"
	"time"

	"payloadgo/internal/ui"
	"payloadgo/internal/webui"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "🌐 Start the web server",
	Long: `Start the PayloadGo Enterprise web server with dashboard and API.

The web server provides:
  • Interactive dashboard
  • Real-time scan monitoring
  • Finding management
  • Report generation
  • Metrics and analytics
  • REST API endpoints`,
	Run: runServer,
}

func NewServerCommand() *cobra.Command {
	serverCmd.Flags().StringP("host", "H", "0.0.0.0", "host to bind to")
	serverCmd.Flags().IntP("port", "p", 8080, "port to bind to")
	serverCmd.Flags().BoolP("web", "w", true, "enable web UI")
	serverCmd.Flags().BoolP("api", "a", true, "enable REST API")
	serverCmd.Flags().BoolP("tls", "t", false, "enable TLS")
	serverCmd.Flags().StringP("cert", "c", "", "TLS certificate file")
	serverCmd.Flags().StringP("key", "k", "", "TLS private key file")
	serverCmd.Flags().BoolP("verbose", "v", false, "verbose output")

	return serverCmd
}

func runServer(cmd *cobra.Command, args []string) {
	visual := ui.NewVisualCLI()

	// Show server banner
	visual.ShowBanner()

	// Get configuration
	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetInt("port")
	web, _ := cmd.Flags().GetBool("web")
	api, _ := cmd.Flags().GetBool("api")
	tls, _ := cmd.Flags().GetBool("tls")
	cert, _ := cmd.Flags().GetString("cert")
	key, _ := cmd.Flags().GetString("key")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Show server configuration
	visual.ShowInfo("Server Configuration")

	configTable := [][]string{
		{"Host", host},
		{"Port", fmt.Sprintf("%d", port)},
		{"Web UI", fmt.Sprintf("%t", web)},
		{"REST API", fmt.Sprintf("%t", api)},
		{"TLS", fmt.Sprintf("%t", tls)},
		{"Verbose", fmt.Sprintf("%t", verbose)},
	}

	visual.ShowTable([]string{"Setting", "Value"}, configTable)

	// Set Gin mode
	if verbose {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.Default()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Add routes
	if web {
		// Web UI routes
		dashboard := webui.NewDashboard()
		dashboard.RegisterRoutes(router)

		// Health check
		router.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status":    "healthy",
				"timestamp": time.Now(),
				"version":   "1.0.0",
			})
		})

		// Metrics endpoint
		router.GET("/metrics", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"scans_total":    100,
				"findings_total": 250,
				"uptime_seconds": time.Since(time.Now()).Seconds(),
			})
		})
	}

	if api {
		// API routes
		api := router.Group("/api/v1")
		{
			api.GET("/status", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"status": "running",
					"time":   time.Now(),
				})
			})

			api.GET("/scans", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"scans": []gin.H{},
				})
			})

			api.GET("/findings", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"findings": []gin.H{},
				})
			})
		}
	}

	// Show startup information
	visual.ShowSuccess("PayloadGo Enterprise Server Starting...")

	protocol := "http"
	if tls {
		protocol = "https"
	}

	visual.ShowInfo(fmt.Sprintf("Server will be available at: %s://%s:%d", protocol, host, port))

	if web {
		visual.ShowInfo(fmt.Sprintf("Web Dashboard: %s://%s:%d/dashboard", protocol, host, port))
	}

	if api {
		visual.ShowInfo(fmt.Sprintf("REST API: %s://%s:%d/api/v1", protocol, host, port))
	}

	visual.ShowInfo("Press Ctrl+C to stop the server")

	// Start server
	addr := fmt.Sprintf("%s:%d", host, port)

	if tls {
		if cert == "" || key == "" {
			visual.ShowError("TLS enabled but certificate or key file not provided")
			return
		}

		visual.ShowSuccess("Starting HTTPS server...")
		if err := router.RunTLS(addr, cert, key); err != nil {
			visual.ShowError(fmt.Sprintf("Failed to start HTTPS server: %v", err))
		}
	} else {
		visual.ShowSuccess("Starting HTTP server...")
		if err := router.Run(addr); err != nil {
			visual.ShowError(fmt.Sprintf("Failed to start HTTP server: %v", err))
		}
	}
}
