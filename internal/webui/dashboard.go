package webui

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Dashboard provides the web UI dashboard
type Dashboard struct {
	// Dashboard implementation would go here
}

// NewDashboard creates a new dashboard instance
func NewDashboard() *Dashboard {
	return &Dashboard{}
}

// RegisterRoutes registers dashboard routes
func (d *Dashboard) RegisterRoutes(r *gin.Engine) {
	// Static files
	r.Static("/static", "./web/static")
	r.LoadHTMLGlob("web/templates/*")

	// Dashboard routes
	dashboard := r.Group("/dashboard")
	{
		dashboard.GET("/", d.Index)
		dashboard.GET("/scans", d.ScanList)
		dashboard.GET("/findings", d.FindingList)
		dashboard.GET("/reports", d.ReportList)
		dashboard.GET("/metrics", d.Metrics)
		dashboard.GET("/settings", d.Settings)
	}
}

// Index renders the main dashboard page
func (d *Dashboard) Index(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "Dashboard",
		"user":  map[string]string{"username": "demo"},
		"stats": map[string]interface{}{
			"total_scans":    10,
			"total_findings": 25,
			"findings_by_severity": map[string]int{
				"critical": 2,
				"high":     5,
				"medium":   10,
				"low":      8,
			},
		},
		"recent_scans":    []map[string]interface{}{},
		"recent_findings": []map[string]interface{}{},
	})
}

// ScanList renders the scan list page
func (d *Dashboard) ScanList(c *gin.Context) {
	c.HTML(http.StatusOK, "scans.html", gin.H{
		"title": "Scans",
		"user":  map[string]string{"username": "demo"},
		"scans": []map[string]interface{}{},
		"total": 0,
		"page":  1,
		"limit": 20,
	})
}

// FindingList renders the finding list page
func (d *Dashboard) FindingList(c *gin.Context) {
	c.HTML(http.StatusOK, "findings.html", gin.H{
		"title":    "Findings",
		"user":     map[string]string{"username": "demo"},
		"findings": []map[string]interface{}{},
		"total":    0,
		"page":     1,
		"limit":    20,
	})
}

// ReportList renders the report list page
func (d *Dashboard) ReportList(c *gin.Context) {
	c.HTML(http.StatusOK, "reports.html", gin.H{
		"title":   "Reports",
		"user":    map[string]string{"username": "demo"},
		"reports": []map[string]interface{}{},
		"total":   0,
		"page":    1,
		"limit":   20,
	})
}

// Metrics renders the metrics page
func (d *Dashboard) Metrics(c *gin.Context) {
	c.HTML(http.StatusOK, "metrics.html", gin.H{
		"title": "Metrics",
		"user":  map[string]string{"username": "demo"},
	})
}

// Settings renders the settings page
func (d *Dashboard) Settings(c *gin.Context) {
	c.HTML(http.StatusOK, "settings.html", gin.H{
		"title": "Settings",
		"user":  map[string]string{"username": "demo"},
	})
}
