package observability

import (
	"context"
	"database/sql"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics provides Prometheus metrics for the application
type Metrics struct {
	// HTTP metrics
	HTTPRequestsTotal    *prometheus.CounterVec
	HTTPRequestDuration  *prometheus.HistogramVec
	HTTPRequestsInFlight *prometheus.GaugeVec

	// Scan metrics
	ScansTotal      *prometheus.CounterVec
	ScansInProgress *prometheus.GaugeVec
	ScanDuration    *prometheus.HistogramVec
	ScanFindings    *prometheus.CounterVec

	// Finding metrics
	FindingsTotal      *prometheus.CounterVec
	FindingsBySeverity *prometheus.CounterVec
	FindingsByType     *prometheus.CounterVec

	// Authentication metrics
	AuthAttempts   *prometheus.CounterVec
	AuthFailures   *prometheus.CounterVec
	ActiveSessions prometheus.Gauge

	// System metrics
	SystemUptime        prometheus.Gauge
	MemoryUsage         prometheus.Gauge
	CPUUsage            prometheus.Gauge
	DatabaseConnections prometheus.Gauge

	// Business metrics
	OrganizationsTotal prometheus.Gauge
	UsersTotal         prometheus.Gauge
	ReportsGenerated   *prometheus.CounterVec
	APIKeysCreated     prometheus.Counter
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		// HTTP metrics
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code", "organization_id"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint", "organization_id"},
		),
		HTTPRequestsInFlight: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "http_requests_in_flight",
				Help: "Number of HTTP requests currently being processed",
			},
			[]string{"method", "endpoint"},
		),

		// Scan metrics
		ScansTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "scans_total",
				Help: "Total number of scans",
			},
			[]string{"status", "organization_id"},
		),
		ScansInProgress: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "scans_in_progress",
				Help: "Number of scans currently in progress",
			},
			[]string{"organization_id"},
		),
		ScanDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "scan_duration_seconds",
				Help:    "Scan duration in seconds",
				Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
			},
			[]string{"organization_id", "scan_type"},
		),
		ScanFindings: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "scan_findings_total",
				Help: "Total number of findings discovered",
			},
			[]string{"scan_id", "organization_id", "severity", "type"},
		),

		// Finding metrics
		FindingsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "findings_total",
				Help: "Total number of findings",
			},
			[]string{"organization_id", "severity", "type", "status"},
		),
		FindingsBySeverity: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "findings_by_severity_total",
				Help: "Total number of findings by severity",
			},
			[]string{"severity", "organization_id"},
		),
		FindingsByType: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "findings_by_type_total",
				Help: "Total number of findings by type",
			},
			[]string{"type", "organization_id"},
		),

		// Authentication metrics
		AuthAttempts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_attempts_total",
				Help: "Total number of authentication attempts",
			},
			[]string{"method", "organization_id", "result"},
		),
		AuthFailures: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_failures_total",
				Help: "Total number of authentication failures",
			},
			[]string{"reason", "organization_id"},
		),
		ActiveSessions: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "active_sessions",
				Help: "Number of active user sessions",
			},
		),

		// System metrics
		SystemUptime: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "system_uptime_seconds",
				Help: "System uptime in seconds",
			},
		),
		MemoryUsage: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
		),
		CPUUsage: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "cpu_usage_percent",
				Help: "CPU usage percentage",
			},
		),
		DatabaseConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "database_connections",
				Help: "Number of active database connections",
			},
		),

		// Business metrics
		OrganizationsTotal: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "organizations_total",
				Help: "Total number of organizations",
			},
		),
		UsersTotal: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "users_total",
				Help: "Total number of users",
			},
		),
		ReportsGenerated: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "reports_generated_total",
				Help: "Total number of reports generated",
			},
			[]string{"type", "format", "organization_id"},
		),
		APIKeysCreated: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "api_keys_created_total",
				Help: "Total number of API keys created",
			},
		),
	}
}

// RecordHTTPRequest records an HTTP request
func (m *Metrics) RecordHTTPRequest(method, endpoint, statusCode, organizationID string, duration time.Duration) {
	m.HTTPRequestsTotal.WithLabelValues(method, endpoint, statusCode, organizationID).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, endpoint, organizationID).Observe(duration.Seconds())
}

// RecordHTTPRequestInFlight records an HTTP request in flight
func (m *Metrics) RecordHTTPRequestInFlight(method, endpoint string, inFlight float64) {
	m.HTTPRequestsInFlight.WithLabelValues(method, endpoint).Set(inFlight)
}

// RecordScan records a scan event
func (m *Metrics) RecordScan(status, organizationID string) {
	m.ScansTotal.WithLabelValues(status, organizationID).Inc()
}

// RecordScanInProgress records scans in progress
func (m *Metrics) RecordScanInProgress(organizationID string, count float64) {
	m.ScansInProgress.WithLabelValues(organizationID).Set(count)
}

// RecordScanDuration records scan duration
func (m *Metrics) RecordScanDuration(organizationID, scanType string, duration time.Duration) {
	m.ScanDuration.WithLabelValues(organizationID, scanType).Observe(duration.Seconds())
}

// RecordScanFinding records a scan finding
func (m *Metrics) RecordScanFinding(scanID, organizationID, severity, findingType string) {
	m.ScanFindings.WithLabelValues(scanID, organizationID, severity, findingType).Inc()
}

// RecordFinding records a finding
func (m *Metrics) RecordFinding(organizationID, severity, findingType, status string) {
	m.FindingsTotal.WithLabelValues(organizationID, severity, findingType, status).Inc()
	m.FindingsBySeverity.WithLabelValues(severity, organizationID).Inc()
	m.FindingsByType.WithLabelValues(findingType, organizationID).Inc()
}

// RecordAuthAttempt records an authentication attempt
func (m *Metrics) RecordAuthAttempt(method, organizationID, result string) {
	m.AuthAttempts.WithLabelValues(method, organizationID, result).Inc()
}

// RecordAuthFailure records an authentication failure
func (m *Metrics) RecordAuthFailure(reason, organizationID string) {
	m.AuthFailures.WithLabelValues(reason, organizationID).Inc()
}

// RecordActiveSessions records the number of active sessions
func (m *Metrics) RecordActiveSessions(count float64) {
	m.ActiveSessions.Set(count)
}

// RecordSystemUptime records system uptime
func (m *Metrics) RecordSystemUptime(uptime time.Duration) {
	m.SystemUptime.Set(uptime.Seconds())
}

// RecordMemoryUsage records memory usage
func (m *Metrics) RecordMemoryUsage(bytes uint64) {
	m.MemoryUsage.Set(float64(bytes))
}

// RecordCPUUsage records CPU usage
func (m *Metrics) RecordCPUUsage(percent float64) {
	m.CPUUsage.Set(percent)
}

// RecordDatabaseConnections records database connections
func (m *Metrics) RecordDatabaseConnections(count float64) {
	m.DatabaseConnections.Set(count)
}

// RecordOrganizationsTotal records total organizations
func (m *Metrics) RecordOrganizationsTotal(count float64) {
	m.OrganizationsTotal.Set(count)
}

// RecordUsersTotal records total users
func (m *Metrics) RecordUsersTotal(count float64) {
	m.UsersTotal.Set(count)
}

// RecordReportGenerated records a generated report
func (m *Metrics) RecordReportGenerated(reportType, format, organizationID string) {
	m.ReportsGenerated.WithLabelValues(reportType, format, organizationID).Inc()
}

// RecordAPIKeyCreated records an API key creation
func (m *Metrics) RecordAPIKeyCreated() {
	m.APIKeysCreated.Inc()
}

// MetricsCollector provides a metrics collector interface
type MetricsCollector interface {
	Collect(ctx context.Context) error
}

// SystemMetricsCollector collects system metrics
type SystemMetricsCollector struct {
	metrics *Metrics
}

// NewSystemMetricsCollector creates a new system metrics collector
func NewSystemMetricsCollector(metrics *Metrics) *SystemMetricsCollector {
	return &SystemMetricsCollector{
		metrics: metrics,
	}
}

// Collect collects system metrics
func (smc *SystemMetricsCollector) Collect(ctx context.Context) error {
	// Collect uptime
	uptime := time.Since(startTime)
	smc.metrics.RecordSystemUptime(uptime)

	// Collect memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	smc.metrics.RecordMemoryUsage(m.Alloc)

	// Collect CPU usage (simplified)
	// In a real implementation, you'd use a proper CPU monitoring library
	smc.metrics.RecordCPUUsage(0.0) // Placeholder

	return nil
}

// DatabaseMetricsCollector collects database metrics
type DatabaseMetricsCollector struct {
	metrics *Metrics
	db      *sql.DB
}

// NewDatabaseMetricsCollector creates a new database metrics collector
func NewDatabaseMetricsCollector(metrics *Metrics, db *sql.DB) *DatabaseMetricsCollector {
	return &DatabaseMetricsCollector{
		metrics: metrics,
		db:      db,
	}
}

// Collect collects database metrics
func (dmc *DatabaseMetricsCollector) Collect(ctx context.Context) error {
	// Get database connection stats
	stats := dmc.db.Stats()
	dmc.metrics.RecordDatabaseConnections(float64(stats.OpenConnections))

	return nil
}

// BusinessMetricsCollector collects business metrics
type BusinessMetricsCollector struct {
	metrics  *Metrics
	userRepo UserRepository
	orgRepo  OrganizationRepository
}

// NewBusinessMetricsCollector creates a new business metrics collector
func NewBusinessMetricsCollector(metrics *Metrics, userRepo UserRepository, orgRepo OrganizationRepository) *BusinessMetricsCollector {
	return &BusinessMetricsCollector{
		metrics:  metrics,
		userRepo: userRepo,
		orgRepo:  orgRepo,
	}
}

// Collect collects business metrics
func (bmc *BusinessMetricsCollector) Collect(ctx context.Context) error {
	// Get user count
	userCount, err := bmc.userRepo.Count()
	if err == nil {
		bmc.metrics.RecordUsersTotal(float64(userCount))
	}

	// Get organization count
	orgCount, err := bmc.orgRepo.Count()
	if err == nil {
		bmc.metrics.RecordOrganizationsTotal(float64(orgCount))
	}

	return nil
}

// Repository interfaces for metrics collection
type UserRepository interface {
	Count() (int, error)
}

type OrganizationRepository interface {
	Count() (int, error)
}

var startTime = time.Now()
