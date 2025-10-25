package storage

import (
	"time"
)

// Scan represents a vulnerability scan
type Scan struct {
	ID             string                 `json:"id" db:"id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	UserID         string                 `json:"user_id" db:"user_id"`
	Name           string                 `json:"name" db:"name"`
	Description    string                 `json:"description" db:"description"`
	Target         string                 `json:"target" db:"target"`
	Status         string                 `json:"status" db:"status"`
	Config         map[string]interface{} `json:"config" db:"config"`
	Progress       int                    `json:"progress" db:"progress"`
	StartedAt      *time.Time             `json:"started_at" db:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at" db:"completed_at"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}

// Finding represents a detected vulnerability
type Finding struct {
	ID             string                 `json:"id" db:"id"`
	ScanID         string                 `json:"scan_id" db:"scan_id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	Type           string                 `json:"type" db:"type"`
	Severity       string                 `json:"severity" db:"severity"`
	Confidence     float64                `json:"confidence" db:"confidence"`
	Title          string                 `json:"title" db:"title"`
	Description    string                 `json:"description" db:"description"`
	Payload        string                 `json:"payload" db:"payload"`
	URL            string                 `json:"url" db:"url"`
	Method         string                 `json:"method" db:"method"`
	StatusCode     int                    `json:"status_code" db:"status_code"`
	Response       string                 `json:"response" db:"response"`
	Evidence       map[string]interface{} `json:"evidence" db:"evidence"`
	Status         string                 `json:"status" db:"status"` // new, confirmed, false_positive, fixed
	AssignedTo     string                 `json:"assigned_to" db:"assigned_to"`
	Tags           []string               `json:"tags" db:"tags"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}

// Report represents a generated report
type Report struct {
	ID             string                 `json:"id" db:"id"`
	ScanID         string                 `json:"scan_id" db:"scan_id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	UserID         string                 `json:"user_id" db:"user_id"`
	Name           string                 `json:"name" db:"name"`
	Type           string                 `json:"type" db:"type"`     // executive, technical, compliance
	Format         string                 `json:"format" db:"format"` // html, pdf, json, csv
	Status         string                 `json:"status" db:"status"` // generating, completed, failed
	Config         map[string]interface{} `json:"config" db:"config"`
	FilePath       string                 `json:"file_path" db:"file_path"`
	FileSize       int64                  `json:"file_size" db:"file_size"`
	FileHash       string                 `json:"file_hash" db:"file_hash"`
	GeneratedAt    *time.Time             `json:"generated_at" db:"generated_at"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
}

// Job represents a background job
type Job struct {
	ID          string                 `json:"id" db:"id"`
	Type        string                 `json:"type" db:"type"`     // scan, report, cleanup, etc.
	Status      string                 `json:"status" db:"status"` // pending, running, completed, failed
	Priority    int                    `json:"priority" db:"priority"`
	Data        map[string]interface{} `json:"data" db:"data"`
	Result      map[string]interface{} `json:"result" db:"result"`
	Error       string                 `json:"error" db:"error"`
	Attempts    int                    `json:"attempts" db:"attempts"`
	MaxAttempts int                    `json:"max_attempts" db:"max_attempts"`
	ScheduledAt time.Time              `json:"scheduled_at" db:"scheduled_at"`
	StartedAt   *time.Time             `json:"started_at" db:"started_at"`
	CompletedAt *time.Time             `json:"completed_at" db:"completed_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
}

// Scan statuses
const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusPaused    = "paused"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"
	ScanStatusCancelled = "cancelled"
)

// Finding statuses
const (
	FindingStatusNew           = "new"
	FindingStatusConfirmed     = "confirmed"
	FindingStatusFalsePositive = "false_positive"
	FindingStatusFixed         = "fixed"
	FindingStatusAccepted      = "accepted"
	FindingStatusRejected      = "rejected"
)

// Finding severities
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding types
const (
	FindingTypeXSS                  = "xss"
	FindingTypeSQLi                 = "sqli"
	FindingTypeXXE                  = "xxe"
	FindingTypeCommandInjection     = "command_injection"
	FindingTypePathTraversal        = "path_traversal"
	FindingTypeLDAP                 = "ldap"
	FindingTypeNoSQL                = "nosql"
	FindingTypeSSRF                 = "ssrf"
	FindingTypeCSRF                 = "csrf"
	FindingTypeIDOR                 = "idor"
	FindingTypeLFI                  = "lfi"
	FindingTypeRFI                  = "rfi"
	FindingTypeSSTI                 = "ssti"
	FindingTypeDeserialization      = "deserialization"
	FindingTypeInsecureDirect       = "insecure_direct_object_reference"
	FindingTypeBrokenAuth           = "broken_authentication"
	FindingTypeSensitiveData        = "sensitive_data_exposure"
	FindingTypeXMLExternal          = "xml_external_entity"
	FindingTypeBrokenAccess         = "broken_access_control"
	FindingTypeSecurityMisconfig    = "security_misconfiguration"
	FindingTypeVulnerableComponents = "vulnerable_components"
	FindingTypeInsufficientLogging  = "insufficient_logging"
	FindingTypeOther                = "other"
)

// Report types
const (
	ReportTypeExecutive  = "executive"
	ReportTypeTechnical  = "technical"
	ReportTypeCompliance = "compliance"
	ReportTypeCustom     = "custom"
)

// Report formats
const (
	ReportFormatHTML  = "html"
	ReportFormatPDF   = "pdf"
	ReportFormatJSON  = "json"
	ReportFormatCSV   = "csv"
	ReportFormatXML   = "xml"
	ReportFormatSARIF = "sarif"
)

// Job types
const (
	JobTypeScan    = "scan"
	JobTypeReport  = "report"
	JobTypeCleanup = "cleanup"
	JobTypeBackup  = "backup"
	JobTypeRestore = "restore"
	JobTypeExport  = "export"
	JobTypeImport  = "import"
)

// Job statuses
const (
	JobStatusPending   = "pending"
	JobStatusRunning   = "running"
	JobStatusCompleted = "completed"
	JobStatusFailed    = "failed"
	JobStatusCancelled = "cancelled"
)
