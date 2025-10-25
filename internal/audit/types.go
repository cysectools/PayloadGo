package audit

import (
	"time"
)

// AuditEvent represents an audit event
type AuditEvent struct {
	ID             string                 `json:"id" db:"id"`
	Timestamp      time.Time              `json:"timestamp" db:"timestamp"`
	UserID         string                 `json:"user_id" db:"user_id"`
	OrganizationID string                 `json:"organization_id" db:"organization_id"`
	Action         string                 `json:"action" db:"action"`
	Resource       string                 `json:"resource" db:"resource"`
	ResourceID     string                 `json:"resource_id" db:"resource_id"`
	IPAddress      string                 `json:"ip_address" db:"ip_address"`
	UserAgent      string                 `json:"user_agent" db:"user_agent"`
	Details        map[string]interface{} `json:"details" db:"details"`
	Request        *RequestSnapshot       `json:"request,omitempty" db:"request"`
	Response       *ResponseSnapshot      `json:"response,omitempty" db:"response"`
	Hash           string                 `json:"hash" db:"hash"`
	Signature      string                 `json:"signature" db:"signature"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
}

// RequestSnapshot captures request details
type RequestSnapshot struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
}

// ResponseSnapshot captures response details
type ResponseSnapshot struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	Duration   time.Duration     `json:"duration"`
}

// Evidence represents tamper-evident evidence
type Evidence struct {
	ID          string    `json:"id" db:"id"`
	EventID     string    `json:"event_id" db:"event_id"`
	Type        string    `json:"type" db:"type"` // scan_result, finding, report, etc.
	Content     []byte    `json:"content" db:"content"`
	ContentHash string    `json:"content_hash" db:"content_hash"`
	Signature   string    `json:"signature" db:"signature"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// AuditRepository defines the interface for audit data operations
type AuditRepository interface {
	CreateEvent(event *AuditEvent) error
	GetEvent(id string) (*AuditEvent, error)
	GetEventsByUser(userID string, limit, offset int) ([]*AuditEvent, error)
	GetEventsByOrganization(orgID string, limit, offset int) ([]*AuditEvent, error)
	GetEventsByAction(action string, limit, offset int) ([]*AuditEvent, error)
	GetEventsByResource(resource, resourceID string, limit, offset int) ([]*AuditEvent, error)
	GetEventsByTimeRange(start, end time.Time, limit, offset int) ([]*AuditEvent, error)
	SearchEvents(query string, limit, offset int) ([]*AuditEvent, error)
}

// EvidenceRepository defines the interface for evidence data operations
type EvidenceRepository interface {
	CreateEvidence(evidence *Evidence) error
	GetEvidence(id string) (*Evidence, error)
	GetEvidenceByEvent(eventID string) ([]*Evidence, error)
	VerifyEvidence(id string) (bool, error)
	DeleteEvidence(id string) error
}

// Predefined audit actions
const (
	// Authentication actions
	ActionLogin          = "auth.login"
	ActionLogout         = "auth.logout"
	ActionLoginFailed    = "auth.login_failed"
	ActionPasswordChange = "auth.password_change"
	ActionPasswordReset  = "auth.password_reset"
	ActionTokenRefresh   = "auth.token_refresh"

	// User management actions
	ActionUserCreate     = "user.create"
	ActionUserUpdate     = "user.update"
	ActionUserDelete     = "user.delete"
	ActionUserActivate   = "user.activate"
	ActionUserDeactivate = "user.deactivate"

	// Organization actions
	ActionOrgCreate = "organization.create"
	ActionOrgUpdate = "organization.update"
	ActionOrgDelete = "organization.delete"
	ActionOrgJoin   = "organization.join"
	ActionOrgLeave  = "organization.leave"

	// Scan actions
	ActionScanCreate   = "scan.create"
	ActionScanStart    = "scan.start"
	ActionScanPause    = "scan.pause"
	ActionScanResume   = "scan.resume"
	ActionScanStop     = "scan.stop"
	ActionScanComplete = "scan.complete"
	ActionScanDelete   = "scan.delete"

	// Finding actions
	ActionFindingCreate        = "finding.create"
	ActionFindingUpdate        = "finding.update"
	ActionFindingConfirm       = "finding.confirm"
	ActionFindingFalsePositive = "finding.false_positive"
	ActionFindingDelete        = "finding.delete"

	// Report actions
	ActionReportCreate   = "report.create"
	ActionReportGenerate = "report.generate"
	ActionReportExport   = "report.export"
	ActionReportDelete   = "report.delete"

	// System actions
	ActionSystemConfig      = "system.config"
	ActionSystemBackup      = "system.backup"
	ActionSystemRestore     = "system.restore"
	ActionSystemMaintenance = "system.maintenance"

	// Security actions
	ActionSecurityAlert    = "security.alert"
	ActionSecurityIncident = "security.incident"
	ActionSecurityBreach   = "security.breach"
	ActionSecurityLockout  = "security.lockout"
)

// Predefined audit resources
const (
	ResourceUser         = "user"
	ResourceOrganization = "organization"
	ResourceScan         = "scan"
	ResourceFinding      = "finding"
	ResourceReport       = "report"
	ResourceSystem       = "system"
	ResourceSecurity     = "security"
	ResourceAPI          = "api"
	ResourceDatabase     = "database"
	ResourceFile         = "file"
)

// Audit levels
const (
	LevelInfo     = "info"
	LevelWarning  = "warning"
	LevelError    = "error"
	LevelCritical = "critical"
)

// Audit categories
const (
	CategoryAuthentication   = "authentication"
	CategoryAuthorization    = "authorization"
	CategoryDataAccess       = "data_access"
	CategoryDataModification = "data_modification"
	CategorySystem           = "system"
	CategorySecurity         = "security"
	CategoryCompliance       = "compliance"
)
