package auth

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           string     `json:"id" db:"id"`
	Email        string     `json:"email" db:"email"`
	Username     string     `json:"username" db:"username"`
	PasswordHash string     `json:"-" db:"password_hash"`
	FirstName    string     `json:"first_name" db:"first_name"`
	LastName     string     `json:"last_name" db:"last_name"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	IsVerified   bool       `json:"is_verified" db:"is_verified"`
	LastLogin    *time.Time `json:"last_login" db:"last_login"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

// Organization represents a multi-tenant organization
type Organization struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Slug        string    `json:"slug" db:"slug"`
	Description string    `json:"description" db:"description"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Role represents a role in the system
type Role struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Permissions []string  `json:"permissions" db:"permissions"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// UserRole represents the relationship between users and roles within an organization
type UserRole struct {
	ID             string    `json:"id" db:"id"`
	UserID         string    `json:"user_id" db:"user_id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	RoleID         string    `json:"role_id" db:"role_id"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// Permission represents a specific permission in the system
type Permission struct {
	ID          string `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`
	Resource    string `json:"resource" db:"resource"`
	Action      string `json:"action" db:"action"`
	Description string `json:"description" db:"description"`
}

// APIKey represents an API key for service-to-service authentication
type APIKey struct {
	ID             string     `json:"id" db:"id"`
	Name           string     `json:"name" db:"name"`
	KeyHash        string     `json:"-" db:"key_hash"`
	UserID         string     `json:"user_id" db:"user_id"`
	OrganizationID string     `json:"organization_id" db:"organization_id"`
	Permissions    []string   `json:"permissions" db:"permissions"`
	LastUsed       *time.Time `json:"last_used" db:"last_used"`
	ExpiresAt      *time.Time `json:"expires_at" db:"expires_at"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// Session represents an active user session
type Session struct {
	ID             string    `json:"id" db:"id"`
	UserID         string    `json:"user_id" db:"user_id"`
	OrganizationID string    `json:"organization_id" db:"organization_id"`
	Token          string    `json:"-" db:"token"`
	RefreshToken   string    `json:"-" db:"refresh_token"`
	UserAgent      string    `json:"user_agent" db:"user_agent"`
	IPAddress      string    `json:"ip_address" db:"ip_address"`
	ExpiresAt      time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// AuthContext represents the current authentication context
type AuthContext struct {
	User         *User         `json:"user"`
	Organization *Organization `json:"organization"`
	Roles        []Role        `json:"roles"`
	Permissions  []string      `json:"permissions"`
	Session      *Session      `json:"session"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Password     string `json:"password" validate:"required,min=8"`
	Organization string `json:"organization,omitempty"`
	RememberMe   bool   `json:"remember_me"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	User         *User         `json:"user"`
	Organization *Organization `json:"organization"`
	Token        string        `json:"token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresAt    time.Time     `json:"expires_at"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email        string `json:"email" validate:"required,email"`
	Username     string `json:"username" validate:"required,min=3,max=50"`
	Password     string `json:"password" validate:"required,min=8"`
	FirstName    string `json:"first_name" validate:"required"`
	LastName     string `json:"last_name" validate:"required"`
	Organization string `json:"organization,omitempty"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// ResetPasswordRequest represents a password reset request
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ConfirmPasswordResetRequest represents a password reset confirmation
type ConfirmPasswordResetRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// Predefined roles
const (
	RoleAdmin    = "admin"
	RoleScanner  = "scanner"
	RoleReviewer = "reviewer"
	RoleAuditor  = "auditor"
)

// Predefined permissions
const (
	// Scan permissions
	PermissionScanCreate  = "scan:create"
	PermissionScanRead    = "scan:read"
	PermissionScanUpdate  = "scan:update"
	PermissionScanDelete  = "scan:delete"
	PermissionScanExecute = "scan:execute"
	PermissionScanPause   = "scan:pause"
	PermissionScanResume  = "scan:resume"
	PermissionScanStop    = "scan:stop"

	// Finding permissions
	PermissionFindingRead          = "finding:read"
	PermissionFindingUpdate        = "finding:update"
	PermissionFindingDelete        = "finding:delete"
	PermissionFindingConfirm       = "finding:confirm"
	PermissionFindingFalsePositive = "finding:false_positive"

	// Report permissions
	PermissionReportCreate = "report:create"
	PermissionReportRead   = "report:read"
	PermissionReportDelete = "report:delete"
	PermissionReportExport = "report:export"

	// User permissions
	PermissionUserCreate = "user:create"
	PermissionUserRead   = "user:read"
	PermissionUserUpdate = "user:update"
	PermissionUserDelete = "user:delete"

	// Organization permissions
	PermissionOrgCreate = "organization:create"
	PermissionOrgRead   = "organization:read"
	PermissionOrgUpdate = "organization:update"
	PermissionOrgDelete = "organization:delete"

	// System permissions
	PermissionSystemAdmin  = "system:admin"
	PermissionSystemConfig = "system:config"
	PermissionSystemAudit  = "system:audit"
)

// Default role permissions mapping
var DefaultRolePermissions = map[string][]string{
	RoleAdmin: {
		PermissionScanCreate, PermissionScanRead, PermissionScanUpdate, PermissionScanDelete, PermissionScanExecute,
		PermissionScanPause, PermissionScanResume, PermissionScanStop,
		PermissionFindingRead, PermissionFindingUpdate, PermissionFindingDelete, PermissionFindingConfirm, PermissionFindingFalsePositive,
		PermissionReportCreate, PermissionReportRead, PermissionReportDelete, PermissionReportExport,
		PermissionUserCreate, PermissionUserRead, PermissionUserUpdate, PermissionUserDelete,
		PermissionOrgCreate, PermissionOrgRead, PermissionOrgUpdate, PermissionOrgDelete,
		PermissionSystemAdmin, PermissionSystemConfig, PermissionSystemAudit,
	},
	RoleScanner: {
		PermissionScanCreate, PermissionScanRead, PermissionScanExecute, PermissionScanPause, PermissionScanResume, PermissionScanStop,
		PermissionFindingRead, PermissionFindingUpdate, PermissionFindingConfirm, PermissionFindingFalsePositive,
		PermissionReportCreate, PermissionReportRead, PermissionReportExport,
	},
	RoleReviewer: {
		PermissionScanRead,
		PermissionFindingRead, PermissionFindingUpdate, PermissionFindingConfirm, PermissionFindingFalsePositive,
		PermissionReportCreate, PermissionReportRead, PermissionReportExport,
	},
	RoleAuditor: {
		PermissionScanRead,
		PermissionFindingRead,
		PermissionReportRead,
		PermissionSystemAudit,
	},
}

// Audit action constants
const (
	ActionUserCreate     = "user:create"
	ActionUserUpdate     = "user:update"
	ActionUserDelete     = "user:delete"
	ActionLogin          = "user:login"
	ActionLogout         = "user:logout"
	ActionLoginFailed    = "login:failed"
	ActionScanCreate     = "scan:create"
	ActionScanUpdate     = "scan:update"
	ActionScanDelete     = "scan:delete"
	ActionScanStart      = "scan:start"
	ActionScanStop       = "scan:stop"
	ActionFindingCreate  = "finding:create"
	ActionFindingUpdate  = "finding:update"
	ActionFindingDelete  = "finding:delete"
	ActionReportGenerate = "report:generate"
	ActionAPIKeyCreate   = "apikey:create"
	ActionAPIKeyDelete   = "apikey:delete"
)

// Audit resource constants
const (
	ResourceUser         = "user"
	ResourceOrganization = "organization"
	ResourceScan         = "scan"
	ResourceFinding      = "finding"
	ResourceReport       = "report"
	ResourceAPIKey       = "apikey"
)
