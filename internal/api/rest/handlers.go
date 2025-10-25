package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"payloadgo/internal/audit"
	"payloadgo/internal/auth"
	"payloadgo/internal/storage"

	"github.com/gin-gonic/gin"
)

// Handlers provides HTTP handlers for the REST API
type Handlers struct {
	authService  *auth.Service
	scanRepo     storage.ScanRepository
	findingRepo  storage.FindingRepository
	reportRepo   storage.ReportRepository
	jobRepo      storage.JobRepository
	auditService *audit.Service
}

// NewHandlers creates a new handlers instance
func NewHandlers(
	authService *auth.Service,
	scanRepo storage.ScanRepository,
	findingRepo storage.FindingRepository,
	reportRepo storage.ReportRepository,
	jobRepo storage.JobRepository,
	auditService *audit.Service,
) *Handlers {
	return &Handlers{
		authService:  authService,
		scanRepo:     scanRepo,
		findingRepo:  findingRepo,
		reportRepo:   reportRepo,
		jobRepo:      jobRepo,
		auditService: auditService,
	}
}

// RegisterRoutes registers all API routes
func (h *Handlers) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api/v1")

	// Authentication routes
	auth := api.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/logout", h.Logout)
		auth.POST("/refresh", h.RefreshToken)
		auth.POST("/forgot-password", h.ForgotPassword)
		auth.POST("/reset-password", h.ResetPassword)
	}

	// Protected routes
	protected := api.Group("")
	protected.Use(h.RequireAuth())
	{
		// Scan routes
		scans := protected.Group("/scans")
		{
			scans.GET("", h.ListScans)
			scans.POST("", h.CreateScan)
			scans.GET("/:id", h.GetScan)
			scans.PUT("/:id", h.UpdateScan)
			scans.DELETE("/:id", h.DeleteScan)
			scans.POST("/:id/start", h.StartScan)
			scans.POST("/:id/pause", h.PauseScan)
			scans.POST("/:id/resume", h.ResumeScan)
			scans.POST("/:id/stop", h.StopScan)
			scans.GET("/:id/findings", h.GetScanFindings)
			scans.GET("/:id/reports", h.GetScanReports)
		}

		// Finding routes
		findings := protected.Group("/findings")
		{
			findings.GET("", h.ListFindings)
			findings.GET("/:id", h.GetFinding)
			findings.PUT("/:id", h.UpdateFinding)
			findings.DELETE("/:id", h.DeleteFinding)
			findings.POST("/:id/confirm", h.ConfirmFinding)
			findings.POST("/:id/false-positive", h.MarkFalsePositive)
			findings.POST("/:id/assign", h.AssignFinding)
		}

		// Report routes
		reports := protected.Group("/reports")
		{
			reports.GET("", h.ListReports)
			reports.POST("", h.CreateReport)
			reports.GET("/:id", h.GetReport)
			reports.DELETE("/:id", h.DeleteReport)
			reports.GET("/:id/download", h.DownloadReport)
		}

		// Organization routes
		orgs := protected.Group("/organizations")
		{
			orgs.GET("", h.ListOrganizations)
			orgs.POST("", h.CreateOrganization)
			orgs.GET("/:id", h.GetOrganization)
			orgs.PUT("/:id", h.UpdateOrganization)
			orgs.DELETE("/:id", h.DeleteOrganization)
		}

		// User routes
		users := protected.Group("/users")
		{
			users.GET("", h.ListUsers)
			users.POST("", h.CreateUser)
			users.GET("/:id", h.GetUser)
			users.PUT("/:id", h.UpdateUser)
			users.DELETE("/:id", h.DeleteUser)
		}

		// API Key routes
		apiKeys := protected.Group("/api-keys")
		{
			apiKeys.GET("", h.ListAPIKeys)
			apiKeys.POST("", h.CreateAPIKey)
			apiKeys.DELETE("/:id", h.DeleteAPIKey)
		}
	}
}

// Authentication handlers

// Register handles user registration
func (h *Handlers) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Log registration event
	h.auditService.LogUserAction(user.ID, "", auth.ActionUserCreate, auth.ResourceUser, user.ID, c.ClientIP(), c.GetHeader("User-Agent"), map[string]interface{}{
		"email":    user.Email,
		"username": user.Username,
	})

	c.JSON(http.StatusCreated, gin.H{"user": user})
}

// Login handles user login
func (h *Handlers) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		// Log failed login attempt
		h.auditService.LogSecurityEvent(audit.LevelWarning, auth.ActionLoginFailed, auth.ResourceUser, "", map[string]interface{}{
			"email":      req.Email,
			"ip_address": c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
		})

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Log successful login
	h.auditService.LogUserAction(response.User.ID, response.Organization.ID, auth.ActionLogin, auth.ResourceUser, response.User.ID, c.ClientIP(), c.GetHeader("User-Agent"), map[string]interface{}{
		"organization": response.Organization.Name,
	})

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *Handlers) Logout(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get token from header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header required"})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	if err := h.authService.Logout(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	// Log logout event
	h.auditService.LogUserAction(authCtx.User.ID, authCtx.Organization.ID, auth.ActionLogout, auth.ResourceUser, authCtx.User.ID, c.ClientIP(), c.GetHeader("User-Agent"), nil)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// ForgotPassword handles password reset requests
func (h *Handlers) ForgotPassword(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ResetPassword handles password reset confirmation
func (h *Handlers) ResetPassword(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// PauseScan pauses a running scan
func (h *Handlers) PauseScan(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ResumeScan resumes a paused scan
func (h *Handlers) ResumeScan(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// StopScan stops a running scan
func (h *Handlers) StopScan(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// GetScanReports retrieves reports for a scan
func (h *Handlers) GetScanReports(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ListFindings lists findings
func (h *Handlers) ListFindings(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// GetFinding retrieves a finding by ID
func (h *Handlers) GetFinding(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// UpdateFinding updates a finding
func (h *Handlers) UpdateFinding(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DeleteFinding deletes a finding
func (h *Handlers) DeleteFinding(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ConfirmFinding confirms a finding
func (h *Handlers) ConfirmFinding(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// MarkFalsePositive marks a finding as false positive
func (h *Handlers) MarkFalsePositive(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// AssignFinding assigns a finding to a user
func (h *Handlers) AssignFinding(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ListReports lists reports
func (h *Handlers) ListReports(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// CreateReport creates a new report
func (h *Handlers) CreateReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// GetReport retrieves a report by ID
func (h *Handlers) GetReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DeleteReport deletes a report
func (h *Handlers) DeleteReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DownloadReport downloads a report file
func (h *Handlers) DownloadReport(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ListOrganizations lists organizations
func (h *Handlers) ListOrganizations(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// CreateOrganization creates a new organization
func (h *Handlers) CreateOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// GetOrganization retrieves an organization by ID
func (h *Handlers) GetOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// UpdateOrganization updates an organization
func (h *Handlers) UpdateOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DeleteOrganization deletes an organization
func (h *Handlers) DeleteOrganization(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ListUsers lists users
func (h *Handlers) ListUsers(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// CreateUser creates a new user
func (h *Handlers) CreateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// GetUser retrieves a user by ID
func (h *Handlers) GetUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// UpdateUser updates a user
func (h *Handlers) UpdateUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DeleteUser deletes a user
func (h *Handlers) DeleteUser(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// ListAPIKeys lists API keys
func (h *Handlers) ListAPIKeys(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// CreateAPIKey creates a new API key
func (h *Handlers) CreateAPIKey(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// DeleteAPIKey deletes an API key
func (h *Handlers) DeleteAPIKey(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented"})
}

// RefreshToken handles token refresh
func (h *Handlers) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// Scan handlers

// ListScans lists scans for the authenticated user
func (h *Handlers) ListScans(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Parse query parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	scans, err := h.scanRepo.GetByOrganization(authCtx.Organization.ID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// CreateScan creates a new scan
func (h *Handlers) CreateScan(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var req struct {
		Name        string                 `json:"name" binding:"required"`
		Description string                 `json:"description"`
		Target      string                 `json:"target" binding:"required"`
		Config      map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scan := &storage.Scan{
		ID:             generateID(),
		OrganizationID: authCtx.Organization.ID,
		UserID:         authCtx.User.ID,
		Name:           req.Name,
		Description:    req.Description,
		Target:         req.Target,
		Status:         storage.ScanStatusPending,
		Config:         req.Config,
		Progress:       0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := h.scanRepo.Create(scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scan"})
		return
	}

	// Log scan creation
	h.auditService.LogScanAction(authCtx.User.ID, authCtx.Organization.ID, auth.ActionScanCreate, scan.ID, c.ClientIP(), c.GetHeader("User-Agent"), map[string]interface{}{
		"target": scan.Target,
		"name":   scan.Name,
	})

	c.JSON(http.StatusCreated, gin.H{"scan": scan})
}

// GetScan retrieves a scan by ID
func (h *Handlers) GetScan(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	scanID := c.Param("id")
	scan, err := h.scanRepo.GetByID(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Check if user has access to this scan
	if scan.OrganizationID != authCtx.Organization.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scan": scan})
}

// UpdateScan updates a scan
func (h *Handlers) UpdateScan(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	scanID := c.Param("id")
	scan, err := h.scanRepo.GetByID(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Check if user has access to this scan
	if scan.OrganizationID != authCtx.Organization.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	var req struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		Config      map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update scan fields
	if req.Name != "" {
		scan.Name = req.Name
	}
	if req.Description != "" {
		scan.Description = req.Description
	}
	if req.Config != nil {
		scan.Config = req.Config
	}
	scan.UpdatedAt = time.Now()

	if err := h.scanRepo.Update(scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scan"})
		return
	}

	// Log scan update
	h.auditService.LogScanAction(authCtx.User.ID, authCtx.Organization.ID, auth.ActionScanUpdate, scan.ID, c.ClientIP(), c.GetHeader("User-Agent"), map[string]interface{}{
		"changes": req,
	})

	c.JSON(http.StatusOK, gin.H{"scan": scan})
}

// DeleteScan deletes a scan
func (h *Handlers) DeleteScan(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	scanID := c.Param("id")
	scan, err := h.scanRepo.GetByID(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Check if user has access to this scan
	if scan.OrganizationID != authCtx.Organization.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if err := h.scanRepo.Delete(scanID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scan"})
		return
	}

	// Log scan deletion
	h.auditService.LogScanAction(authCtx.User.ID, authCtx.Organization.ID, auth.ActionScanDelete, scan.ID, c.ClientIP(), c.GetHeader("User-Agent"), nil)

	c.JSON(http.StatusOK, gin.H{"message": "Scan deleted successfully"})
}

// StartScan starts a scan
func (h *Handlers) StartScan(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	scanID := c.Param("id")
	scan, err := h.scanRepo.GetByID(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Check if user has access to this scan
	if scan.OrganizationID != authCtx.Organization.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Update scan status
	scan.Status = storage.ScanStatusRunning
	now := time.Now()
	scan.StartedAt = &now
	scan.UpdatedAt = now

	if err := h.scanRepo.Update(scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start scan"})
		return
	}

	// Log scan start
	h.auditService.LogScanAction(authCtx.User.ID, authCtx.Organization.ID, auth.ActionScanStart, scan.ID, c.ClientIP(), c.GetHeader("User-Agent"), nil)

	c.JSON(http.StatusOK, gin.H{"scan": scan})
}

// GetScanFindings retrieves findings for a scan
func (h *Handlers) GetScanFindings(c *gin.Context) {
	authCtx := auth.GetAuthContext(c)
	if authCtx == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	scanID := c.Param("id")
	scan, err := h.scanRepo.GetByID(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	// Check if user has access to this scan
	if scan.OrganizationID != authCtx.Organization.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// Parse query parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	findings, err := h.findingRepo.GetByScan(scanID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch findings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings})
}

// Helper functions

func generateID() string {
	return fmt.Sprintf("id_%d", time.Now().UnixNano())
}

// RequireAuth middleware
func (h *Handlers) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		authCtx, err := h.authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("auth_context", authCtx)
		c.Next()
	}
}
