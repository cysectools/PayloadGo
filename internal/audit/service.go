package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Service handles audit logging operations
type Service struct {
	auditRepo    AuditRepository
	evidenceRepo EvidenceRepository
	signingKey   []byte
}

// NewService creates a new audit service
func NewService(auditRepo AuditRepository, evidenceRepo EvidenceRepository, signingKey []byte) *Service {
	return &Service{
		auditRepo:    auditRepo,
		evidenceRepo: evidenceRepo,
		signingKey:   signingKey,
	}
}

// LogEvent logs an audit event
func (s *Service) LogEvent(event *AuditEvent) error {
	// Generate hash for tamper detection
	hash, err := s.generateHash(event)
	if err != nil {
		return fmt.Errorf("failed to generate hash: %w", err)
	}
	event.Hash = hash

	// Generate signature
	signature, err := s.generateSignature(event)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}
	event.Signature = signature

	// Store event
	if err := s.auditRepo.CreateEvent(event); err != nil {
		return fmt.Errorf("failed to store audit event: %w", err)
	}

	return nil
}

// LogUserAction logs a user action
func (s *Service) LogUserAction(userID, organizationID, action, resource, resourceID, ipAddress, userAgent string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:             generateEventID(),
		Timestamp:      time.Now(),
		UserID:         userID,
		OrganizationID: organizationID,
		Action:         action,
		Resource:       resource,
		ResourceID:     resourceID,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Details:        details,
		CreatedAt:      time.Now(),
	}

	return s.LogEvent(event)
}

// LogSystemAction logs a system action
func (s *Service) LogSystemAction(action, resource, resourceID string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:         generateEventID(),
		Timestamp:  time.Now(),
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		CreatedAt:  time.Now(),
	}

	return s.LogEvent(event)
}

// LogScanAction logs a scan-related action
func (s *Service) LogScanAction(userID, organizationID, action, scanID, ipAddress, userAgent string, details map[string]interface{}) error {
	return s.LogUserAction(userID, organizationID, action, ResourceScan, scanID, ipAddress, userAgent, details)
}

// LogFindingAction logs a finding-related action
func (s *Service) LogFindingAction(userID, organizationID, action, findingID, ipAddress, userAgent string, details map[string]interface{}) error {
	return s.LogUserAction(userID, organizationID, action, ResourceFinding, findingID, ipAddress, userAgent, details)
}

// LogReportAction logs a report-related action
func (s *Service) LogReportAction(userID, organizationID, action, reportID, ipAddress, userAgent string, details map[string]interface{}) error {
	return s.LogUserAction(userID, organizationID, action, ResourceReport, reportID, ipAddress, userAgent, details)
}

// LogSecurityEvent logs a security-related event
func (s *Service) LogSecurityEvent(level, action, resource, resourceID string, details map[string]interface{}) error {
	event := &AuditEvent{
		ID:         generateEventID(),
		Timestamp:  time.Now(),
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
		CreatedAt:  time.Now(),
	}

	// Add security level to details
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	event.Details["security_level"] = level

	return s.LogEvent(event)
}

// StoreEvidence stores tamper-evident evidence
func (s *Service) StoreEvidence(eventID, evidenceType string, content []byte) (*Evidence, error) {
	// Generate content hash
	contentHash := s.generateContentHash(content)

	// Create evidence
	evidence := &Evidence{
		ID:          generateEvidenceID(),
		EventID:     eventID,
		Type:        evidenceType,
		Content:     content,
		ContentHash: contentHash,
		CreatedAt:   time.Now(),
	}

	// Generate signature
	signature, err := s.generateEvidenceSignature(evidence)
	if err != nil {
		return nil, fmt.Errorf("failed to generate evidence signature: %w", err)
	}
	evidence.Signature = signature

	// Store evidence
	if err := s.evidenceRepo.CreateEvidence(evidence); err != nil {
		return nil, fmt.Errorf("failed to store evidence: %w", err)
	}

	return evidence, nil
}

// VerifyEvidence verifies the integrity of stored evidence
func (s *Service) VerifyEvidence(evidenceID string) (bool, error) {
	// Get evidence
	evidence, err := s.evidenceRepo.GetEvidence(evidenceID)
	if err != nil {
		return false, fmt.Errorf("failed to get evidence: %w", err)
	}

	// Verify content hash
	expectedHash := s.generateContentHash(evidence.Content)
	if evidence.ContentHash != expectedHash {
		return false, fmt.Errorf("content hash mismatch")
	}

	// Verify signature
	valid, err := s.verifyEvidenceSignature(evidence)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	return valid, nil
}

// GetAuditTrail retrieves audit events for a specific resource
func (s *Service) GetAuditTrail(resource, resourceID string, limit, offset int) ([]*AuditEvent, error) {
	return s.auditRepo.GetEventsByResource(resource, resourceID, limit, offset)
}

// GetUserAuditTrail retrieves audit events for a specific user
func (s *Service) GetUserAuditTrail(userID string, limit, offset int) ([]*AuditEvent, error) {
	return s.auditRepo.GetEventsByUser(userID, limit, offset)
}

// GetOrganizationAuditTrail retrieves audit events for a specific organization
func (s *Service) GetOrganizationAuditTrail(orgID string, limit, offset int) ([]*AuditEvent, error) {
	return s.auditRepo.GetEventsByOrganization(orgID, limit, offset)
}

// SearchAuditEvents searches audit events
func (s *Service) SearchAuditEvents(query string, limit, offset int) ([]*AuditEvent, error) {
	return s.auditRepo.SearchEvents(query, limit, offset)
}

// Helper functions

func (s *Service) generateHash(event *AuditEvent) (string, error) {
	// Create a copy of the event without hash and signature for hashing
	eventCopy := *event
	eventCopy.Hash = ""
	eventCopy.Signature = ""

	// Serialize event to JSON
	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %w", err)
	}

	// Generate SHA-256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (s *Service) generateSignature(event *AuditEvent) (string, error) {
	// Create JWT token with event data
	claims := jwt.MapClaims{
		"event_id":  event.ID,
		"timestamp": event.Timestamp.Unix(),
		"user_id":   event.UserID,
		"action":    event.Action,
		"resource":  event.Resource,
		"hash":      event.Hash,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signature, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signature, nil
}

func (s *Service) generateContentHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func (s *Service) generateEvidenceSignature(evidence *Evidence) (string, error) {
	// Create JWT token with evidence data
	claims := jwt.MapClaims{
		"evidence_id":  evidence.ID,
		"event_id":     evidence.EventID,
		"type":         evidence.Type,
		"content_hash": evidence.ContentHash,
		"created_at":   evidence.CreatedAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signature, err := token.SignedString(s.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign evidence: %w", err)
	}

	return signature, nil
}

func (s *Service) verifyEvidenceSignature(evidence *Evidence) (bool, error) {
	// Parse JWT token
	token, err := jwt.Parse(evidence.Signature, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	})

	if err != nil {
		return false, fmt.Errorf("failed to parse signature: %w", err)
	}

	if !token.Valid {
		return false, fmt.Errorf("invalid signature")
	}

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid claims")
	}

	// Check evidence ID
	if claims["evidence_id"] != evidence.ID {
		return false, fmt.Errorf("evidence ID mismatch")
	}

	// Check content hash
	if claims["content_hash"] != evidence.ContentHash {
		return false, fmt.Errorf("content hash mismatch")
	}

	return true, nil
}

func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

func generateEvidenceID() string {
	return fmt.Sprintf("evd_%d", time.Now().UnixNano())
}
