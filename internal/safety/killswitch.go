package safety

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// KillSwitch provides emergency stop functionality for all running scans
type KillSwitch struct {
	mu          sync.RWMutex
	isActive    bool
	reason      string
	activatedBy string
	activatedAt time.Time
	scans       map[uuid.UUID]*ScanContext
	notifyChan  chan KillSwitchEvent
	subscribers []KillSwitchSubscriber
}

// ScanContext represents a running scan that can be killed
type ScanContext struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	OrgID      uuid.UUID
	Target     string
	StartedAt  time.Time
	Context    context.Context
	CancelFunc context.CancelFunc
	Status     string
	Progress   float64
}

// KillSwitchEvent represents a kill switch event
type KillSwitchEvent struct {
	Type      string     `json:"type"` // "activated", "deactivated", "scan_killed"
	Reason    string     `json:"reason"`
	UserID    uuid.UUID  `json:"user_id"`
	OrgID     uuid.UUID  `json:"org_id"`
	Timestamp time.Time  `json:"timestamp"`
	ScanID    *uuid.UUID `json:"scan_id,omitempty"`
}

// KillSwitchSubscriber interface for components that need to be notified of kill switch events
type KillSwitchSubscriber interface {
	OnKillSwitchActivated(event KillSwitchEvent)
	OnKillSwitchDeactivated(event KillSwitchEvent)
	OnScanKilled(event KillSwitchEvent)
}

// NewKillSwitch creates a new kill switch instance
func NewKillSwitch() *KillSwitch {
	ks := &KillSwitch{
		scans:       make(map[uuid.UUID]*ScanContext),
		notifyChan:  make(chan KillSwitchEvent, 100),
		subscribers: make([]KillSwitchSubscriber, 0),
	}

	// Start event processing goroutine
	go ks.processEvents()

	return ks
}

// RegisterScan registers a new scan with the kill switch
func (ks *KillSwitch) RegisterScan(scanCtx *ScanContext) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if kill switch is already active
	if ks.isActive {
		return fmt.Errorf("kill switch is active - cannot register new scans")
	}

	ks.scans[scanCtx.ID] = scanCtx
	return nil
}

// UnregisterScan removes a scan from the kill switch
func (ks *KillSwitch) UnregisterScan(scanID uuid.UUID) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	delete(ks.scans, scanID)
}

// ActivateKillSwitch activates the kill switch for an organization or globally
func (ks *KillSwitch) ActivateKillSwitch(userID, orgID uuid.UUID, reason string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.isActive {
		return fmt.Errorf("kill switch is already active")
	}

	ks.isActive = true
	ks.reason = reason
	ks.activatedBy = userID.String()
	ks.activatedAt = time.Now()

	// Kill all running scans
	for scanID, scanCtx := range ks.scans {
		if orgID == uuid.Nil || scanCtx.OrgID == orgID {
			ks.killScan(scanID, scanCtx)
		}
	}

	// Notify subscribers
	event := KillSwitchEvent{
		Type:      "activated",
		Reason:    reason,
		UserID:    userID,
		OrgID:     orgID,
		Timestamp: time.Now(),
	}

	select {
	case ks.notifyChan <- event:
	default:
		// Channel is full, event will be dropped
	}

	return nil
}

// DeactivateKillSwitch deactivates the kill switch
func (ks *KillSwitch) DeactivateKillSwitch(userID uuid.UUID) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.isActive {
		return fmt.Errorf("kill switch is not active")
	}

	ks.isActive = false
	ks.reason = ""
	ks.activatedBy = ""
	ks.activatedAt = time.Time{}

	// Notify subscribers
	event := KillSwitchEvent{
		Type:      "deactivated",
		Reason:    "Kill switch deactivated",
		UserID:    userID,
		OrgID:     uuid.Nil,
		Timestamp: time.Now(),
	}

	select {
	case ks.notifyChan <- event:
	default:
		// Channel is full, event will be dropped
	}

	return nil
}

// IsActive returns whether the kill switch is currently active
func (ks *KillSwitch) IsActive() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.isActive
}

// GetStatus returns the current kill switch status
func (ks *KillSwitch) GetStatus() KillSwitchStatus {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	return KillSwitchStatus{
		IsActive:    ks.isActive,
		Reason:      ks.reason,
		ActivatedBy: ks.activatedBy,
		ActivatedAt: ks.activatedAt,
		ActiveScans: len(ks.scans),
	}
}

// KillSwitchStatus represents the current status of the kill switch
type KillSwitchStatus struct {
	IsActive    bool      `json:"is_active"`
	Reason      string    `json:"reason"`
	ActivatedBy string    `json:"activated_by"`
	ActivatedAt time.Time `json:"activated_at"`
	ActiveScans int       `json:"active_scans"`
}

// CheckKillSwitch checks if the kill switch is active and should stop the scan
func (ks *KillSwitch) CheckKillSwitch(scanID uuid.UUID) error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if !ks.isActive {
		return nil
	}

	// Check if this specific scan should be killed
	scanCtx, exists := ks.scans[scanID]
	if !exists {
		return nil
	}

	// Kill the scan
	ks.killScan(scanID, scanCtx)

	return fmt.Errorf("scan killed by emergency kill switch: %s", ks.reason)
}

// Subscribe adds a subscriber to receive kill switch events
func (ks *KillSwitch) Subscribe(subscriber KillSwitchSubscriber) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.subscribers = append(ks.subscribers, subscriber)
}

// killScan kills a specific scan
func (ks *KillSwitch) killScan(scanID uuid.UUID, scanCtx *ScanContext) {
	// Cancel the scan context
	if scanCtx.CancelFunc != nil {
		scanCtx.CancelFunc()
	}

	// Update scan status
	scanCtx.Status = "killed"

	// Notify subscribers
	event := KillSwitchEvent{
		Type:      "scan_killed",
		Reason:    ks.reason,
		UserID:    scanCtx.UserID,
		OrgID:     scanCtx.OrgID,
		Timestamp: time.Now(),
		ScanID:    &scanID,
	}

	select {
	case ks.notifyChan <- event:
	default:
		// Channel is full, event will be dropped
	}
}

// processEvents processes kill switch events and notifies subscribers
func (ks *KillSwitch) processEvents() {
	for event := range ks.notifyChan {
		ks.mu.RLock()
		subscribers := make([]KillSwitchSubscriber, len(ks.subscribers))
		copy(subscribers, ks.subscribers)
		ks.mu.RUnlock()

		// Notify all subscribers
		for _, subscriber := range subscribers {
			switch event.Type {
			case "activated":
				subscriber.OnKillSwitchActivated(event)
			case "deactivated":
				subscriber.OnKillSwitchDeactivated(event)
			case "scan_killed":
				subscriber.OnScanKilled(event)
			}
		}
	}
}

// GetActiveScans returns information about currently active scans
func (ks *KillSwitch) GetActiveScans() []ScanContext {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	scans := make([]ScanContext, 0, len(ks.scans))
	for _, scan := range ks.scans {
		scans = append(scans, *scan)
	}

	return scans
}

// EmergencyKillAll immediately kills all scans without any checks
func (ks *KillSwitch) EmergencyKillAll(reason string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.isActive = true
	ks.reason = reason
	ks.activatedBy = "system"
	ks.activatedAt = time.Now()

	// Kill all scans immediately
	for scanID, scanCtx := range ks.scans {
		ks.killScan(scanID, scanCtx)
	}

	// Clear the scans map
	ks.scans = make(map[uuid.UUID]*ScanContext)
}
