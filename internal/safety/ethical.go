package safety

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EthicalChecker provides ethical and safety checks before scans
type EthicalChecker struct {
	guidelines []EthicalGuideline
	checks     []SafetyCheck
}

// EthicalGuideline represents a guideline that must be followed
type EthicalGuideline struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Category    string `json:"category"`
}

// SafetyCheck represents a safety check that must be completed
type SafetyCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Category    string `json:"category"`
}

// EthicalConsent represents user consent for ethical guidelines
type EthicalConsent struct {
	UserID     uuid.UUID              `json:"user_id"`
	OrgID      uuid.UUID              `json:"org_id"`
	Guidelines map[string]bool        `json:"guidelines"`
	Checks     map[string]bool        `json:"checks"`
	Timestamp  time.Time              `json:"timestamp"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NewEthicalChecker creates a new ethical checker with default guidelines
func NewEthicalChecker() *EthicalChecker {
	ec := &EthicalChecker{
		guidelines: getDefaultGuidelines(),
		checks:     getDefaultSafetyChecks(),
	}

	return ec
}

// ValidateConsent validates that all required ethical guidelines and safety checks are completed
func (ec *EthicalChecker) ValidateConsent(consent *EthicalConsent) error {
	// Check required guidelines
	for _, guideline := range ec.guidelines {
		if guideline.Required {
			if !consent.Guidelines[guideline.ID] {
				return fmt.Errorf("required ethical guideline not accepted: %s", guideline.Title)
			}
		}
	}

	// Check required safety checks
	for _, check := range ec.checks {
		if check.Required {
			if !consent.Checks[check.ID] {
				return fmt.Errorf("required safety check not completed: %s", check.Title)
			}
		}
	}

	return nil
}

// GetGuidelines returns all ethical guidelines
func (ec *EthicalChecker) GetGuidelines() []EthicalGuideline {
	return ec.guidelines
}

// GetSafetyChecks returns all safety checks
func (ec *EthicalChecker) GetSafetyChecks() []SafetyCheck {
	return ec.checks
}

// GetConsentForm returns a formatted consent form
func (ec *EthicalChecker) GetConsentForm() ConsentForm {
	return ConsentForm{
		Guidelines: ec.guidelines,
		Checks:     ec.checks,
		Timestamp:  time.Now(),
	}
}

// ConsentForm represents a consent form for ethical guidelines
type ConsentForm struct {
	Guidelines []EthicalGuideline `json:"guidelines"`
	Checks     []SafetyCheck      `json:"checks"`
	Timestamp  time.Time          `json:"timestamp"`
}

// getDefaultGuidelines returns the default ethical guidelines
func getDefaultGuidelines() []EthicalGuideline {
	return []EthicalGuideline{
		{
			ID:          "permission",
			Title:       "Explicit Permission",
			Description: "I have explicit written permission to perform security testing on the target system",
			Required:    true,
			Category:    "Authorization",
		},
		{
			ID:          "authorization",
			Title:       "Proper Authorization",
			Description: "I am authorized by the system owner to perform security testing",
			Required:    true,
			Category:    "Authorization",
		},
		{
			ID:          "notification",
			Title:       "Stakeholder Notification",
			Description: "Relevant stakeholders have been notified about the security testing",
			Required:    true,
			Category:    "Communication",
		},
		{
			ID:          "scope",
			Title:       "Defined Scope",
			Description: "The scope of testing is clearly defined and agreed upon",
			Required:    true,
			Category:    "Scope",
		},
		{
			ID:          "impact",
			Title:       "Impact Understanding",
			Description: "I understand the potential impact of security testing on the target system",
			Required:    true,
			Category:    "Risk",
		},
		{
			ID:          "destructive",
			Title:       "No Destructive Operations",
			Description: "I will not perform destructive operations without explicit consent",
			Required:    true,
			Category:    "Safety",
		},
		{
			ID:          "rate_limits",
			Title:       "Respect Rate Limits",
			Description: "I will respect rate limits and not overwhelm the target system",
			Required:    true,
			Category:    "Safety",
		},
		{
			ID:          "reporting",
			Title:       "Responsible Reporting",
			Description: "I will report findings responsibly and securely to authorized personnel",
			Required:    true,
			Category:    "Reporting",
		},
		{
			ID:          "production",
			Title:       "Production Systems",
			Description: "I will not test production systems without proper authorization and safeguards",
			Required:    true,
			Category:    "Safety",
		},
		{
			ID:          "data_protection",
			Title:       "Data Protection",
			Description: "I will protect any sensitive data discovered during testing",
			Required:    true,
			Category:    "Privacy",
		},
	}
}

// getDefaultSafetyChecks returns the default safety checks
func getDefaultSafetyChecks() []SafetyCheck {
	return []SafetyCheck{
		{
			ID:          "contact_person",
			Title:       "Emergency Contact",
			Description: "Emergency contact person has been identified and notified",
			Required:    true,
			Category:    "Emergency",
		},
		{
			ID:          "rollback_plan",
			Title:       "Rollback Plan",
			Description: "A rollback plan is in place in case of issues",
			Required:    true,
			Category:    "Recovery",
		},
		{
			ID:          "monitoring",
			Title:       "System Monitoring",
			Description: "Target system monitoring is in place during testing",
			Required:    true,
			Category:    "Monitoring",
		},
		{
			ID:          "backup",
			Title:       "Data Backup",
			Description: "Critical data has been backed up before testing",
			Required:    true,
			Category:    "Data Protection",
		},
		{
			ID:          "schedule",
			Title:       "Testing Schedule",
			Description: "Testing is scheduled during appropriate maintenance windows",
			Required:    false,
			Category:    "Scheduling",
		},
		{
			ID:          "team_availability",
			Title:       "Team Availability",
			Description: "Response team is available during testing hours",
			Required:    true,
			Category:    "Support",
		},
		{
			ID:          "communication_channel",
			Title:       "Communication Channel",
			Description: "Direct communication channel is established with system owners",
			Required:    true,
			Category:    "Communication",
		},
		{
			ID:          "kill_switch",
			Title:       "Emergency Stop",
			Description: "Emergency stop procedures are understood and accessible",
			Required:    true,
			Category:    "Safety",
		},
	}
}

// SafeDefaults provides safe default configurations
type SafeDefaults struct {
	MaxConcurrency     int           `json:"max_concurrency"`
	MaxRateLimit       int           `json:"max_rate_limit"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	AllowedPayloads    []string      `json:"allowed_payloads"`
	BlockedPayloads    []string      `json:"blocked_payloads"`
	RequireAuth        bool          `json:"require_auth"`
	MaxScanDuration    time.Duration `json:"max_scan_duration"`
	DestructiveAllowed bool          `json:"destructive_allowed"`
}

// GetSafeDefaults returns safe default configurations
func GetSafeDefaults() *SafeDefaults {
	return &SafeDefaults{
		MaxConcurrency:     5,
		MaxRateLimit:       10,
		DefaultTimeout:     30 * time.Second,
		AllowedPayloads:    []string{"xss", "sqli", "xxe", "lfi", "rfi", "ssti"},
		BlockedPayloads:    []string{"rm", "del", "format", "shutdown", "reboot"},
		RequireAuth:        true,
		MaxScanDuration:    4 * time.Hour,
		DestructiveAllowed: false,
	}
}

// ValidateSafeDefaults validates scan configuration against safe defaults
func ValidateSafeDefaults(config map[string]interface{}) error {
	defaults := GetSafeDefaults()

	// Check concurrency
	if concurrency, ok := config["concurrency"].(int); ok {
		if concurrency > defaults.MaxConcurrency {
			return fmt.Errorf("concurrency exceeds safe maximum: %d > %d", concurrency, defaults.MaxConcurrency)
		}
	}

	// Check rate limit
	if rateLimit, ok := config["rate_limit"].(int); ok {
		if rateLimit > defaults.MaxRateLimit {
			return fmt.Errorf("rate limit exceeds safe maximum: %d > %d", rateLimit, defaults.MaxRateLimit)
		}
	}

	// Check timeout
	if timeout, ok := config["timeout"].(time.Duration); ok {
		if timeout > defaults.DefaultTimeout {
			return fmt.Errorf("timeout exceeds safe maximum: %v > %v", timeout, defaults.DefaultTimeout)
		}
	}

	// Check for destructive payloads
	if payloads, ok := config["payloads"].([]string); ok {
		for _, payload := range payloads {
			for _, blocked := range defaults.BlockedPayloads {
				if payload == blocked {
					return fmt.Errorf("destructive payload blocked: %s", payload)
				}
			}
		}
	}

	// Check scan duration
	if duration, ok := config["max_duration"].(time.Duration); ok {
		if duration > defaults.MaxScanDuration {
			return fmt.Errorf("scan duration exceeds safe maximum: %v > %v", duration, defaults.MaxScanDuration)
		}
	}

	return nil
}

// RequireDestructiveFlag checks if destructive operations require explicit flag
func RequireDestructiveFlag(config map[string]interface{}) bool {
	defaults := GetSafeDefaults()

	if !defaults.DestructiveAllowed {
		// Check if destructive flag is set
		if allowDestructive, ok := config["allow_destructive"].(bool); ok {
			return allowDestructive
		}
		return false
	}

	return true
}
