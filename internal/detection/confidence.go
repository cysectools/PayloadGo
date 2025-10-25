package detection

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ConfidenceScorer provides confidence scoring for vulnerability detection
type ConfidenceScorer struct {
	patterns map[string][]*DetectionPattern
	weights  map[string]float64
}

// DetectionPattern represents a detection pattern
type DetectionPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Weight      float64
	Description string
	Category    string
}

// ConfidenceScore represents a confidence score for a finding
type ConfidenceScore struct {
	Score       float64                `json:"score"`
	Factors     []*ConfidenceFactor    `json:"factors"`
	Explanation string                 `json:"explanation"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ConfidenceFactor represents a factor contributing to the confidence score
type ConfidenceFactor struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
}

// NewConfidenceScorer creates a new confidence scorer
func NewConfidenceScorer() *ConfidenceScorer {
	scorer := &ConfidenceScorer{
		patterns: make(map[string][]*DetectionPattern),
		weights:  make(map[string]float64),
	}

	// Initialize default patterns and weights
	scorer.initializePatterns()
	scorer.initializeWeights()

	return scorer
}

// CalculateConfidence calculates confidence score for a finding
func (cs *ConfidenceScorer) CalculateConfidence(finding *Finding) *ConfidenceScore {
	score := &ConfidenceScore{
		Score:    0.0,
		Factors:  []*ConfidenceFactor{},
		Metadata: make(map[string]interface{}),
	}

	// Analyze payload reflection
	reflectionScore := cs.analyzePayloadReflection(finding)
	score.Factors = append(score.Factors, reflectionScore)

	// Analyze error messages
	errorScore := cs.analyzeErrorMessages(finding)
	score.Factors = append(score.Factors, errorScore)

	// Analyze response timing
	timingScore := cs.analyzeResponseTiming(finding)
	score.Factors = append(score.Factors, timingScore)

	// Analyze status codes
	statusScore := cs.analyzeStatusCodes(finding)
	score.Factors = append(score.Factors, statusScore)

	// Analyze response content
	contentScore := cs.analyzeResponseContent(finding)
	score.Factors = append(score.Factors, contentScore)

	// Calculate weighted score
	totalScore := 0.0
	totalWeight := 0.0

	for _, factor := range score.Factors {
		totalScore += factor.Score * factor.Weight
		totalWeight += factor.Weight
	}

	if totalWeight > 0 {
		score.Score = totalScore / totalWeight
	}

	// Generate explanation
	score.Explanation = cs.generateExplanation(score.Factors, score.Score)

	// Add metadata
	score.Metadata["total_factors"] = len(score.Factors)
	score.Metadata["calculation_time"] = time.Now()

	return score
}

// analyzePayloadReflection analyzes payload reflection in response
func (cs *ConfidenceScorer) analyzePayloadReflection(finding *Finding) *ConfidenceFactor {
	factor := &ConfidenceFactor{
		Name:        "Payload Reflection",
		Weight:      cs.weights["payload_reflection"],
		Category:    "reflection",
		Description: "Analyzes how the payload is reflected in the response",
	}

	// Check if payload is reflected in response
	if strings.Contains(finding.Response, finding.Payload) {
		factor.Score = 0.9
		factor.Description += " - Payload is directly reflected in response"
	} else {
		// Check for partial reflection or encoding
		encodedPayload := cs.encodePayload(finding.Payload)
		if strings.Contains(finding.Response, encodedPayload) {
			factor.Score = 0.7
			factor.Description += " - Payload is reflected with encoding"
		} else {
			factor.Score = 0.3
			factor.Description += " - No payload reflection detected"
		}
	}

	return factor
}

// analyzeErrorMessages analyzes error messages in response
func (cs *ConfidenceScorer) analyzeErrorMessages(finding *Finding) *ConfidenceFactor {
	factor := &ConfidenceFactor{
		Name:        "Error Message Analysis",
		Weight:      cs.weights["error_messages"],
		Category:    "error_analysis",
		Description: "Analyzes error messages that indicate vulnerability",
	}

	score := 0.0
	matchedPatterns := []string{}

	// Check for SQL error patterns
	sqlPatterns := cs.patterns["sql_errors"]
	for _, pattern := range sqlPatterns {
		if pattern.Pattern.MatchString(finding.Response) {
			score += pattern.Weight
			matchedPatterns = append(matchedPatterns, pattern.Name)
		}
	}

	// Check for XSS error patterns
	xssPatterns := cs.patterns["xss_errors"]
	for _, pattern := range xssPatterns {
		if pattern.Pattern.MatchString(finding.Response) {
			score += pattern.Weight
			matchedPatterns = append(matchedPatterns, pattern.Name)
		}
	}

	// Check for command injection patterns
	cmdPatterns := cs.patterns["command_errors"]
	for _, pattern := range cmdPatterns {
		if pattern.Pattern.MatchString(finding.Response) {
			score += pattern.Weight
			matchedPatterns = append(matchedPatterns, pattern.Name)
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	factor.Score = score
	if len(matchedPatterns) > 0 {
		factor.Description += " - Matched error patterns: " + strings.Join(matchedPatterns, ", ")
	} else {
		factor.Description += " - No error patterns matched"
	}

	return factor
}

// analyzeResponseTiming analyzes response timing for blind injection
func (cs *ConfidenceScorer) analyzeResponseTiming(finding *Finding) *ConfidenceFactor {
	factor := &ConfidenceFactor{
		Name:        "Response Timing",
		Weight:      cs.weights["response_timing"],
		Category:    "timing",
		Description: "Analyzes response timing for blind injection detection",
	}

	// Check if payload contains timing-based injection
	if strings.Contains(finding.Payload, "sleep(") || strings.Contains(finding.Payload, "waitfor") {
		// This would typically compare with baseline response time
		// For now, use a simple heuristic
		if finding.ResponseTime > 3*time.Second {
			factor.Score = 0.8
			factor.Description += " - Delayed response indicates timing-based injection"
		} else {
			factor.Score = 0.2
			factor.Description += " - No significant delay detected"
		}
	} else {
		factor.Score = 0.5
		factor.Description += " - No timing-based payload detected"
	}

	return factor
}

// analyzeStatusCodes analyzes HTTP status codes
func (cs *ConfidenceScorer) analyzeStatusCodes(finding *Finding) *ConfidenceFactor {
	factor := &ConfidenceFactor{
		Name:        "Status Code Analysis",
		Weight:      cs.weights["status_codes"],
		Category:    "status",
		Description: "Analyzes HTTP status codes for vulnerability indicators",
	}

	score := 0.0

	switch finding.StatusCode {
	case 200:
		score = 0.6 // Normal response
	case 500:
		score = 0.8 // Server error - might indicate injection
	case 403:
		score = 0.7 // Forbidden - might indicate path traversal
	case 404:
		score = 0.3 // Not found
	case 400:
		score = 0.5 // Bad request
	default:
		score = 0.4 // Other status codes
	}

	factor.Score = score
	factor.Description += " - Status code: " + string(rune(finding.StatusCode))

	return factor
}

// analyzeResponseContent analyzes response content for vulnerability indicators
func (cs *ConfidenceScorer) analyzeResponseContent(finding *Finding) *ConfidenceFactor {
	factor := &ConfidenceFactor{
		Name:        "Response Content Analysis",
		Weight:      cs.weights["response_content"],
		Category:    "content",
		Description: "Analyzes response content for vulnerability indicators",
	}

	score := 0.0
	indicators := []string{}

	// Check for database-related content
	dbIndicators := []string{"mysql", "postgresql", "oracle", "sqlite", "database", "query"}
	for _, indicator := range dbIndicators {
		if strings.Contains(strings.ToLower(finding.Response), indicator) {
			score += 0.2
			indicators = append(indicators, indicator)
		}
	}

	// Check for system-related content
	sysIndicators := []string{"root:", "/etc/passwd", "system", "command", "exec"}
	for _, indicator := range sysIndicators {
		if strings.Contains(strings.ToLower(finding.Response), indicator) {
			score += 0.3
			indicators = append(indicators, indicator)
		}
	}

	// Check for file system indicators
	fsIndicators := []string{"directory", "file", "path", "access denied"}
	for _, indicator := range fsIndicators {
		if strings.Contains(strings.ToLower(finding.Response), indicator) {
			score += 0.2
			indicators = append(indicators, indicator)
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	factor.Score = score
	if len(indicators) > 0 {
		factor.Description += " - Found indicators: " + strings.Join(indicators, ", ")
	} else {
		factor.Description += " - No vulnerability indicators found"
	}

	return factor
}

// encodePayload applies common encoding to payload
func (cs *ConfidenceScorer) encodePayload(payload string) string {
	// URL encoding
	encoded := strings.ReplaceAll(payload, "<", "%3C")
	encoded = strings.ReplaceAll(encoded, ">", "%3E")
	encoded = strings.ReplaceAll(encoded, " ", "%20")
	encoded = strings.ReplaceAll(encoded, "'", "%27")
	encoded = strings.ReplaceAll(encoded, "\"", "%22")

	return encoded
}

// generateExplanation generates a human-readable explanation of the confidence score
func (cs *ConfidenceScorer) generateExplanation(factors []*ConfidenceFactor, score float64) string {
	explanation := "Confidence Score: " + formatScore(score) + "\n\n"
	explanation += "Contributing Factors:\n"

	for _, factor := range factors {
		explanation += "- " + factor.Name + ": " + formatScore(factor.Score) + " (weight: " + formatWeight(factor.Weight) + ")\n"
		explanation += "  " + factor.Description + "\n\n"
	}

	// Add overall assessment
	if score >= 0.8 {
		explanation += "Assessment: HIGH confidence - Strong indicators of vulnerability"
	} else if score >= 0.6 {
		explanation += "Assessment: MEDIUM confidence - Some indicators present"
	} else if score >= 0.4 {
		explanation += "Assessment: LOW confidence - Weak indicators"
	} else {
		explanation += "Assessment: VERY LOW confidence - Minimal indicators"
	}

	return explanation
}

// initializePatterns initializes detection patterns
func (cs *ConfidenceScorer) initializePatterns() {
	// SQL error patterns
	cs.patterns["sql_errors"] = []*DetectionPattern{
		{
			Name:        "MySQL Error",
			Pattern:     regexp.MustCompile(`(?i)mysql.*error|mysql.*warning`),
			Weight:      0.9,
			Description: "MySQL database error",
			Category:    "sql",
		},
		{
			Name:        "PostgreSQL Error",
			Pattern:     regexp.MustCompile(`(?i)postgresql.*error|postgres.*error`),
			Weight:      0.9,
			Description: "PostgreSQL database error",
			Category:    "sql",
		},
		{
			Name:        "SQL Syntax Error",
			Pattern:     regexp.MustCompile(`(?i)syntax.*error|sql.*error`),
			Weight:      0.8,
			Description: "SQL syntax error",
			Category:    "sql",
		},
	}

	// XSS error patterns
	cs.patterns["xss_errors"] = []*DetectionPattern{
		{
			Name:        "Script Tag Error",
			Pattern:     regexp.MustCompile(`(?i)<script.*error|script.*error`),
			Weight:      0.7,
			Description: "Script tag processing error",
			Category:    "xss",
		},
	}

	// Command injection patterns
	cs.patterns["command_errors"] = []*DetectionPattern{
		{
			Name:        "Command Not Found",
			Pattern:     regexp.MustCompile(`(?i)command.*not.*found|cmd.*not.*found`),
			Weight:      0.8,
			Description: "Command not found error",
			Category:    "command",
		},
		{
			Name:        "Permission Denied",
			Pattern:     regexp.MustCompile(`(?i)permission.*denied|access.*denied`),
			Weight:      0.6,
			Description: "Permission denied error",
			Category:    "command",
		},
	}
}

// initializeWeights initializes factor weights
func (cs *ConfidenceScorer) initializeWeights() {
	cs.weights["payload_reflection"] = 0.3
	cs.weights["error_messages"] = 0.25
	cs.weights["response_timing"] = 0.2
	cs.weights["status_codes"] = 0.15
	cs.weights["response_content"] = 0.1
}

// Helper functions

func formatScore(score float64) string {
	return fmt.Sprintf("%.2f", score)
}

func formatWeight(weight float64) string {
	return fmt.Sprintf("%.2f", weight)
}

// Finding represents a vulnerability finding
type Finding struct {
	ID           string
	Type         string
	Payload      string
	Response     string
	ResponseTime time.Duration
	StatusCode   int
	URL          string
	Method       string
}
