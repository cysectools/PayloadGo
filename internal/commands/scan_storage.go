package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ScanData represents a saved scan result
type ScanData struct {
	ScanID        string                 `json:"scan_id"`
	Target        string                 `json:"target"`
	Domain        string                 `json:"domain"`
	Status        string                 `json:"status"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   time.Time              `json:"completed_at"`
	Duration      string                 `json:"duration"`
	Findings      []Finding              `json:"findings"`
	Statistics    Statistics             `json:"statistics"`
	Configuration map[string]interface{} `json:"configuration"`
}

// Finding represents a security finding
type Finding struct {
	ID             string    `json:"id"`
	Title          string    `json:"title"`
	Type           string    `json:"type"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	URL            string    `json:"url"`
	Endpoint       string    `json:"endpoint"`
	Parameter      string    `json:"parameter"`
	Payload        string    `json:"payload"`
	PayloadUsed    string    `json:"payload_used"`
	Description    string    `json:"description"`
	SeverityReason string    `json:"severity_reason"`
	Impact         string    `json:"impact"`
	CVSS           string    `json:"cvss"`
	CWE            string    `json:"cwe"`
	Remediation    string    `json:"remediation"`
	References     []string  `json:"references"`
	ProofOfConcept string    `json:"proof_of_concept"`
	Timestamp      time.Time `json:"timestamp"`
}

// Statistics represents scan statistics
type Statistics struct {
	TotalPayloads   int            `json:"total_payloads"`
	Processed       int            `json:"processed"`
	Vulnerabilities int            `json:"vulnerabilities"`
	BySeverity      map[string]int `json:"by_severity"`
}

var (
	scanStorageDir  = ".payloadgo/scans"
	scanCounter     = 0
	scanCounterFile = ".payloadgo/scan_counter.txt"
)

// getNextScanID returns the next scan ID
func getNextScanID() string {
	// Try to load current counter
	counter := loadScanCounter()
	counter++
	saveScanCounter(counter)

	return fmt.Sprintf("SCAN-%03d", counter)
}

// loadScanCounter loads the scan counter from file
func loadScanCounter() int {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return 0
	}

	filePath := filepath.Join(homeDir, scanCounterFile)

	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0
	}

	var counter int
	fmt.Sscanf(string(data), "%d", &counter)
	return counter
}

// saveScanCounter saves the scan counter to file
func saveScanCounter(counter int) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(filepath.Join(homeDir, scanCounterFile))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	filePath := filepath.Join(homeDir, scanCounterFile)
	return os.WriteFile(filePath, []byte(fmt.Sprintf("%d", counter)), 0644)
}

// initScanStorage initializes the scan storage directory
func initScanStorage() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	storagePath := filepath.Join(homeDir, scanStorageDir)
	return os.MkdirAll(storagePath, 0755)
}

// getScanFilename generates a filename based on target domain
func getScanFilename(target string) string {
	// Extract domain from target URL
	domain := extractDomain(target)

	// Remove protocol
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Remove trailing slash
	domain = strings.TrimSuffix(domain, "/")

	// Replace dots and slashes with underscores for filesystem
	domain = strings.ReplaceAll(domain, ".", "_")
	domain = strings.ReplaceAll(domain, "/", "_")
	domain = strings.ReplaceAll(domain, "-", "_")

	// Add timestamp for uniqueness
	timestamp := time.Now().Format("20060102_150405")

	// Get unique scan ID
	scanID := getNextScanID()

	return fmt.Sprintf("%s_%s_%s.json", domain, timestamp, scanID)
}

// extractDomain extracts the domain from a URL
func extractDomain(url string) string {
	// Remove protocol
	domain := strings.TrimPrefix(url, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Remove path
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	return domain
}

// SaveScan saves a scan result to disk
func SaveScan(data ScanData) (string, error) {
	// Initialize storage directory
	if err := initScanStorage(); err != nil {
		return "", fmt.Errorf("failed to initialize scan storage: %w", err)
	}

	// Get home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Generate filename
	filename := getScanFilename(data.Target)

	// Create full path
	filePath := filepath.Join(homeDir, scanStorageDir, filename)

	// Convert to JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return "", fmt.Errorf("failed to write scan file: %w", err)
	}

	return filePath, nil
}

// LoadScan loads a scan result from disk
func LoadScan(filename string) (*ScanData, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(homeDir, scanStorageDir, filename)

	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan file: %w", err)
	}

	var scanData ScanData
	if err := json.Unmarshal(jsonData, &scanData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan data: %w", err)
	}

	return &scanData, nil
}

// ListScans returns a list of available scan files
func ListScans() ([]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	scanDir := filepath.Join(homeDir, scanStorageDir)

	files, err := os.ReadDir(scanDir)
	if err != nil {
		return nil, err
	}

	var scans []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			scans = append(scans, file.Name())
		}
	}

	return scans, nil
}

// GetLatestScan returns the most recently created scan file
func GetLatestScan() (*ScanData, error) {
	scans, err := ListScans()
	if err != nil {
		return nil, err
	}

	if len(scans) == 0 {
		return nil, fmt.Errorf("no scans found")
	}

	// Get the last file (most recent based on naming convention)
	latestFile := scans[len(scans)-1]

	return LoadScan(latestFile)
}
