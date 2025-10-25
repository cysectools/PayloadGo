package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"payloadgo/internal/storage"
)

// EnterpriseReporter provides enterprise-grade reporting capabilities
type EnterpriseReporter struct {
	templateRepo TemplateRepository
	storageRepo  StorageRepository
	config       *ReportConfig
}

// TemplateRepository defines the interface for template operations
type TemplateRepository interface {
	GetTemplate(name string) (*Template, error)
	SaveTemplate(template *Template) error
	ListTemplates() ([]*Template, error)
}

// StorageRepository defines the interface for storage operations
type StorageRepository interface {
	SaveReport(report *Report) error
	GetReport(id string) (*Report, error)
	DeleteReport(id string) error
}

// Template represents a report template
type Template struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`   // executive, technical, compliance
	Format    string            `json:"format"` // html, pdf, json, csv
	Content   string            `json:"content"`
	Variables map[string]string `json:"variables"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Report represents a generated report
type Report struct {
	ID             string                 `json:"id"`
	ScanID         string                 `json:"scan_id"`
	OrganizationID string                 `json:"organization_id"`
	UserID         string                 `json:"user_id"`
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Format         string                 `json:"format"`
	Status         string                 `json:"status"`
	Config         map[string]interface{} `json:"config"`
	FilePath       string                 `json:"file_path"`
	FileSize       int64                  `json:"file_size"`
	FileHash       string                 `json:"file_hash"`
	GeneratedAt    *time.Time             `json:"generated_at"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// ReportConfig represents report configuration
type ReportConfig struct {
	TemplatesPath  string
	OutputPath     string
	MaxFileSize    int64
	AllowedFormats []string
}

// NewEnterpriseReporter creates a new enterprise reporter
func NewEnterpriseReporter(templateRepo TemplateRepository, storageRepo StorageRepository, config *ReportConfig) *EnterpriseReporter {
	return &EnterpriseReporter{
		templateRepo: templateRepo,
		storageRepo:  storageRepo,
		config:       config,
	}
}

// GenerateReport generates a comprehensive report
func (er *EnterpriseReporter) GenerateReport(ctx context.Context, req *GenerateReportRequest) (*Report, error) {
	// Validate request
	if err := er.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Get template
	template, err := er.templateRepo.GetTemplate(req.TemplateName)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Create report record
	report := &Report{
		ID:             generateReportID(),
		ScanID:         req.ScanID,
		OrganizationID: req.OrganizationID,
		UserID:         req.UserID,
		Name:           req.Name,
		Type:           template.Type,
		Format:         template.Format,
		Status:         "generating",
		Config:         req.Config,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Save report record
	if err := er.storageRepo.SaveReport(report); err != nil {
		return nil, fmt.Errorf("failed to save report: %w", err)
	}

	// Generate report content
	content, err := er.generateContent(ctx, template, req)
	if err != nil {
		report.Status = "failed"
		er.storageRepo.SaveReport(report)
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	// Save report file
	filePath, fileSize, fileHash, err := er.saveReportFile(report, content)
	if err != nil {
		report.Status = "failed"
		er.storageRepo.SaveReport(report)
		return nil, fmt.Errorf("failed to save report file: %w", err)
	}

	// Update report with file information
	report.FilePath = filePath
	report.FileSize = fileSize
	report.FileHash = fileHash
	report.Status = "completed"
	now := time.Now()
	report.GeneratedAt = &now
	report.UpdatedAt = now

	// Save updated report
	if err := er.storageRepo.SaveReport(report); err != nil {
		return nil, fmt.Errorf("failed to update report: %w", err)
	}

	return report, nil
}

// GenerateExecutiveReport generates an executive summary report
func (er *EnterpriseReporter) GenerateExecutiveReport(ctx context.Context, scan *storage.Scan, findings []*storage.Finding) (*Report, error) {
	// Prepare executive summary data
	summary := &ExecutiveSummary{
		Scan:          scan,
		Findings:      findings,
		TotalFindings: len(findings),
		CriticalCount: er.countBySeverity(findings, "critical"),
		HighCount:     er.countBySeverity(findings, "high"),
		MediumCount:   er.countBySeverity(findings, "medium"),
		LowCount:      er.countBySeverity(findings, "low"),
		InfoCount:     er.countBySeverity(findings, "info"),
		GeneratedAt:   time.Now(),
	}

	// Generate HTML content
	content, err := er.generateExecutiveHTML(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to generate executive HTML: %w", err)
	}

	// Create report
	report := &Report{
		ID:             generateReportID(),
		ScanID:         scan.ID,
		OrganizationID: scan.OrganizationID,
		UserID:         scan.UserID,
		Name:           fmt.Sprintf("Executive Report - %s", scan.Name),
		Type:           "executive",
		Format:         "html",
		Status:         "completed",
		GeneratedAt:    &time.Time{},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Save report file
	filePath, fileSize, fileHash, err := er.saveReportFile(report, content)
	if err != nil {
		return nil, fmt.Errorf("failed to save report file: %w", err)
	}

	report.FilePath = filePath
	report.FileSize = fileSize
	report.FileHash = fileHash
	now := time.Now()
	report.GeneratedAt = &now

	return report, nil
}

// GenerateTechnicalReport generates a technical detailed report
func (er *EnterpriseReporter) GenerateTechnicalReport(ctx context.Context, scan *storage.Scan, findings []*storage.Finding) (*Report, error) {
	// Prepare technical report data
	technical := &TechnicalReport{
		Scan:          scan,
		Findings:      findings,
		TotalFindings: len(findings),
		ByType:        er.groupByType(findings),
		BySeverity:    er.groupBySeverity(findings),
		ByStatus:      er.groupByStatus(findings),
		Timeline:      er.generateTimeline(findings),
		GeneratedAt:   time.Now(),
	}

	// Generate HTML content
	content, err := er.generateTechnicalHTML(technical)
	if err != nil {
		return nil, fmt.Errorf("failed to generate technical HTML: %w", err)
	}

	// Create report
	report := &Report{
		ID:             generateReportID(),
		ScanID:         scan.ID,
		OrganizationID: scan.OrganizationID,
		UserID:         scan.UserID,
		Name:           fmt.Sprintf("Technical Report - %s", scan.Name),
		Type:           "technical",
		Format:         "html",
		Status:         "completed",
		GeneratedAt:    &time.Time{},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Save report file
	filePath, fileSize, fileHash, err := er.saveReportFile(report, content)
	if err != nil {
		return nil, fmt.Errorf("failed to save report file: %w", err)
	}

	report.FilePath = filePath
	report.FileSize = fileSize
	report.FileHash = fileHash
	now := time.Now()
	report.GeneratedAt = &now

	return report, nil
}

// GenerateComplianceReport generates a compliance report
func (er *EnterpriseReporter) GenerateComplianceReport(ctx context.Context, scan *storage.Scan, findings []*storage.Finding, framework string) (*Report, error) {
	// Map findings to compliance framework
	compliance := er.mapToCompliance(framework, findings)

	// Generate compliance report
	content, err := er.generateComplianceHTML(scan, compliance, framework)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance HTML: %w", err)
	}

	// Create report
	report := &Report{
		ID:             generateReportID(),
		ScanID:         scan.ID,
		OrganizationID: scan.OrganizationID,
		UserID:         scan.UserID,
		Name:           fmt.Sprintf("Compliance Report - %s", framework),
		Type:           "compliance",
		Format:         "html",
		Status:         "completed",
		GeneratedAt:    &time.Time{},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Save report file
	filePath, fileSize, fileHash, err := er.saveReportFile(report, content)
	if err != nil {
		return nil, fmt.Errorf("failed to save report file: %w", err)
	}

	report.FilePath = filePath
	report.FileSize = fileSize
	report.FileHash = fileHash
	now := time.Now()
	report.GeneratedAt = &now

	return report, nil
}

// GenerateSARIFReport generates a SARIF (Static Analysis Results Interchange Format) report
func (er *EnterpriseReporter) GenerateSARIFReport(ctx context.Context, scan *storage.Scan, findings []*storage.Finding) (*Report, error) {
	// Generate SARIF content
	sarif := er.generateSARIF(scan, findings)
	content, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	// Create report
	report := &Report{
		ID:             generateReportID(),
		ScanID:         scan.ID,
		OrganizationID: scan.OrganizationID,
		UserID:         scan.UserID,
		Name:           fmt.Sprintf("SARIF Report - %s", scan.Name),
		Type:           "sarif",
		Format:         "json",
		Status:         "completed",
		GeneratedAt:    &time.Time{},
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Save report file
	filePath, fileSize, fileHash, err := er.saveReportFile(report, content)
	if err != nil {
		return nil, fmt.Errorf("failed to save report file: %w", err)
	}

	report.FilePath = filePath
	report.FileSize = fileSize
	report.FileHash = fileHash
	now := time.Now()
	report.GeneratedAt = &now

	return report, nil
}

// GeneratePoC generates proof-of-concept artifacts
func (er *EnterpriseReporter) GeneratePoC(ctx context.Context, finding *storage.Finding) (*PoC, error) {
	poc := &PoC{
		ID:          generatePoCID(),
		FindingID:   finding.ID,
		Type:        finding.Type,
		Severity:    finding.Severity,
		Title:       finding.Title,
		Description: finding.Description,
		Payload:     finding.Payload,
		URL:         finding.URL,
		Method:      finding.Method,
		StatusCode:  finding.StatusCode,
		Response:    finding.Response,
		Evidence:    finding.Evidence,
		CreatedAt:   time.Now(),
	}

	// Generate curl command
	poc.CurlCommand = er.generateCurlCommand(finding)

	// Generate Burp Suite request
	poc.BurpRequest = er.generateBurpRequest(finding)

	// Generate Python script
	poc.PythonScript = er.generatePythonScript(finding)

	// Generate JavaScript snippet
	poc.JavaScriptSnippet = er.generateJavaScriptSnippet(finding)

	return poc, nil
}

// Helper methods

func (er *EnterpriseReporter) validateRequest(req *GenerateReportRequest) error {
	if req.ScanID == "" {
		return fmt.Errorf("scan ID is required")
	}
	if req.OrganizationID == "" {
		return fmt.Errorf("organization ID is required")
	}
	if req.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	if req.TemplateName == "" {
		return fmt.Errorf("template name is required")
	}
	return nil
}

func (er *EnterpriseReporter) generateContent(ctx context.Context, tmpl *Template, req *GenerateReportRequest) ([]byte, error) {
	// Parse template
	t, err := template.New("report").Parse(tmpl.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Prepare data
	data := map[string]interface{}{
		"ScanID":         req.ScanID,
		"OrganizationID": req.OrganizationID,
		"UserID":         req.UserID,
		"Config":         req.Config,
		"GeneratedAt":    time.Now(),
	}

	// Execute template
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

func (er *EnterpriseReporter) saveReportFile(report *Report, content []byte) (string, int64, string, error) {
	// Generate file path
	fileName := fmt.Sprintf("%s_%s.%s", report.ID, report.Type, report.Format)
	filePath := filepath.Join(er.config.OutputPath, fileName)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return "", 0, "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return "", 0, "", fmt.Errorf("failed to write file: %w", err)
	}

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to get file info: %w", err)
	}

	// Calculate hash
	hash := er.calculateHash(content)

	return filePath, info.Size(), hash, nil
}

func (er *EnterpriseReporter) calculateHash(content []byte) string {
	// Simple hash calculation - in production, use proper hashing
	return fmt.Sprintf("%x", content)
}

func (er *EnterpriseReporter) countBySeverity(findings []*storage.Finding, severity string) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

func (er *EnterpriseReporter) groupByType(findings []*storage.Finding) map[string][]*storage.Finding {
	groups := make(map[string][]*storage.Finding)
	for _, finding := range findings {
		groups[finding.Type] = append(groups[finding.Type], finding)
	}
	return groups
}

func (er *EnterpriseReporter) groupBySeverity(findings []*storage.Finding) map[string][]*storage.Finding {
	groups := make(map[string][]*storage.Finding)
	for _, finding := range findings {
		groups[finding.Severity] = append(groups[finding.Severity], finding)
	}
	return groups
}

func (er *EnterpriseReporter) groupByStatus(findings []*storage.Finding) map[string][]*storage.Finding {
	groups := make(map[string][]*storage.Finding)
	for _, finding := range findings {
		groups[finding.Status] = append(groups[finding.Status], finding)
	}
	return groups
}

func (er *EnterpriseReporter) generateTimeline(findings []*storage.Finding) []*TimelineEvent {
	events := make([]*TimelineEvent, 0, len(findings))
	for _, finding := range findings {
		events = append(events, &TimelineEvent{
			Time:     finding.CreatedAt,
			Type:     finding.Type,
			Severity: finding.Severity,
			Title:    finding.Title,
			URL:      finding.URL,
		})
	}
	return events
}

func (er *EnterpriseReporter) mapToCompliance(framework string, findings []*storage.Finding) *ComplianceReport {
	// Map findings to compliance framework requirements
	// This is a simplified implementation
	compliance := &ComplianceReport{
		Framework: framework,
		Findings:  findings,
		Mappings:  make(map[string][]*storage.Finding),
	}

	// Map to common compliance frameworks
	switch framework {
	case "OWASP":
		compliance.Mappings["A01"] = er.filterByType(findings, "broken_access_control")
		compliance.Mappings["A02"] = er.filterByType(findings, "broken_authentication")
		compliance.Mappings["A03"] = er.filterByType(findings, "sensitive_data_exposure")
		// Add more mappings...
	case "PCI-DSS":
		// Map to PCI-DSS requirements
		compliance.Mappings["6.5.1"] = er.filterByType(findings, "injection")
		compliance.Mappings["6.5.2"] = er.filterByType(findings, "xss")
		// Add more mappings...
	}

	return compliance
}

func (er *EnterpriseReporter) filterByType(findings []*storage.Finding, findingType string) []*storage.Finding {
	var filtered []*storage.Finding
	for _, finding := range findings {
		if finding.Type == findingType {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func (er *EnterpriseReporter) generateCurlCommand(finding *storage.Finding) string {
	return fmt.Sprintf("curl -X %s '%s' -H 'Content-Type: application/json' -d '%s'",
		finding.Method, finding.URL, finding.Payload)
}

func (er *EnterpriseReporter) generateBurpRequest(finding *storage.Finding) string {
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\nContent-Type: application/json\n\n%s",
		finding.Method, finding.URL, "target.com", finding.Payload)
}

func (er *EnterpriseReporter) generatePythonScript(finding *storage.Finding) string {
	return fmt.Sprintf(`import requests

url = "%s"
payload = "%s"

response = requests.%s(url, data=payload)
print(response.text)`, finding.URL, finding.Payload, strings.ToLower(finding.Method))
}

func (er *EnterpriseReporter) generateJavaScriptSnippet(finding *storage.Finding) string {
	return fmt.Sprintf(`fetch('%s', {
    method: '%s',
    body: '%s'
}).then(response => response.text())
.then(data => console.log(data));`, finding.URL, finding.Method, finding.Payload)
}

// Data structures

type GenerateReportRequest struct {
	ScanID         string                 `json:"scan_id"`
	OrganizationID string                 `json:"organization_id"`
	UserID         string                 `json:"user_id"`
	TemplateName   string                 `json:"template_name"`
	Name           string                 `json:"name"`
	Config         map[string]interface{} `json:"config"`
}

type ExecutiveSummary struct {
	Scan          *storage.Scan      `json:"scan"`
	Findings      []*storage.Finding `json:"findings"`
	TotalFindings int                `json:"total_findings"`
	CriticalCount int                `json:"critical_count"`
	HighCount     int                `json:"high_count"`
	MediumCount   int                `json:"medium_count"`
	LowCount      int                `json:"low_count"`
	InfoCount     int                `json:"info_count"`
	GeneratedAt   time.Time          `json:"generated_at"`
}

type TechnicalReport struct {
	Scan          *storage.Scan                 `json:"scan"`
	Findings      []*storage.Finding            `json:"findings"`
	TotalFindings int                           `json:"total_findings"`
	ByType        map[string][]*storage.Finding `json:"by_type"`
	BySeverity    map[string][]*storage.Finding `json:"by_severity"`
	ByStatus      map[string][]*storage.Finding `json:"by_status"`
	Timeline      []*TimelineEvent              `json:"timeline"`
	GeneratedAt   time.Time                     `json:"generated_at"`
}

type ComplianceReport struct {
	Framework string                        `json:"framework"`
	Findings  []*storage.Finding            `json:"findings"`
	Mappings  map[string][]*storage.Finding `json:"mappings"`
}

type TimelineEvent struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	URL      string    `json:"url"`
}

type PoC struct {
	ID                string                 `json:"id"`
	FindingID         string                 `json:"finding_id"`
	Type              string                 `json:"type"`
	Severity          string                 `json:"severity"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Payload           string                 `json:"payload"`
	URL               string                 `json:"url"`
	Method            string                 `json:"method"`
	StatusCode        int                    `json:"status_code"`
	Response          string                 `json:"response"`
	Evidence          map[string]interface{} `json:"evidence"`
	CurlCommand       string                 `json:"curl_command"`
	BurpRequest       string                 `json:"burp_request"`
	PythonScript      string                 `json:"python_script"`
	JavaScriptSnippet string                 `json:"javascript_snippet"`
	CreatedAt         time.Time              `json:"created_at"`
}

// Helper functions

func generateReportID() string {
	return fmt.Sprintf("rpt_%d", time.Now().UnixNano())
}

func generatePoCID() string {
	return fmt.Sprintf("poc_%d", time.Now().UnixNano())
}
