package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

// Repository handles database operations
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new repository
func NewRepository(dsn string) (*Repository, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	repo := &Repository{db: db}

	// Initialize database schema
	if err := repo.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return repo, nil
}

// NewSQLiteRepository creates a new SQLite repository
func NewSQLiteRepository(path string) (*Repository, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}

	repo := &Repository{db: db}

	// Initialize database schema
	if err := repo.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize SQLite schema: %w", err)
	}

	return repo, nil
}

// Close closes the database connection
func (r *Repository) Close() error {
	return r.db.Close()
}

// ScanRepository defines the interface for scan data operations
type ScanRepository interface {
	Create(scan *Scan) error
	GetByID(id string) (*Scan, error)
	GetByOrganization(orgID string, limit, offset int) ([]*Scan, error)
	GetByUser(userID string, limit, offset int) ([]*Scan, error)
	Update(scan *Scan) error
	Delete(id string) error
	GetByStatus(status string, limit, offset int) ([]*Scan, error)
	GetRunningScans() ([]*Scan, error)
}

// FindingRepository defines the interface for finding data operations
type FindingRepository interface {
	Create(finding *Finding) error
	GetByID(id string) (*Finding, error)
	GetByScan(scanID string, limit, offset int) ([]*Finding, error)
	GetByOrganization(orgID string, limit, offset int) ([]*Finding, error)
	GetByType(findingType string, limit, offset int) ([]*Finding, error)
	GetBySeverity(severity string, limit, offset int) ([]*Finding, error)
	GetByStatus(status string, limit, offset int) ([]*Finding, error)
	Update(finding *Finding) error
	Delete(id string) error
	GetStats(orgID string) (*FindingStats, error)
}

// ReportRepository defines the interface for report data operations
type ReportRepository interface {
	Create(report *Report) error
	GetByID(id string) (*Report, error)
	GetByScan(scanID string, limit, offset int) ([]*Report, error)
	GetByOrganization(orgID string, limit, offset int) ([]*Report, error)
	GetByUser(userID string, limit, offset int) ([]*Report, error)
	Update(report *Report) error
	Delete(id string) error
}

// JobRepository defines the interface for job data operations
type JobRepository interface {
	Create(job *Job) error
	GetByID(id string) (*Job, error)
	GetByStatus(status string, limit, offset int) ([]*Job, error)
	GetByType(jobType string, limit, offset int) ([]*Job, error)
	GetPendingJobs(limit int) ([]*Job, error)
	Update(job *Job) error
	Delete(id string) error
	CleanupCompleted(days int) error
}

// FindingStats represents statistics about findings
type FindingStats struct {
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"by_severity"`
	ByType         map[string]int `json:"by_type"`
	ByStatus       map[string]int `json:"by_status"`
	ByOrganization map[string]int `json:"by_organization"`
	Recent         []*Finding     `json:"recent"`
}

// Implementations

// CreateScan creates a new scan
func (r *Repository) CreateScan(scan *Scan) error {
	query := `
		INSERT INTO scans (id, organization_id, user_id, name, description, target, status, config, progress, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	configJSON, _ := json.Marshal(scan.Config)

	_, err := r.db.Exec(query,
		scan.ID, scan.OrganizationID, scan.UserID, scan.Name, scan.Description,
		scan.Target, scan.Status, configJSON, scan.Progress,
		scan.CreatedAt, scan.UpdatedAt)

	return err
}

// GetScanByID retrieves a scan by ID
func (r *Repository) GetScanByID(id string) (*Scan, error) {
	query := `
		SELECT id, organization_id, user_id, name, description, target, status, config, progress,
		       started_at, completed_at, created_at, updated_at
		FROM scans WHERE id = $1
	`

	row := r.db.QueryRow(query, id)
	scan := &Scan{}
	var configJSON []byte
	var startedAt, completedAt sql.NullTime

	err := row.Scan(
		&scan.ID, &scan.OrganizationID, &scan.UserID, &scan.Name, &scan.Description,
		&scan.Target, &scan.Status, &configJSON, &scan.Progress,
		&startedAt, &completedAt, &scan.CreatedAt, &scan.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if startedAt.Valid {
		scan.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	json.Unmarshal(configJSON, &scan.Config)

	return scan, nil
}

// UpdateScan updates a scan
func (r *Repository) UpdateScan(scan *Scan) error {
	query := `
		UPDATE scans SET name = $2, description = $3, target = $4, status = $5, config = $6,
		                progress = $7, started_at = $8, completed_at = $9, updated_at = $10
		WHERE id = $1
	`

	configJSON, _ := json.Marshal(scan.Config)

	_, err := r.db.Exec(query,
		scan.ID, scan.Name, scan.Description, scan.Target, scan.Status,
		configJSON, scan.Progress, scan.StartedAt, scan.CompletedAt, scan.UpdatedAt)

	return err
}

// CreateFinding creates a new finding
func (r *Repository) CreateFinding(finding *Finding) error {
	query := `
		INSERT INTO findings (id, scan_id, organization_id, type, severity, confidence, title, description,
		                     payload, url, method, status_code, response, evidence, status, assigned_to, tags, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	evidenceJSON, _ := json.Marshal(finding.Evidence)
	tagsJSON, _ := json.Marshal(finding.Tags)

	_, err := r.db.Exec(query,
		finding.ID, finding.ScanID, finding.OrganizationID, finding.Type, finding.Severity,
		finding.Confidence, finding.Title, finding.Description, finding.Payload,
		finding.URL, finding.Method, finding.StatusCode, finding.Response,
		evidenceJSON, finding.Status, finding.AssignedTo, tagsJSON,
		finding.CreatedAt, finding.UpdatedAt)

	return err
}

// GetFindingByID retrieves a finding by ID
func (r *Repository) GetFindingByID(id string) (*Finding, error) {
	query := `
		SELECT id, scan_id, organization_id, type, severity, confidence, title, description,
		       payload, url, method, status_code, response, evidence, status, assigned_to, tags, created_at, updated_at
		FROM findings WHERE id = $1
	`

	row := r.db.QueryRow(query, id)
	finding := &Finding{}
	var evidenceJSON, tagsJSON []byte

	err := row.Scan(
		&finding.ID, &finding.ScanID, &finding.OrganizationID, &finding.Type, &finding.Severity,
		&finding.Confidence, &finding.Title, &finding.Description, &finding.Payload,
		&finding.URL, &finding.Method, &finding.StatusCode, &finding.Response,
		&evidenceJSON, &finding.Status, &finding.AssignedTo, &tagsJSON,
		&finding.CreatedAt, &finding.UpdatedAt)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(evidenceJSON, &finding.Evidence)
	json.Unmarshal(tagsJSON, &finding.Tags)

	return finding, nil
}

// GetFindingsByScan retrieves findings for a scan
func (r *Repository) GetFindingsByScan(scanID string, limit, offset int) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, organization_id, type, severity, confidence, title, description,
		       payload, url, method, status_code, response, evidence, status, assigned_to, tags, created_at, updated_at
		FROM findings WHERE scan_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Query(query, scanID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		finding := &Finding{}
		var evidenceJSON, tagsJSON []byte

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.OrganizationID, &finding.Type, &finding.Severity,
			&finding.Confidence, &finding.Title, &finding.Description, &finding.Payload,
			&finding.URL, &finding.Method, &finding.StatusCode, &finding.Response,
			&evidenceJSON, &finding.Status, &finding.AssignedTo, &tagsJSON,
			&finding.CreatedAt, &finding.UpdatedAt)

		if err != nil {
			return nil, err
		}

		json.Unmarshal(evidenceJSON, &finding.Evidence)
		json.Unmarshal(tagsJSON, &finding.Tags)

		findings = append(findings, finding)
	}

	return findings, nil
}

// UpdateFinding updates a finding
func (r *Repository) UpdateFinding(finding *Finding) error {
	query := `
		UPDATE findings SET type = $2, severity = $3, confidence = $4, title = $5, description = $6,
		                   payload = $7, url = $8, method = $9, status_code = $10, response = $11,
		                   evidence = $12, status = $13, assigned_to = $14, tags = $15, updated_at = $16
		WHERE id = $1
	`

	evidenceJSON, _ := json.Marshal(finding.Evidence)
	tagsJSON, _ := json.Marshal(finding.Tags)

	_, err := r.db.Exec(query,
		finding.ID, finding.Type, finding.Severity, finding.Confidence, finding.Title,
		finding.Description, finding.Payload, finding.URL, finding.Method, finding.StatusCode,
		finding.Response, evidenceJSON, finding.Status, finding.AssignedTo, tagsJSON, finding.UpdatedAt)

	return err
}

// GetFindingStats retrieves finding statistics
func (r *Repository) GetFindingStats(orgID string) (*FindingStats, error) {
	stats := &FindingStats{
		BySeverity:     make(map[string]int),
		ByType:         make(map[string]int),
		ByStatus:       make(map[string]int),
		ByOrganization: make(map[string]int),
	}

	// Total count
	err := r.db.QueryRow("SELECT COUNT(*) FROM findings WHERE organization_id = $1", orgID).Scan(&stats.Total)
	if err != nil {
		return nil, err
	}

	// By severity
	rows, err := r.db.Query("SELECT severity, COUNT(*) FROM findings WHERE organization_id = $1 GROUP BY severity", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		rows.Scan(&severity, &count)
		stats.BySeverity[severity] = count
	}

	// By type
	rows, err = r.db.Query("SELECT type, COUNT(*) FROM findings WHERE organization_id = $1 GROUP BY type", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var findingType string
		var count int
		rows.Scan(&findingType, &count)
		stats.ByType[findingType] = count
	}

	// By status
	rows, err = r.db.Query("SELECT status, COUNT(*) FROM findings WHERE organization_id = $1 GROUP BY status", orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		rows.Scan(&status, &count)
		stats.ByStatus[status] = count
	}

	// Recent findings
	rows, err = r.db.Query(`
		SELECT id, scan_id, organization_id, type, severity, confidence, title, description,
		       payload, url, method, status_code, response, evidence, status, assigned_to, tags, created_at, updated_at
		FROM findings WHERE organization_id = $1
		ORDER BY created_at DESC LIMIT 10
	`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		finding := &Finding{}
		var evidenceJSON, tagsJSON []byte

		err := rows.Scan(
			&finding.ID, &finding.ScanID, &finding.OrganizationID, &finding.Type, &finding.Severity,
			&finding.Confidence, &finding.Title, &finding.Description, &finding.Payload,
			&finding.URL, &finding.Method, &finding.StatusCode, &finding.Response,
			&evidenceJSON, &finding.Status, &finding.AssignedTo, &tagsJSON,
			&finding.CreatedAt, &finding.UpdatedAt)

		if err != nil {
			return nil, err
		}

		json.Unmarshal(evidenceJSON, &finding.Evidence)
		json.Unmarshal(tagsJSON, &finding.Tags)

		stats.Recent = append(stats.Recent, finding)
	}

	return stats, nil
}

// initSchema initializes the database schema
func (r *Repository) initSchema() error {
	schema := `
		-- Scans table
		CREATE TABLE IF NOT EXISTS scans (
			id VARCHAR(36) PRIMARY KEY,
			organization_id VARCHAR(36) NOT NULL,
			user_id VARCHAR(36) NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			target VARCHAR(500) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			config JSONB,
			progress INTEGER DEFAULT 0,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);

		-- Findings table
		CREATE TABLE IF NOT EXISTS findings (
			id VARCHAR(36) PRIMARY KEY,
			scan_id VARCHAR(36) NOT NULL,
			organization_id VARCHAR(36) NOT NULL,
			type VARCHAR(100) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			confidence DECIMAL(3,2) DEFAULT 0.0,
			title VARCHAR(500) NOT NULL,
			description TEXT,
			payload TEXT,
			url VARCHAR(1000),
			method VARCHAR(10),
			status_code INTEGER,
			response TEXT,
			evidence JSONB,
			status VARCHAR(50) DEFAULT 'new',
			assigned_to VARCHAR(36),
			tags JSONB,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);

		-- Reports table
		CREATE TABLE IF NOT EXISTS reports (
			id VARCHAR(36) PRIMARY KEY,
			scan_id VARCHAR(36) NOT NULL,
			organization_id VARCHAR(36) NOT NULL,
			user_id VARCHAR(36) NOT NULL,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(50) NOT NULL,
			format VARCHAR(20) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'generating',
			config JSONB,
			file_path VARCHAR(500),
			file_size BIGINT,
			file_hash VARCHAR(64),
			generated_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		);

		-- Jobs table
		CREATE TABLE IF NOT EXISTS jobs (
			id VARCHAR(36) PRIMARY KEY,
			type VARCHAR(50) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			priority INTEGER DEFAULT 0,
			data JSONB,
			result JSONB,
			error TEXT,
			attempts INTEGER DEFAULT 0,
			max_attempts INTEGER DEFAULT 3,
			scheduled_at TIMESTAMP NOT NULL,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);

		-- Create indexes
		CREATE INDEX IF NOT EXISTS idx_scans_organization_id ON scans(organization_id);
		CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
		CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
		CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

		CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
		CREATE INDEX IF NOT EXISTS idx_findings_organization_id ON findings(organization_id);
		CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
		CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
		CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
		CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);

		CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
		CREATE INDEX IF NOT EXISTS idx_reports_organization_id ON reports(organization_id);
		CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id);
		CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

		CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
		CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(type);
		CREATE INDEX IF NOT EXISTS idx_jobs_scheduled_at ON jobs(scheduled_at);
		CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority);
	`

	_, err := r.db.Exec(schema)
	return err
}
