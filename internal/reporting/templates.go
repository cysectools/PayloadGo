package reporting

import (
	"bytes"
	"fmt"
	"html/template"
	"payloadgo/internal/storage"
	"strings"
	"time"
)

// generateExecutiveHTML generates an executive summary HTML report
func (er *EnterpriseReporter) generateExecutiveHTML(summary *ExecutiveSummary) ([]byte, error) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - {{.Scan.Name}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .summary {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            border-left: 5px solid #667eea;
        }
        
        .summary h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat {
            background: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }
        
        .stat:hover {
            transform: translateY(-2px);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 1em;
            color: #6c757d;
            font-weight: 500;
        }
        
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #17a2b8; }
        
        .recommendations {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 15px;
            margin-top: 30px;
        }
        
        .recommendations h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
        }
        
        .recommendation {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
                border-radius: 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Executive Summary</h1>
            <p>Vulnerability Assessment Report - {{.Scan.Name}}</p>
            <p>Generated on {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <h2>📊 Security Assessment Overview</h2>
                <p>This report provides a high-level overview of the security assessment conducted on <strong>{{.Scan.Target}}</strong>. 
                The assessment identified <strong>{{.TotalFindings}}</strong> potential security vulnerabilities across various categories.</p>
                
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number critical">{{.CriticalCount}}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number high">{{.HighCount}}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number medium">{{.MediumCount}}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number low">{{.LowCount}}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number info">{{.InfoCount}}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>
            </div>
            
            <div class="recommendations">
                <h2>🎯 Key Recommendations</h2>
                {{if gt .CriticalCount 0}}
                <div class="recommendation">
                    <h3>🚨 Immediate Action Required</h3>
                    <p><strong>{{.CriticalCount}} critical vulnerabilities</strong> require immediate attention. These issues pose the highest risk to your organization and should be addressed within 24-48 hours.</p>
                </div>
                {{end}}
                
                {{if gt .HighCount 0}}
                <div class="recommendation">
                    <h3>⚠️ High Priority Issues</h3>
                    <p><strong>{{.HighCount}} high-severity vulnerabilities</strong> should be addressed within 1-2 weeks to maintain security posture.</p>
                </div>
                {{end}}
                
                {{if gt .MediumCount 0}}
                <div class="recommendation">
                    <h3>🔧 Medium Priority Issues</h3>
                    <p><strong>{{.MediumCount}} medium-severity vulnerabilities</strong> should be addressed within 1-2 months as part of regular security maintenance.</p>
                </div>
                {{end}}
                
                <div class="recommendation">
                    <h3>📈 Continuous Improvement</h3>
                    <p>Implement a regular security assessment schedule and establish a vulnerability management program to maintain ongoing security posture.</p>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by PayloadGo - Enterprise Vulnerability Testing Platform</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("executive").Parse(tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, summary); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// generateTechnicalHTML generates a technical detailed HTML report
func (er *EnterpriseReporter) generateTechnicalHTML(technical *TechnicalReport) ([]byte, error) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technical Report - {{.Scan.Name}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.2em;
            margin-bottom: 10px;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .finding {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }
        
        .finding:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.2em;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #212529; }
        .severity-low { background: #28a745; color: white; }
        .severity-info { background: #17a2b8; color: white; }
        
        .finding-details {
            margin-bottom: 15px;
        }
        
        .finding-details p {
            margin-bottom: 10px;
        }
        
        .payload {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            margin: 10px 0;
        }
        
        .response {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-break: break-all;
            margin: 10px 0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
        }
        
        .timeline {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
        }
        
        .timeline-event {
            display: flex;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #dee2e6;
        }
        
        .timeline-event:last-child {
            border-bottom: none;
        }
        
        .timeline-time {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #6c757d;
            margin-right: 15px;
            min-width: 120px;
        }
        
        .timeline-content {
            flex: 1;
        }
        
        .timeline-title {
            font-weight: 600;
            color: #2c3e50;
        }
        
        .timeline-meta {
            font-size: 0.9em;
            color: #6c757d;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Technical Security Report</h1>
            <p>{{.Scan.Name}} - {{.Scan.Target}}</p>
            <p>Generated on {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Summary Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{{.TotalFindings}}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{{len .ByType}}</div>
                        <div class="stat-label">Vulnerability Types</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{{len .BySeverity}}</div>
                        <div class="stat-label">Severity Levels</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Detailed Findings</h2>
                {{range .Findings}}
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">{{.Title}}</div>
                        <span class="severity-badge severity-{{.Severity}}">{{.Severity}}</span>
                    </div>
                    
                    <div class="finding-details">
                        <p><strong>Type:</strong> {{.Type}}</p>
                        <p><strong>URL:</strong> {{.URL}}</p>
                        <p><strong>Method:</strong> {{.Method}}</p>
                        <p><strong>Status Code:</strong> {{.StatusCode}}</p>
                        <p><strong>Description:</strong> {{.Description}}</p>
                        
                        {{if .Payload}}
                        <p><strong>Payload:</strong></p>
                        <div class="payload">{{.Payload}}</div>
                        {{end}}
                        
                        {{if .Response}}
                        <p><strong>Response:</strong></p>
                        <div class="response">{{.Response}}</div>
                        {{end}}
                    </div>
                </div>
                {{end}}
            </div>
            
            <div class="section">
                <h2>📈 Timeline</h2>
                <div class="timeline">
                    {{range .Timeline}}
                    <div class="timeline-event">
                        <div class="timeline-time">{{.Time.Format "15:04:05"}}</div>
                        <div class="timeline-content">
                            <div class="timeline-title">{{.Title}}</div>
                            <div class="timeline-meta">{{.Type}} - {{.Severity}} - {{.URL}}</div>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by PayloadGo - Enterprise Vulnerability Testing Platform</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("technical").Parse(tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, technical); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// generateComplianceHTML generates a compliance HTML report
func (er *EnterpriseReporter) generateComplianceHTML(scan *storage.Scan, compliance *ComplianceReport, framework string) ([]byte, error) {
	tmpl := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Report - {{.Framework}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.2em;
            margin-bottom: 10px;
        }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #28a745;
        }
        
        .requirement {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .requirement-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .requirement-id {
            font-size: 1.1em;
            font-weight: 600;
            color: #28a745;
        }
        
        .requirement-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-compliant { background: #28a745; color: white; }
        .status-non-compliant { background: #dc3545; color: white; }
        .status-partial { background: #ffc107; color: #212529; }
        
        .requirement-findings {
            margin-top: 15px;
        }
        
        .finding-item {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .finding-meta {
            font-size: 0.9em;
            color: #6c757d;
        }
        
        .summary {
            background: #e8f5e8;
            border: 1px solid #28a745;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .summary h3 {
            color: #28a745;
            margin-bottom: 15px;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .summary-stat {
            text-align: center;
        }
        
        .summary-number {
            font-size: 1.5em;
            font-weight: 700;
            color: #28a745;
        }
        
        .summary-label {
            font-size: 0.9em;
            color: #6c757d;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Compliance Report</h1>
            <p>{{.Framework}} Framework Assessment</p>
            <p>Generated on {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Compliance Summary</h2>
                <div class="summary">
                    <h3>Assessment Overview</h3>
                    <p>This report assesses compliance with the <strong>{{.Framework}}</strong> framework based on the security findings from the vulnerability assessment.</p>
                    
                    <div class="summary-stats">
                        <div class="summary-stat">
                            <div class="summary-number">{{len .Mappings}}</div>
                            <div class="summary-label">Requirements Assessed</div>
                        </div>
                        <div class="summary-stat">
                            <div class="summary-number">{{len .Findings}}</div>
                            <div class="summary-label">Total Findings</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Requirement Analysis</h2>
                {{range $requirement, $findings := .Mappings}}
                <div class="requirement">
                    <div class="requirement-header">
                        <div class="requirement-id">{{$requirement}}</div>
                        <span class="requirement-status {{if eq (len $findings) 0}}status-compliant{{else}}status-non-compliant{{end}}">
                            {{if eq (len $findings) 0}}Compliant{{else}}Non-Compliant{{end}}
                        </span>
                    </div>
                    
                    {{if gt (len $findings) 0}}
                    <div class="requirement-findings">
                        <p><strong>Findings ({{len $findings}}):</strong></p>
                        {{range $findings}}
                        <div class="finding-item">
                            <div class="finding-title">{{.Title}}</div>
                            <div class="finding-meta">
                                Severity: {{.Severity}} | Type: {{.Type}} | URL: {{.URL}}
                            </div>
                        </div>
                        {{end}}
                    </div>
                    {{else}}
                    <p>No findings related to this requirement.</p>
                    {{end}}
                </div>
                {{end}}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by PayloadGo - Enterprise Vulnerability Testing Platform</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>`

	data := struct {
		Framework   string
		GeneratedAt time.Time
		Mappings    map[string][]*storage.Finding
		Findings    []*storage.Finding
	}{
		Framework:   framework,
		GeneratedAt: time.Now(),
		Mappings:    compliance.Mappings,
		Findings:    compliance.Findings,
	}

	t, err := template.New("compliance").Parse(tmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.Bytes(), nil
}

// generateSARIF generates a SARIF report
func (er *EnterpriseReporter) generateSARIF(scan *storage.Scan, findings []*storage.Finding) map[string]interface{} {
	// Convert findings to SARIF format
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "PayloadGo",
						"version":        "1.0.0",
						"informationUri": "https://github.com/payloadgo/payloadgo",
					},
				},
				"results": er.convertFindingsToSARIF(findings),
			},
		},
	}

	return sarif
}

// convertFindingsToSARIF converts findings to SARIF format
func (er *EnterpriseReporter) convertFindingsToSARIF(findings []*storage.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, finding := range findings {
		result := map[string]interface{}{
			"ruleId": finding.Type,
			"level":  er.mapSeverityToSARIF(finding.Severity),
			"message": map[string]interface{}{
				"text": finding.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": finding.URL,
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"payload":    finding.Payload,
				"method":     finding.Method,
				"statusCode": finding.StatusCode,
				"confidence": finding.Confidence,
			},
		}

		results = append(results, result)
	}

	return results
}

// mapSeverityToSARIF maps severity to SARIF level
func (er *EnterpriseReporter) mapSeverityToSARIF(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "note"
	}
}
