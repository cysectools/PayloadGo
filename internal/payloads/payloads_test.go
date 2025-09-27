package payloads

import (
	"os"
	"testing"
)

func TestGetCategory(t *testing.T) {
	tests := []struct {
		name     string
		category string
		expected int
	}{
		{"XSS category", "xss", 19},
		{"SQLi category", "sqli", 25},
		{"XXE category", "xxe", 8},
		{"Path traversal category", "path_traversal", 11},
		{"Command injection category", "command_injection", 25},
		{"LDAP category", "ldap", 15},
		{"NoSQL category", "nosql", 15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetCategory(tt.category)
			if len(payloads) != tt.expected {
				t.Errorf("Expected %d payloads for %s, got %d", tt.expected, tt.category, len(payloads))
			}
		})
	}
}

func TestGetAllPayloads(t *testing.T) {
	payloads := GetAllPayloads()
	if len(payloads) == 0 {
		t.Error("Expected payloads to be returned")
	}
}

func TestGetCategories(t *testing.T) {
	categories := GetCategories()
	expectedCategories := []string{"xss", "sqli", "xxe", "path_traversal", "command_injection", "ldap", "nosql"}

	if len(categories) != len(expectedCategories) {
		t.Errorf("Expected %d categories, got %d", len(expectedCategories), len(categories))
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary file
	tmpfile, err := os.CreateTemp("", "test_payloads.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write test payloads
	testPayloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"../etc/passwd",
		"# This is a comment",
		"", // Empty line
		"<img src=x onerror=alert(1)>",
	}

	for _, payload := range testPayloads {
		tmpfile.WriteString(payload + "\n")
	}
	tmpfile.Close()

	// Load payloads
	payloads, err := LoadFromFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load payloads: %v", err)
	}

	// Should have 4 payloads (excluding comment and empty line)
	expectedCount := 4
	if len(payloads) != expectedCount {
		t.Errorf("Expected %d payloads, got %d", expectedCount, len(payloads))
	}

	// Check specific payloads
	expectedPayloads := []string{
		"<script>alert(1)</script>",
		"' OR '1'='1",
		"../etc/passwd",
		"<img src=x onerror=alert(1)>",
	}

	for i, expected := range expectedPayloads {
		if payloads[i] != expected {
			t.Errorf("Expected payload %d to be %s, got %s", i, expected, payloads[i])
		}
	}
}

func TestLoadFromFile_NonExistent(t *testing.T) {
	_, err := LoadFromFile("nonexistent.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}
