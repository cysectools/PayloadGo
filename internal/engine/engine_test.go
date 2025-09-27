package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEngine_TestURL(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if query == "<script>alert(1)</script>" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Search results for: " + query + "</body></html>"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>No results</body></html>"))
		}
	}))
	defer server.Close()

	// Create engine
	eng, err := NewEngine(1, 5*time.Second, "PayloadGo/1.0", "")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test XSS payload
	targetURL := server.URL + "/search?q=TEST"
	payload := "<script>alert(1)</script>"

	result := eng.TestURL(targetURL, payload)

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected")
	}

	if result.VulnType != "XSS" {
		t.Errorf("Expected XSS vulnerability type, got: %s", result.VulnType)
	}
}

func TestEngine_TestForm(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == "' OR '1'='1" && password == "' OR '1'='1" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html><body>Welcome admin!</body></html>"))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("<html><body>Invalid credentials</body></html>"))
			}
		}
	}))
	defer server.Close()

	// Create engine
	eng, err := NewEngine(1, 5*time.Second, "PayloadGo/1.0", "")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test SQL injection payload
	payload := "' OR '1'='1"

	result := eng.TestForm(server.URL+"/login", payload, "username", "password")

	if result.Error != nil {
		t.Errorf("Unexpected error: %v", result.Error)
	}

	if result.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", result.StatusCode)
	}
}

func TestEngine_RunConcurrent(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if query == "test" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Found: " + query + "</body></html>"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>No results</body></html>"))
		}
	}))
	defer server.Close()

	// Create engine
	eng, err := NewEngine(2, 5*time.Second, "PayloadGo/1.0", "")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test concurrent execution
	payloads := []string{"test", "payload1", "payload2", "payload3"}
	targetURL := server.URL + "/search?q=TEST"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results := eng.RunConcurrent(ctx, targetURL, payloads, "url", "", "")

	var resultCount int
	for result := range results {
		resultCount++
		if result.Error != nil {
			t.Errorf("Unexpected error: %v", result.Error)
		}
	}

	if resultCount != len(payloads) {
		t.Errorf("Expected %d results, got %d", len(payloads), resultCount)
	}
}

func TestEngine_Stats(t *testing.T) {
	eng, err := NewEngine(1, 5*time.Second, "PayloadGo/1.0", "")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	stats := eng.GetStats()
	if stats.Total != 0 {
		t.Errorf("Expected initial total to be 0, got: %d", stats.Total)
	}
}
