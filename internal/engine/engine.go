package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type TestResult struct {
	Payload      string
	URL          string
	StatusCode   int
	Response     string
	Vulnerable   bool
	VulnType     string
	ResponseTime time.Duration
	Error        error
}

type Engine struct {
	client    *http.Client
	threads   int
	timeout   time.Duration
	userAgent string
	proxy     *url.URL
	results   chan TestResult
	mu        sync.RWMutex
	stats     *Stats
}

type Stats struct {
	Total      int
	Tested     int
	Vulnerable int
	Errors     int
	StartTime  time.Time
}

func NewEngine(threads int, timeout time.Duration, userAgent, proxyURL string) (*Engine, error) {
	client := &http.Client{
		Timeout: timeout,
	}

	var proxy *url.URL
	if proxyURL != "" {
		var err error
		proxy, err = url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxy)}
	}

	return &Engine{
		client:    client,
		threads:   threads,
		timeout:   timeout,
		userAgent: userAgent,
		proxy:     proxy,
		results:   make(chan TestResult, 1000),
		stats:     &Stats{StartTime: time.Now()},
	}, nil
}

func (e *Engine) TestURL(targetURL, payload string) TestResult {
	start := time.Now()

	// Replace TEST placeholder with payload
	testURL := strings.Replace(targetURL, "TEST", url.QueryEscape(payload), 1)

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return TestResult{
			Payload: payload,
			URL:     testURL,
			Error:   err,
		}
	}

	req.Header.Set("User-Agent", e.userAgent)

	resp, err := e.client.Do(req)
	if err != nil {
		return TestResult{
			Payload: payload,
			URL:     testURL,
			Error:   err,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Payload:      payload,
			URL:          testURL,
			StatusCode:   resp.StatusCode,
			ResponseTime: time.Since(start),
			Error:        err,
		}
	}

	response := string(body)
	vulnerable, vulnType := e.analyzeResponse(payload, response, resp.StatusCode)

	return TestResult{
		Payload:      payload,
		URL:          testURL,
		StatusCode:   resp.StatusCode,
		Response:     response,
		Vulnerable:   vulnerable,
		VulnType:     vulnType,
		ResponseTime: time.Since(start),
	}
}

func (e *Engine) TestForm(targetURL, payload, userField, passField string) TestResult {
	start := time.Now()

	form := url.Values{}
	form.Set(userField, payload)
	form.Set(passField, payload)

	req, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TestResult{
			Payload: payload,
			URL:     targetURL,
			Error:   err,
		}
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", e.userAgent)

	resp, err := e.client.Do(req)
	if err != nil {
		return TestResult{
			Payload: payload,
			URL:     targetURL,
			Error:   err,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TestResult{
			Payload:      payload,
			URL:          targetURL,
			StatusCode:   resp.StatusCode,
			ResponseTime: time.Since(start),
			Error:        err,
		}
	}

	response := string(body)
	vulnerable, vulnType := e.analyzeResponse(payload, response, resp.StatusCode)

	return TestResult{
		Payload:      payload,
		URL:          targetURL,
		StatusCode:   resp.StatusCode,
		Response:     response,
		Vulnerable:   vulnerable,
		VulnType:     vulnType,
		ResponseTime: time.Since(start),
	}
}

func (e *Engine) analyzeResponse(payload, response string, statusCode int) (bool, string) {
	responseLower := strings.ToLower(response)

	// XSS Detection
	if strings.Contains(response, payload) {
		return true, "XSS"
	}

	// SQL Injection Detection
	sqlKeywords := []string{"sql", "mysql", "postgresql", "oracle", "sqlite", "database", "query", "syntax"}
	for _, keyword := range sqlKeywords {
		if strings.Contains(responseLower, keyword) {
			return true, "SQLi"
		}
	}

	// XXE Detection
	if strings.Contains(responseLower, "xml") || strings.Contains(responseLower, "entity") {
		return true, "XXE"
	}

	// Command Injection Detection
	cmdKeywords := []string{"command", "exec", "system", "shell", "bash", "cmd"}
	for _, keyword := range cmdKeywords {
		if strings.Contains(responseLower, keyword) {
			return true, "Command Injection"
		}
	}

	// Path Traversal Detection
	if strings.Contains(responseLower, "root:") || strings.Contains(responseLower, "/etc/passwd") {
		return true, "Path Traversal"
	}

	// Interesting status codes
	if statusCode == 500 || statusCode == 403 {
		return true, "Interesting Response"
	}

	return false, ""
}

func (e *Engine) RunConcurrent(ctx context.Context, targetURL string, payloads []string, testType string, userField, passField string) <-chan TestResult {
	resultChan := make(chan TestResult, len(payloads))

	// Worker pool
	payloadChan := make(chan string, len(payloads))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < e.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range payloadChan {
				select {
				case <-ctx.Done():
					return
				default:
					var result TestResult
					if testType == "form" {
						result = e.TestForm(targetURL, payload, userField, passField)
					} else {
						result = e.TestURL(targetURL, payload)
					}

					e.updateStats(result)
					resultChan <- result
				}
			}
		}()
	}

	// Send payloads to workers
	go func() {
		defer close(payloadChan)
		for _, payload := range payloads {
			select {
			case payloadChan <- payload:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close result channel when done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return resultChan
}

func (e *Engine) updateStats(result TestResult) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.Tested++
	if result.Error != nil {
		e.stats.Errors++
	} else if result.Vulnerable {
		e.stats.Vulnerable++
	}
}

func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return *e.stats
}

func (e *Engine) PrintResult(result TestResult, verbose bool) {
	if result.Error != nil {
		color.Red("❌ Error: %s - %v", result.Payload, result.Error)
		return
	}

	if result.Vulnerable {
		color.Green("✅ %s: %s (%s) - %dms",
			result.VulnType, result.Payload, result.URL, result.ResponseTime.Milliseconds())
	} else {
		if verbose {
			color.Blue("🔸 Tested: %s (%d) - %dms",
				result.Payload, result.StatusCode, result.ResponseTime.Milliseconds())
		}
	}
}
