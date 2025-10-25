package engine

import (
	"math/rand"
	"sync"
	"time"
)

// AdaptiveEngine provides adaptive concurrency control
type AdaptiveEngine struct {
	mu                 sync.RWMutex
	baseConcurrency    int
	maxConcurrency     int
	minConcurrency     int
	currentConcurrency int
	successRate        float64
	errorRate          float64
	avgResponseTime    time.Duration
	circuitBreaker     *CircuitBreaker
	metrics            *EngineMetrics
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	mu                sync.RWMutex
	state             CircuitState
	failureCount      int
	successCount      int
	failureThreshold  int
	successThreshold  int
	timeout           time.Duration
	lastFailureTime   time.Time
	halfOpenMaxCalls  int
	halfOpenCallCount int
}

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitStateClosed CircuitState = iota
	CircuitStateOpen
	CircuitStateHalfOpen
)

// EngineMetrics tracks engine performance metrics
type EngineMetrics struct {
	mu                 sync.RWMutex
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	TotalResponseTime  time.Duration
	ErrorCounts        map[int]int
	LastUpdated        time.Time
}

// NewAdaptiveEngine creates a new adaptive engine
func NewAdaptiveEngine(baseConcurrency, maxConcurrency, minConcurrency int) *AdaptiveEngine {
	return &AdaptiveEngine{
		baseConcurrency:    baseConcurrency,
		maxConcurrency:     maxConcurrency,
		minConcurrency:     minConcurrency,
		currentConcurrency: baseConcurrency,
		circuitBreaker:     NewCircuitBreaker(5, 3, 30*time.Second),
		metrics: &EngineMetrics{
			ErrorCounts: make(map[int]int),
		},
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failureThreshold, successThreshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            CircuitStateClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
		halfOpenMaxCalls: 3,
	}
}

// GetConcurrency returns the current concurrency level
func (ae *AdaptiveEngine) GetConcurrency() int {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	return ae.currentConcurrency
}

// UpdateMetrics updates engine metrics based on request results
func (ae *AdaptiveEngine) UpdateMetrics(success bool, responseTime time.Duration, statusCode int) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.metrics.TotalRequests++
	ae.metrics.TotalResponseTime += responseTime

	if success {
		ae.metrics.SuccessfulRequests++
		ae.circuitBreaker.RecordSuccess()
	} else {
		ae.metrics.FailedRequests++
		ae.metrics.ErrorCounts[statusCode]++
		ae.circuitBreaker.RecordFailure()
	}

	ae.metrics.LastUpdated = time.Now()

	// Update success/error rates
	if ae.metrics.TotalRequests > 0 {
		ae.successRate = float64(ae.metrics.SuccessfulRequests) / float64(ae.metrics.TotalRequests)
		ae.errorRate = float64(ae.metrics.FailedRequests) / float64(ae.metrics.TotalRequests)
	}

	// Update average response time
	if ae.metrics.TotalRequests > 0 {
		ae.avgResponseTime = ae.metrics.TotalResponseTime / time.Duration(ae.metrics.TotalRequests)
	}

	// Adjust concurrency based on metrics
	ae.adjustConcurrency()
}

// adjustConcurrency adjusts concurrency based on current metrics
func (ae *AdaptiveEngine) adjustConcurrency() {
	// If circuit breaker is open, reduce concurrency significantly
	if ae.circuitBreaker.GetState() == CircuitStateOpen {
		ae.currentConcurrency = ae.minConcurrency
		return
	}

	// If error rate is high, reduce concurrency
	if ae.errorRate > 0.1 { // 10% error rate threshold
		ae.currentConcurrency = max(ae.minConcurrency, ae.currentConcurrency-1)
		return
	}

	// If success rate is high and response time is low, increase concurrency
	if ae.successRate > 0.95 && ae.avgResponseTime < 500*time.Millisecond {
		ae.currentConcurrency = min(ae.maxConcurrency, ae.currentConcurrency+1)
		return
	}

	// If response time is high, reduce concurrency
	if ae.avgResponseTime > 2*time.Second {
		ae.currentConcurrency = max(ae.minConcurrency, ae.currentConcurrency-1)
		return
	}
}

// CanExecute checks if a request can be executed based on circuit breaker state
func (ae *AdaptiveEngine) CanExecute() bool {
	return ae.circuitBreaker.CanExecute()
}

// GetMetrics returns current engine metrics
func (ae *AdaptiveEngine) GetMetrics() *EngineMetrics {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	// Return a copy to avoid race conditions
	metrics := &EngineMetrics{
		TotalRequests:      ae.metrics.TotalRequests,
		SuccessfulRequests: ae.metrics.SuccessfulRequests,
		FailedRequests:     ae.metrics.FailedRequests,
		TotalResponseTime:  ae.metrics.TotalResponseTime,
		ErrorCounts:        make(map[int]int),
		LastUpdated:        ae.metrics.LastUpdated,
	}

	// Copy error counts
	for code, count := range ae.metrics.ErrorCounts {
		metrics.ErrorCounts[code] = count
	}

	return metrics
}

// Reset resets the engine metrics
func (ae *AdaptiveEngine) Reset() {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.metrics = &EngineMetrics{
		ErrorCounts: make(map[int]int),
	}
	ae.currentConcurrency = ae.baseConcurrency
	ae.successRate = 0
	ae.errorRate = 0
	ae.avgResponseTime = 0
}

// Circuit Breaker Methods

// CanExecute checks if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case CircuitStateClosed:
		return true
	case CircuitStateOpen:
		// Check if timeout has passed
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.state = CircuitStateHalfOpen
			cb.halfOpenCallCount = 0
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	case CircuitStateHalfOpen:
		// Allow limited calls in half-open state
		return cb.halfOpenCallCount < cb.halfOpenMaxCalls
	default:
		return false
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.successCount++
	cb.failureCount = 0

	if cb.state == CircuitStateHalfOpen {
		cb.halfOpenCallCount++
		if cb.successCount >= cb.successThreshold {
			cb.state = CircuitStateClosed
			cb.successCount = 0
		}
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.successCount = 0
	cb.lastFailureTime = time.Now()

	if cb.state == CircuitStateHalfOpen {
		cb.state = CircuitStateOpen
	} else if cb.failureCount >= cb.failureThreshold {
		cb.state = CircuitStateOpen
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return map[string]interface{}{
		"state":           cb.state,
		"failure_count":   cb.failureCount,
		"success_count":   cb.successCount,
		"last_failure":    cb.lastFailureTime,
		"half_open_calls": cb.halfOpenCallCount,
	}
}

// Helper functions

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	mu         sync.Mutex
	limit      int
	interval   time.Duration
	tokens     int
	lastRefill time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:      limit,
		interval:   interval,
		tokens:     limit,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed >= rl.interval {
		rl.tokens = rl.limit
		rl.lastRefill = now
	}

	// Check if tokens are available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// GetStats returns rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return map[string]interface{}{
		"limit":       rl.limit,
		"tokens":      rl.tokens,
		"interval":    rl.interval,
		"last_refill": rl.lastRefill,
	}
}

// BackoffStrategy implements exponential backoff
type BackoffStrategy struct {
	baseDelay  time.Duration
	maxDelay   time.Duration
	multiplier float64
	jitter     bool
}

// NewBackoffStrategy creates a new backoff strategy
func NewBackoffStrategy(baseDelay, maxDelay time.Duration, multiplier float64, jitter bool) *BackoffStrategy {
	return &BackoffStrategy{
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
		multiplier: multiplier,
		jitter:     jitter,
	}
}

// GetDelay calculates the delay for the given attempt
func (bs *BackoffStrategy) GetDelay(attempt int) time.Duration {
	delay := float64(bs.baseDelay) * pow(bs.multiplier, float64(attempt))

	if delay > float64(bs.maxDelay) {
		delay = float64(bs.maxDelay)
	}

	if bs.jitter {
		// Add jitter to prevent thundering herd
		jitter := delay * 0.1 * (2*rand.Float64() - 1)
		delay += jitter
	}

	return time.Duration(delay)
}

// pow calculates x^y
func pow(x, y float64) float64 {
	result := 1.0
	for i := 0; i < int(y); i++ {
		result *= x
	}
	return result
}
