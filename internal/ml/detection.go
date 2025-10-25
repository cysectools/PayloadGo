package ml

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// MLDetector provides machine learning-based vulnerability detection
type MLDetector struct {
	models map[string]MLModel
}

// MLModel represents a machine learning model for detection
type MLModel struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Type        string                 `json:"type"` // "classification", "regression", "anomaly"
	Features    []string               `json:"features"`
	Threshold   float64                `json:"threshold"`
	Metadata    map[string]interface{} `json:"metadata"`
	LastUpdated time.Time              `json:"last_updated"`
}

// DetectionResult represents the result of ML-based detection
type DetectionResult struct {
	ModelName    string                 `json:"model_name"`
	Confidence   float64                `json:"confidence"`
	Prediction   string                 `json:"prediction"`
	Probability  map[string]float64     `json:"probability"`
	Features     map[string]interface{} `json:"features"`
	Explanation  string                 `json:"explanation"`
	Timestamp    time.Time              `json:"timestamp"`
	ModelVersion string                 `json:"model_version"`
}

// FeatureExtractor extracts features from HTTP requests and responses
type FeatureExtractor struct {
	// Feature extraction configuration
	config FeatureConfig
}

// FeatureConfig contains configuration for feature extraction
type FeatureConfig struct {
	IncludeHeaders  bool     `json:"include_headers"`
	IncludeBody     bool     `json:"include_body"`
	IncludeURL      bool     `json:"include_url"`
	MaxBodyLength   int      `json:"max_body_length"`
	MaxHeaderLength int      `json:"max_header_length"`
	NormalizeText   bool     `json:"normalize_text"`
	ExtractPatterns bool     `json:"extract_patterns"`
	PatternRegexes  []string `json:"pattern_regexes"`
}

// NewMLDetector creates a new ML detector instance
func NewMLDetector() *MLDetector {
	return &MLDetector{
		models: make(map[string]MLModel),
	}
}

// LoadModel loads a machine learning model
func (mld *MLDetector) LoadModel(name string, model MLModel) {
	mld.models[name] = model
}

// DetectVulnerability detects vulnerabilities using ML models
func (mld *MLDetector) DetectVulnerability(ctx context.Context, request *HTTPRequest, response *HTTPResponse) ([]DetectionResult, error) {
	var results []DetectionResult

	// Extract features from request/response
	features, err := mld.extractFeatures(request, response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract features: %w", err)
	}

	// Run detection through all applicable models
	for modelName, model := range mld.models {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result, err := mld.runModelDetection(modelName, model, features)
		if err != nil {
			continue // Log error but continue with other models
		}

		// Only include results above threshold
		if result.Confidence >= model.Threshold {
			results = append(results, result)
		}
	}

	return results, nil
}

// extractFeatures extracts features from HTTP request and response
func (mld *MLDetector) extractFeatures(request *HTTPRequest, response *HTTPResponse) (map[string]interface{}, error) {
	features := make(map[string]interface{})

	// Basic request features
	features["method"] = request.Method
	features["url_length"] = len(request.URL)
	features["url_depth"] = strings.Count(request.URL, "/")
	features["has_query"] = strings.Contains(request.URL, "?")
	features["query_length"] = len(request.Query)

	// Header features
	features["header_count"] = len(request.Headers)
	features["content_type"] = request.Headers["Content-Type"]
	features["user_agent"] = request.Headers["User-Agent"]
	features["has_auth"] = request.Headers["Authorization"] != ""

	// Body features
	features["body_length"] = len(request.Body)
	features["body_entropy"] = mld.calculateEntropy(request.Body)
	features["has_json"] = strings.Contains(request.Headers["Content-Type"], "json")
	features["has_xml"] = strings.Contains(request.Headers["Content-Type"], "xml")

	// Response features
	features["status_code"] = response.StatusCode
	features["response_length"] = len(response.Body)
	features["response_time"] = response.ResponseTime.Milliseconds()
	features["response_entropy"] = mld.calculateEntropy(response.Body)

	// Pattern-based features
	features["sql_patterns"] = mld.detectSQLPatterns(request.Body + response.Body)
	features["xss_patterns"] = mld.detectXSSPatterns(request.Body + response.Body)
	features["injection_patterns"] = mld.detectInjectionPatterns(request.Body + response.Body)

	// Behavioral features
	features["error_indicators"] = mld.detectErrorIndicators(response.Body)
	features["timing_anomaly"] = mld.detectTimingAnomaly(response.ResponseTime)
	features["size_anomaly"] = mld.detectSizeAnomaly(len(response.Body))

	return features, nil
}

// runModelDetection runs a specific model on extracted features
func (mld *MLDetector) runModelDetection(modelName string, model MLModel, features map[string]interface{}) (DetectionResult, error) {
	result := DetectionResult{
		ModelName:    modelName,
		ModelVersion: model.Version,
		Features:     features,
		Timestamp:    time.Now(),
	}

	// This is a simplified ML inference - in practice, you'd use a proper ML framework
	// like TensorFlow, PyTorch, or ONNX Runtime
	switch model.Type {
	case "classification":
		result = mld.runClassificationModel(model, features)
	case "regression":
		result = mld.runRegressionModel(model, features)
	case "anomaly":
		result = mld.runAnomalyModel(model, features)
	default:
		return result, fmt.Errorf("unknown model type: %s", model.Type)
	}

	return result, nil
}

// runClassificationModel runs a classification model
func (mld *MLDetector) runClassificationModel(model MLModel, features map[string]interface{}) DetectionResult {
	// Simplified classification logic
	// In practice, this would use a trained model
	confidence := mld.calculateConfidence(features)

	// Determine prediction based on confidence and features
	var prediction string
	probability := make(map[string]float64)

	if confidence > 0.8 {
		prediction = "vulnerable"
		probability["vulnerable"] = confidence
		probability["safe"] = 1.0 - confidence
	} else if confidence > 0.5 {
		prediction = "suspicious"
		probability["suspicious"] = confidence
		probability["safe"] = 1.0 - confidence
	} else {
		prediction = "safe"
		probability["safe"] = 1.0 - confidence
		probability["vulnerable"] = confidence
	}

	return DetectionResult{
		ModelName:    model.Name,
		ModelVersion: model.Version,
		Confidence:   confidence,
		Prediction:   prediction,
		Probability:  probability,
		Features:     features,
		Explanation:  mld.generateExplanation(features, prediction, confidence),
		Timestamp:    time.Now(),
	}
}

// runRegressionModel runs a regression model
func (mld *MLDetector) runRegressionModel(model MLModel, features map[string]interface{}) DetectionResult {
	// Simplified regression logic
	confidence := mld.calculateConfidence(features)

	// Regression models typically output a continuous value
	// Here we convert it to a classification
	var prediction string
	if confidence > 0.7 {
		prediction = "high_risk"
	} else if confidence > 0.4 {
		prediction = "medium_risk"
	} else {
		prediction = "low_risk"
	}

	return DetectionResult{
		ModelName:    model.Name,
		ModelVersion: model.Version,
		Confidence:   confidence,
		Prediction:   prediction,
		Features:     features,
		Explanation:  mld.generateExplanation(features, prediction, confidence),
		Timestamp:    time.Now(),
	}
}

// runAnomalyModel runs an anomaly detection model
func (mld *MLDetector) runAnomalyModel(model MLModel, features map[string]interface{}) DetectionResult {
	// Simplified anomaly detection
	anomalyScore := mld.calculateAnomalyScore(features)

	var prediction string
	if anomalyScore > 0.8 {
		prediction = "anomaly"
	} else {
		prediction = "normal"
	}

	return DetectionResult{
		ModelName:    model.Name,
		ModelVersion: model.Version,
		Confidence:   anomalyScore,
		Prediction:   prediction,
		Features:     features,
		Explanation:  mld.generateExplanation(features, prediction, anomalyScore),
		Timestamp:    time.Now(),
	}
}

// calculateConfidence calculates confidence score based on features
func (mld *MLDetector) calculateConfidence(features map[string]interface{}) float64 {
	// Simplified confidence calculation
	// In practice, this would use a trained model
	score := 0.0

	// Check for SQL injection indicators
	if sqlPatterns, ok := features["sql_patterns"].(int); ok && sqlPatterns > 0 {
		score += 0.3
	}

	// Check for XSS indicators
	if xssPatterns, ok := features["xss_patterns"].(int); ok && xssPatterns > 0 {
		score += 0.3
	}

	// Check for error indicators
	if errorIndicators, ok := features["error_indicators"].(int); ok && errorIndicators > 0 {
		score += 0.2
	}

	// Check for timing anomalies
	if timingAnomaly, ok := features["timing_anomaly"].(bool); ok && timingAnomaly {
		score += 0.2
	}

	// Normalize to 0-1 range
	return math.Min(score, 1.0)
}

// calculateAnomalyScore calculates anomaly score
func (mld *MLDetector) calculateAnomalyScore(features map[string]interface{}) float64 {
	// Simplified anomaly detection
	score := 0.0

	// Check for unusual patterns
	if entropy, ok := features["body_entropy"].(float64); ok && entropy > 4.0 {
		score += 0.3
	}

	if sizeAnomaly, ok := features["size_anomaly"].(bool); ok && sizeAnomaly {
		score += 0.4
	}

	if timingAnomaly, ok := features["timing_anomaly"].(bool); ok && timingAnomaly {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

// Helper methods for feature extraction
func (mld *MLDetector) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (mld *MLDetector) detectSQLPatterns(data string) int {
	patterns := []string{
		"union select", "drop table", "delete from", "insert into",
		"update set", "create table", "alter table", "exec(",
		"execute(", "sp_", "xp_", "waitfor delay",
	}

	count := 0
	lowerData := strings.ToLower(data)
	for _, pattern := range patterns {
		if strings.Contains(lowerData, pattern) {
			count++
		}
	}

	return count
}

func (mld *MLDetector) detectXSSPatterns(data string) int {
	patterns := []string{
		"<script>", "</script>", "javascript:", "onload=",
		"onerror=", "onclick=", "alert(", "document.cookie",
		"window.location", "eval(", "innerHTML",
	}

	count := 0
	lowerData := strings.ToLower(data)
	for _, pattern := range patterns {
		if strings.Contains(lowerData, pattern) {
			count++
		}
	}

	return count
}

func (mld *MLDetector) detectInjectionPatterns(data string) int {
	patterns := []string{
		"../", "..\\", "/etc/passwd", "c:\\windows",
		"${", "#{", "<%", "%>", "<?php", "<?=",
	}

	count := 0
	for _, pattern := range patterns {
		if strings.Contains(data, pattern) {
			count++
		}
	}

	return count
}

func (mld *MLDetector) detectErrorIndicators(data string) int {
	indicators := []string{
		"error", "exception", "stack trace", "fatal",
		"warning", "notice", "undefined", "null pointer",
		"sql syntax", "mysql error", "postgresql error",
	}

	count := 0
	lowerData := strings.ToLower(data)
	for _, indicator := range indicators {
		if strings.Contains(lowerData, indicator) {
			count++
		}
	}

	return count
}

func (mld *MLDetector) detectTimingAnomaly(responseTime time.Duration) bool {
	// Check if response time is unusually long (potential for timing attacks)
	return responseTime > 5*time.Second
}

func (mld *MLDetector) detectSizeAnomaly(size int) bool {
	// Check if response size is unusually large or small
	return size > 1000000 || size < 100 // 1MB or 100 bytes
}

func (mld *MLDetector) generateExplanation(features map[string]interface{}, prediction string, confidence float64) string {
	var explanation strings.Builder

	explanation.WriteString(fmt.Sprintf("Prediction: %s (confidence: %.2f)\n", prediction, confidence))
	explanation.WriteString("Key indicators:\n")

	if sqlPatterns, ok := features["sql_patterns"].(int); ok && sqlPatterns > 0 {
		explanation.WriteString(fmt.Sprintf("- SQL injection patterns detected: %d\n", sqlPatterns))
	}

	if xssPatterns, ok := features["xss_patterns"].(int); ok && xssPatterns > 0 {
		explanation.WriteString(fmt.Sprintf("- XSS patterns detected: %d\n", xssPatterns))
	}

	if errorIndicators, ok := features["error_indicators"].(int); ok && errorIndicators > 0 {
		explanation.WriteString(fmt.Sprintf("- Error indicators: %d\n", errorIndicators))
	}

	if timingAnomaly, ok := features["timing_anomaly"].(bool); ok && timingAnomaly {
		explanation.WriteString("- Timing anomaly detected\n")
	}

	return explanation.String()
}

// HTTPRequest represents an HTTP request for ML analysis
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Query   string            `json:"query"`
}

// HTTPResponse represents an HTTP response for ML analysis
type HTTPResponse struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	ResponseTime time.Duration     `json:"response_time"`
}

// TrainModel trains a machine learning model (placeholder)
func (mld *MLDetector) TrainModel(ctx context.Context, modelName string, trainingData []TrainingExample) error {
	// This would implement actual model training
	// For now, it's a placeholder
	return fmt.Errorf("model training not implemented")
}

// TrainingExample represents a training example for ML models
type TrainingExample struct {
	Features   map[string]interface{} `json:"features"`
	Label      string                 `json:"label"`
	Confidence float64                `json:"confidence"`
}

// UpdateModel updates an existing model
func (mld *MLDetector) UpdateModel(modelName string, model MLModel) {
	mld.models[modelName] = model
}

// GetModel returns a model by name
func (mld *MLDetector) GetModel(modelName string) (MLModel, bool) {
	model, exists := mld.models[modelName]
	return model, exists
}

// ListModels returns all available models
func (mld *MLDetector) ListModels() map[string]MLModel {
	return mld.models
}
