# PayloadGo 🚀

**Professional payload testing tool for bug bounty hunters**

PayloadGo is a high-performance, concurrent payload testing tool designed specifically for bug bounty professionals. It features intelligent vulnerability detection, comprehensive reporting, and advanced testing capabilities.

## ✨ Features

### 🔥 Core Features
- **Concurrent Testing**: Multi-threaded payload testing with configurable worker pools
- **Intelligent Detection**: Advanced pattern matching for XSS, SQLi, XXE, Command Injection, and more
- **Professional Reporting**: JSON, HTML, and text report generation
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
- **Proxy Support**: SOCKS and HTTP proxy support for stealth testing
- **Custom Headers**: Full control over HTTP headers and user agents

### 🎯 Advanced Features
- **Payload Categories**: Organized payloads by vulnerability type (XSS, SQLi, XXE, etc.)
- **Custom Payloads**: Create and manage custom payload sets
- **Burp Suite Integration**: Seamless integration with Burp Suite Professional
- **Response Analysis**: Intelligent analysis of server responses
- **Timing Attacks**: Detection of blind injection vulnerabilities
- **Configuration Management**: YAML-based configuration system

### 🛡️ Bug Bounty Features
- **Stealth Mode**: Rate limiting and proxy rotation
- **Custom User Agents**: Mimic different browsers and tools
- **Header Manipulation**: Full control over HTTP headers
- **Response Caching**: Avoid duplicate requests
- **Session Management**: Maintain sessions across requests
- **Error Handling**: Graceful error handling and recovery

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/payloadgo.git
cd payloadgo

# Install dependencies
go mod tidy

# Build the tool
go build -o payloadgo cmd/payloadgo/main.go
```

### Basic Usage

```bash
# Interactive fuzzing
./payloadgo fuzz "http://target.com/search?q=TEST" -i

# Comprehensive scan
./payloadgo scan "http://target.com/search?q=TEST" -c xss,sqli -o results.json

# Generate report
./payloadgo report results.json -f html -o report.html
```

## 📖 Usage Examples

### 1. Interactive Fuzzing
```bash
./payloadgo fuzz "http://target.com/search?q=TEST" -i
```

### 2. Category-Specific Testing
```bash
# Test only XSS payloads
./payloadgo scan "http://target.com/search?q=TEST" -c xss

# Test multiple categories
./payloadgo scan "http://target.com/search?q=TEST" -c xss,sqli,xxe
```

### 3. Advanced Configuration
```bash
# Use custom threads and timeout
./payloadgo scan "http://target.com/search?q=TEST" -t 20 -T 30

# Use proxy
./payloadgo scan "http://target.com/search?q=TEST" -p "http://127.0.0.1:8080"

# Custom user agent
./payloadgo scan "http://target.com/search?q=TEST" -u "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

### 4. Report Generation
```bash
# Generate HTML report
./payloadgo report results.json -f html -o report.html

# Generate summary report
./payloadgo report results.json -f html -s

# Generate PDF report
./payloadgo report results.json -f pdf -o report.pdf
```

## 🔧 Configuration

### Configuration File
Create `~/.payloadgo.yaml`:

```yaml
threads: 10
timeout: 10
user_agent: "PayloadGo/1.0"
proxy: ""
verbose: false
rate_limit: 10
```

### Environment Variables
```bash
export PAYLOADGO_THREADS=20
export PAYLOADGO_TIMEOUT=30
export PAYLOADGO_PROXY="http://127.0.0.1:8080"
```

## 🎯 Payload Categories

### XSS (Cross-Site Scripting)
- Basic script tags
- Event handlers
- SVG-based XSS
- Filter bypasses
- DOM-based XSS

### SQL Injection
- Union-based
- Boolean-based blind
- Time-based blind
- Error-based
- Stacked queries

### XXE (XML External Entity)
- File inclusion
- SSRF attacks
- Blind XXE
- Parameter pollution

### Command Injection
- Basic command execution
- Filter bypasses
- Blind command injection
- Time-based detection

### Path Traversal
- Directory traversal
- Filter bypasses
- Encoding variations
- Null byte injection

## 🔍 Advanced Detection

### Vulnerability Detection
- **XSS**: Script tag detection, event handler analysis
- **SQLi**: Error message analysis, timing attacks
- **XXE**: XML parsing errors, external entity detection
- **Command Injection**: Command execution errors
- **Path Traversal**: File system access detection

### Response Analysis
- Status code analysis
- Response time analysis
- Content-type detection
- Error message parsing
- Payload reflection detection

## 📊 Reporting

### Report Formats
- **JSON**: Machine-readable format for automation
- **HTML**: Professional web reports with styling
- **PDF**: Print-ready reports
- **TXT**: Simple text reports

### Report Features
- Vulnerability categorization
- Severity assessment
- Response analysis
- Timeline information
- Executive summary

## 🛠️ Development

### Project Structure
```
payloadgo/
├── cmd/payloadgo/          # Main application
├── internal/
│   ├── cli/               # CLI interface
│   ├── commands/          # Command implementations
│   ├── config/           # Configuration management
│   ├── engine/           # Core testing engine
│   ├── payloads/         # Payload management
│   ├── features/         # Advanced features
│   └── utils/            # Utility functions
├── tests/               # Test files
└── docs/                # Documentation
```

### Adding Custom Payloads
```go
// Create custom payload manager
pm := features.NewPayloadManager()

// Add custom payload
pm.CreatePayload("custom-xss", "xss", "Custom XSS payloads", "high", []string{
    "<script>alert('custom')</script>",
    "<img src=x onerror=alert('custom')>",
})

// Save to file
pm.SaveCustomPayloads("custom-payloads.json")
```

### Extending Detection
```go
// Add custom detection patterns
detector := features.NewVulnerabilityDetector()
detector.AddPattern("CustomVuln", regexp.MustCompile(`custom-pattern`))
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test ./internal/engine
```

### Test Categories
- Unit tests for individual components
- Integration tests for full workflows
- Performance tests for concurrent operations
- Security tests for payload validation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Development Guidelines
- Follow Go best practices
- Add comprehensive tests
- Update documentation
- Use meaningful commit messages

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the bug bounty community
- Built for security researchers
- Designed for professional use

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/payloadgo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/payloadgo/discussions)
- **Security**: [Security Policy](https://github.com/yourusername/payloadgo/security)

---

**⚠️ Disclaimer**: This tool is for authorized testing only. Always ensure you have permission before testing any target. The authors are not responsible for any misuse of this tool.
