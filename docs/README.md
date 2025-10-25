# PayloadGo Enterprise Documentation

Welcome to PayloadGo Enterprise, the comprehensive security testing platform designed for enterprise environments.

## Table of Contents

- [Getting Started](#getting-started)
- [Installation](#installation)
- [Configuration](#configuration)
- [User Guide](#user-guide)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Getting Started

PayloadGo Enterprise is a modular, observable, safe-by-default, auditable, and easy-to-integrate security testing platform. It provides enterprise-grade features including multi-tenancy, RBAC, audit logging, and comprehensive reporting.

### Key Features

- **🔒 Enterprise Security**: Multi-tenant architecture with role-based access control
- **📊 Advanced Analytics**: ML-powered confidence scoring and false-positive reduction
- **🛡️ Safety First**: Safe defaults, kill switches, and ethical guidelines
- **📈 Comprehensive Reporting**: Executive, technical, and compliance reports
- **🔧 Flexible Integration**: REST API, webhooks, and CI/CD integrations
- **📱 Modern UI**: Interactive CLI, TUI, and web dashboard

## Installation

### Binary Installation

Download the latest release for your platform:

```bash
# Linux AMD64
wget https://github.com/payloadgo/payloadgo/releases/latest/download/payloadgo_linux_amd64.tar.gz
tar -xzf payloadgo_linux_amd64.tar.gz
sudo mv payloadgo /usr/local/bin/

# macOS
brew install payloadgo/payloadgo/payloadgo

# Windows
# Download from GitHub releases and extract to your PATH
```

### Docker Installation

```bash
# Pull the latest image
docker pull payloadgo/payloadgo:latest

# Run with default configuration
docker run -d --name payloadgo \
  -p 8080:8080 \
  -v payloadgo_data:/var/lib/payloadgo \
  payloadgo/payloadgo:latest
```

### Kubernetes Installation

```bash
# Add the Helm repository
helm repo add payloadgo https://payloadgo.github.io/helm-charts
helm repo update

# Install PayloadGo Enterprise
helm install payloadgo payloadgo/payloadgo \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=payloadgo.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

## Configuration

### Basic Configuration

Create a configuration file at `/etc/payloadgo/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/payloadgo/certs/server.crt"
    key_file: "/etc/payloadgo/certs/server.key"

database:
  type: "postgresql"
  host: "localhost"
  port: 5432
  name: "payloadgo"
  username: "payloadgo"
  password: "secure_password"
  ssl_mode: "require"

auth:
  jwt_secret: "your-jwt-secret-key"
  token_ttl: "24h"
  refresh_token_ttl: "168h"

security:
  encryption_key: "your-encryption-key"
  audit_logging: true
  kill_switch: true

scanning:
  max_concurrency: 10
  default_rate_limit: 10
  default_timeout: 30s
  safe_defaults: true

observability:
  metrics:
    enabled: true
    port: 9090
  logging:
    level: "info"
    format: "json"
  tracing:
    enabled: true
    jaeger_endpoint: "http://localhost:14268"
```

### Environment Variables

You can also configure PayloadGo using environment variables:

```bash
export PAYLOADGO_DATABASE_URL="postgres://user:pass@localhost/payloadgo"
export PAYLOADGO_JWT_SECRET="your-secret-key"
export PAYLOADGO_ENCRYPTION_KEY="your-encryption-key"
export PAYLOADGO_LOG_LEVEL="info"
```

## User Guide

### Interactive CLI

Start the interactive CLI for guided workflows:

```bash
payloadgo interactive
```

This launches a user-friendly interface with:
- Quick scan setup
- Advanced scan configuration
- Template management
- Finding review
- Report generation

### Web Dashboard

Access the web dashboard at `https://your-payloadgo-instance/dashboard`:

- **Dashboard**: Overview of scans, findings, and metrics
- **Scans**: Manage and monitor security scans
- **Findings**: Review and triage security findings
- **Reports**: Generate and download reports
- **Metrics**: View performance and security metrics

### Command Line Usage

```bash
# Quick scan
payloadgo scan --target https://example.com --type web

# Advanced scan with authentication
payloadgo scan --target https://example.com \
  --auth-type basic \
  --username admin \
  --password secret \
  --categories xss,sqli,xxe \
  --rate-limit 5 \
  --concurrency 3

# Generate report
payloadgo report --scan-id scan-123 --format html --output report.html

# List findings
payloadgo findings --severity critical,high --status open
```

## API Documentation

PayloadGo Enterprise provides a comprehensive REST API for integration:

### Authentication

```bash
# Login
curl -X POST https://payloadgo.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Use JWT token
curl -H "Authorization: Bearer <token>" \
  https://payloadgo.example.com/api/v1/scans
```

### Core Endpoints

- `GET /api/v1/scans` - List scans
- `POST /api/v1/scans` - Create scan
- `GET /api/v1/scans/{id}` - Get scan details
- `GET /api/v1/findings` - List findings
- `GET /api/v1/findings/{id}` - Get finding details
- `POST /api/v1/reports` - Generate report

### Webhooks

Configure webhooks for real-time notifications:

```json
{
  "url": "https://your-system.com/webhook",
  "events": ["scan.completed", "finding.created"],
  "secret": "webhook-secret"
}
```

## Architecture

PayloadGo Enterprise follows a modular, microservices-inspired architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web UI        │    │   REST API      │    │   CLI/TUI       │
│   Dashboard     │    │   Endpoints     │    │   Interface     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
┌─────────────────────────────────┼─────────────────────────────────┐
│                                 │                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Auth Service  │  │  Scan Engine    │  │  Report Engine  │  │
│  │   RBAC          │  │  Adaptive       │  │  Templates      │  │
│  │   JWT/API Keys  │  │  Concurrency    │  │  Export         │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                 │                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Storage       │  │  Observability  │  │   Safety        │  │
│  │   PostgreSQL    │  │  Metrics        │  │   Kill Switch   │  │
│  │   Redis Cache   │  │  Logging        │  │   Ethical       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

- **Authentication & Authorization**: JWT-based auth with RBAC
- **Scan Engine**: Adaptive concurrency with circuit breakers
- **Detection Engine**: ML-powered confidence scoring
- **Storage Layer**: PostgreSQL with Redis caching
- **Observability**: Prometheus metrics and structured logging
- **Safety Systems**: Kill switches and ethical guidelines

## Security

### Data Protection

- **Encryption at Rest**: AES-256-GCM encryption for sensitive data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Secrets Management**: Integration with HashiCorp Vault and AWS KMS
- **Audit Logging**: Immutable audit trails with tamper evidence

### Access Control

- **Multi-tenancy**: Organization and team isolation
- **Role-based Access**: Admin, Scanner, Reviewer, Auditor roles
- **API Security**: JWT tokens and API key authentication
- **Rate Limiting**: Per-user and per-organization limits

### Safety Features

- **Safe Defaults**: Non-destructive payloads by default
- **Kill Switch**: Emergency stop for all scans
- **Ethical Guidelines**: Required consent and safety checks
- **Rate Limiting**: Protection against overwhelming targets

## Troubleshooting

### Common Issues

**Database Connection Issues**
```bash
# Check database connectivity
payloadgo health --check-database

# View database logs
docker logs payloadgo-db
```

**Authentication Problems**
```bash
# Reset admin password
payloadgo admin reset-password --email admin@example.com

# Check JWT configuration
payloadgo config validate
```

**Scan Failures**
```bash
# Check scan logs
payloadgo logs --scan-id scan-123

# Test connectivity
payloadgo test --target https://example.com
```

### Logs and Monitoring

```bash
# View application logs
journalctl -u payloadgo -f

# Check metrics
curl http://localhost:9090/metrics

# Health check
curl http://localhost:8080/health
```

## Contributing

We welcome contributions to PayloadGo Enterprise! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/payloadgo/payloadgo.git
cd payloadgo

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build
go build -o payloadgo ./cmd/payloadgo

# Run in development mode
./payloadgo server --config configs/config.yaml
```

### Code Style

- Follow Go best practices and conventions
- Use `gofmt` and `golint`
- Write comprehensive tests
- Document public APIs

## Support

- **Documentation**: [docs.payloadgo.com](https://docs.payloadgo.com)
- **Community**: [GitHub Discussions](https://github.com/payloadgo/payloadgo/discussions)
- **Enterprise Support**: [support@payloadgo.com](mailto:support@payloadgo.com)
- **Security Issues**: [security@payloadgo.com](mailto:security@payloadgo.com)

## License

PayloadGo Enterprise is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**PayloadGo Enterprise** - Secure, Scalable, Enterprise-Ready Security Testing
