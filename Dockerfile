# Multi-stage build for PayloadGo
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o payloadgo ./cmd/payloadgo

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    postgresql-client \
    curl \
    jq \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S payloadgo && \
    adduser -u 1001 -S payloadgo -G payloadgo

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/payloadgo /usr/local/bin/payloadgo

# Copy configuration files
COPY --from=builder /app/configs/ /app/configs/
COPY --from=builder /app/scripts/ /app/scripts/

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/reports /app/evidence && \
    chown -R payloadgo:payloadgo /app

# Set permissions
RUN chmod +x /usr/local/bin/payloadgo

# Switch to non-root user
USER payloadgo

# Expose ports
EXPOSE 8080 9090 9091

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Labels
LABEL org.opencontainers.image.title="PayloadGo" \
      org.opencontainers.image.description="Enterprise vulnerability testing platform" \
      org.opencontainers.image.url="https://github.com/payloadgo/payloadgo" \
      org.opencontainers.image.source="https://github.com/payloadgo/payloadgo" \
      org.opencontainers.image.vendor="PayloadGo" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.documentation="https://github.com/payloadgo/payloadgo/wiki" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

# Default command
CMD ["payloadgo", "server", "--config", "/app/configs/config.yaml"]
