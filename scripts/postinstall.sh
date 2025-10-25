#!/bin/bash
# Post-installation script for PayloadGo Enterprise

set -e

echo "PayloadGo Enterprise installation completed successfully!"

# Create payloadgo user if it doesn't exist
if ! id "payloadgo" &>/dev/null; then
    echo "Creating payloadgo system user..."
    useradd -r -s /bin/false -d /var/lib/payloadgo payloadgo
fi

# Create directories
mkdir -p /var/lib/payloadgo
mkdir -p /var/log/payloadgo
mkdir -p /etc/payloadgo

# Set permissions
chown -R payloadgo:payloadgo /var/lib/payloadgo
chown -R payloadgo:payloadgo /var/log/payloadgo
chmod 755 /var/lib/payloadgo
chmod 755 /var/log/payloadgo

# Copy default configuration if it doesn't exist
if [ ! -f /etc/payloadgo/config.yaml ]; then
    echo "Installing default configuration..."
    cp /usr/share/payloadgo/configs/config.yaml /etc/payloadgo/
    chown payloadgo:payloadgo /etc/payloadgo/config.yaml
    chmod 644 /etc/payloadgo/config.yaml
fi

# Create systemd service file
if command -v systemctl >/dev/null 2>&1; then
    echo "Installing systemd service..."
    cat > /etc/systemd/system/payloadgo.service << EOF
[Unit]
Description=PayloadGo Enterprise Security Testing Platform
After=network.target

[Service]
Type=simple
User=payloadgo
Group=payloadgo
WorkingDirectory=/var/lib/payloadgo
ExecStart=/usr/bin/payloadgo server --config /etc/payloadgo/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=payloadgo

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "PayloadGo service installed. Start with: systemctl start payloadgo"
    echo "Enable auto-start with: systemctl enable payloadgo"
fi

echo ""
echo "🎉 PayloadGo Enterprise is ready!"
echo ""
echo "Next steps:"
echo "1. Configure /etc/payloadgo/config.yaml"
echo "2. Start the service: systemctl start payloadgo"
echo "3. Check status: systemctl status payloadgo"
echo "4. View logs: journalctl -u payloadgo -f"
echo ""
echo "Documentation: https://docs.payloadgo.com"
echo "Support: support@payloadgo.com"
