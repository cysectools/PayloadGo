#!/bin/bash
# Pre-removal script for PayloadGo Enterprise

set -e

echo "Stopping PayloadGo Enterprise service..."

# Stop and disable systemd service
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet payloadgo; then
        systemctl stop payloadgo
    fi
    if systemctl is-enabled --quiet payloadgo; then
        systemctl disable payloadgo
    fi
    rm -f /etc/systemd/system/payloadgo.service
    systemctl daemon-reload
fi

echo "PayloadGo Enterprise service stopped and disabled."
