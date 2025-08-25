#!/bin/bash

# UDP Tunnel Server Setup Script
# This script sets up a UDP tunnel server on your VPS

echo "🚀 Setting up UDP Tunnel Server..."
echo "=================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script needs to run as root for port 4433"
    echo "   Run: sudo bash setup_udp_tunnel.sh"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
apt update && apt upgrade -y

# Install Python and dependencies
echo "🐍 Installing Python and dependencies..."
apt install -y python3 python3-pip python3-venv

# Install cryptography dependencies
echo "🔐 Installing cryptography dependencies..."
apt install -y build-essential libssl-dev libffi-dev python3-dev

# Create virtual environment
echo "🏗️  Creating Python virtual environment..."
python3 -m venv /opt/udp_tunnel
source /opt/udp_tunnel/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Copy server files
echo "📁 Setting up server files..."
mkdir -p /opt/udp_tunnel/server
cp udp_tunnel_server.py /opt/udp_tunnel/server/
cp requirements.txt /opt/udp_tunnel/server/

# Create systemd service
echo "⚙️  Creating systemd service..."
cat > /etc/systemd/system/udp-tunnel.service << EOF
[Unit]
Description=UDP Tunnel Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/udp_tunnel/server
Environment=PATH=/opt/udp_tunnel/bin
ExecStart=/opt/udp_tunnel/bin/python3 udp_tunnel_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "🚀 Starting UDP tunnel service..."
systemctl daemon-reload
systemctl enable udp-tunnel
systemctl start udp-tunnel

# Check service status
echo "📊 Service status:"
systemctl status udp-tunnel --no-pager -l

# Create firewall rules
echo "🔥 Configuring firewall..."
ufw allow 4433/udp
ufw allow 4433/tcp

# Show connection info
echo ""
echo "✅ UDP Tunnel Server setup complete!"
echo "===================================="
echo "🌐 Server listening on: 0.0.0.0:4433 (UDP)"
echo "🔐 Encryption key: quicvpn2024secretkey32byteslong!"
echo "🌍 Supports all UDP ports: 1-65535"
echo ""
echo "📱 Your Android app should connect to:"
echo "   Server: $(hostname -I | awk '{print $1}')"
echo "   Port: 4433"
echo ""
echo "📋 Useful commands:"
echo "   Check status: systemctl status udp-tunnel"
echo "   View logs: journalctl -u udp-tunnel -f"
echo "   Stop service: systemctl stop udp-tunnel"
echo "   Start service: systemctl start udp-tunnel"
echo ""
echo "🔍 Testing the server:"
echo "   netcat -u $(hostname -I | awk '{print $1}') 4433"
echo ""
