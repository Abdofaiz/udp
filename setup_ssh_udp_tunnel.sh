#!/bin/bash

# SSH + UDP Tunnel Server Setup Script
# This script sets up a comprehensive SSH + UDP tunnel server with full port range support

set -e

echo "🚀 Setting up SSH + UDP Tunnel Server..."
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Updating system packages..."
apt update && apt upgrade -y

print_status "Installing Python and dependencies..."
apt install -y python3 python3-pip python3-venv build-essential libffi-dev libssl-dev python3-dev

print_status "Installing cryptography dependencies..."
apt install -y build-essential libffi-dev libssl-dev python3-dev

print_status "Creating Python virtual environment..."
mkdir -p /opt/ssh_udp_tunnel
cd /opt/ssh_udp_tunnel
python3 -m venv venv
source venv/bin/activate

print_status "Installing Python packages..."
pip install --upgrade pip
pip install cryptography

print_status "Creating server directory..."
mkdir -p /opt/ssh_udp_tunnel/server
cd /opt/ssh_udp_tunnel/server

print_status "Copying server files..."
# Copy the SSH + UDP tunnel server
cp ssh_udp_tunnel_server.py /opt/ssh_udp_tunnel/server/
chmod +x /opt/ssh_udp_tunnel/server/ssh_udp_tunnel_server.py

print_status "Creating systemd service..."
cat > /etc/systemd/system/ssh-udp-tunnel.service << EOF
[Unit]
Description=SSH + UDP Tunnel Server with Full Port Range Support
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/ssh_udp_tunnel/server
Environment=PATH=/opt/ssh_udp_tunnel/venv/bin
Environment=SSH_PORT=22
Environment=UDP_PORT=4433
Environment=ENCRYPTION_KEY=quicvpn2024secretkey32byteslong!
ExecStart=/opt/ssh_udp_tunnel/venv/bin/python3 ssh_udp_tunnel_server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

print_status "Reloading systemd..."
systemctl daemon-reload

print_status "Enabling SSH + UDP tunnel service..."
systemctl enable ssh-udp-tunnel

print_status "Configuring firewall..."
# Allow SSH (port 22) and UDP tunnel (port 4433)
ufw allow 22/tcp
ufw allow 4433/udp
ufw allow 4433/tcp

print_status "Starting SSH + UDP tunnel service..."
systemctl start ssh-udp-tunnel

print_status "Checking service status..."
systemctl status ssh-udp-tunnel --no-pager -l

print_success "SSH + UDP Tunnel Server setup completed!"
echo ""
echo "🔧 Configuration Details:"
echo "=========================="
echo "SSH Port: 22"
echo "UDP Tunnel Port: 4433"
echo "Encryption: AES-256-CBC"
echo "Port Range: 1-65535"
echo "Default Users:"
echo "  - vpnuser / vpnpass123"
echo "  - admin / adminpass456"
echo ""
echo "📁 Server Location: /opt/ssh_udp_tunnel/server/"
echo "📋 Service Name: ssh-udp-tunnel"
echo ""
echo "🚀 Useful Commands:"
echo "==================="
echo "Start service:     systemctl start ssh-udp-tunnel"
echo "Stop service:      systemctl stop ssh-udp-tunnel"
echo "Restart service:   systemctl restart ssh-udp-tunnel"
echo "Check status:      systemctl status ssh-udp-tunnel"
echo "View logs:         journalctl -u ssh-udp-tunnel -f"
echo "Check firewall:    ufw status"
echo ""
echo "🧪 Testing:"
echo "==========="
echo "1. SSH connection: ssh vpnuser@YOUR_VPS_IP"
echo "2. UDP tunnel:     Test with Android app on port 4433"
echo "3. Port range:     Full 1-65535 support"
echo ""
print_warning "⚠️  IMPORTANT: Change default passwords in production!"
print_warning "⚠️  Raw socket requires root privileges for internet forwarding"
echo ""
print_success "🎉 Setup complete! Your SSH + UDP tunnel server is ready!"
