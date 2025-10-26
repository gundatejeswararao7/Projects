#!/bin/bash

echo "======================================"
echo "Personal Firewall Setup Script"
echo "======================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install dependencies based on OS
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    echo "Installing dependencies for Debian/Ubuntu..."
    apt-get update
    apt-get install -y python3 python3-pip libpcap-dev
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
    echo "Installing dependencies for RHEL/CentOS/Fedora..."
    yum install -y python3 python3-pip libpcap-devel
elif [[ "$OS" == *"Arch"* ]]; then
    echo "Installing dependencies for Arch Linux..."
    pacman -S --noconfirm python python-pip libpcap
else
    echo "Unsupported OS. Please install python3, pip, and libpcap manually."
    exit 1
fi

# Install Python dependencies
echo ""
echo "Installing Python packages..."
pip3 install -r requirements.txt

# Create necessary directories
echo ""
echo "Setting up directories..."
mkdir -p /var/log/personal-firewall
mkdir -p /etc/personal-firewall

# Copy files
echo "Copying configuration files..."
if [ -f firewall_rules.json ]; then
    cp firewall_rules.json /etc/personal-firewall/firewall_rules.json
    echo "Configuration copied to /etc/personal-firewall/"
else
    echo "firewall_rules.json not found in current directory"
    echo "Default rules will be created on first run"
fi

# Create systemd service (Linux only)
if command -v systemctl &> /dev/null; then
    echo ""
    echo "Creating systemd service..."
    cat > /etc/systemd/system/personal-firewall.service << EOF
[Unit]
Description=Personal Firewall Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $(pwd)/firewall.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Systemd service created."
    echo ""
    echo "Service Management Commands:"
    echo "  Start:   sudo systemctl start personal-firewall"
    echo "  Stop:    sudo systemctl stop personal-firewall"
    echo "  Status:  sudo systemctl status personal-firewall"
    echo "  Enable:  sudo systemctl enable personal-firewall"
    echo "  Logs:    sudo journalctl -u personal-firewall -f"
fi

# Create CLI symlink
echo ""
echo "Creating CLI command..."
ln -sf $(pwd)/firewall_cli.py /usr/local/bin/firewall-cli
chmod +x $(pwd)/firewall_cli.py
chmod +x $(pwd)/firewall.py

echo ""
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo "Quick Start Guide:"
echo ""
echo "1. Test the installation:"
echo "   python3 test_firewall.py"
echo ""
echo "2. Start the firewall:"
echo "   Option A - Direct:  sudo python3 firewall.py"
echo "   Option B - Service: sudo systemctl start personal-firewall"
echo ""
echo "3. Manage firewall:"
echo "   firewall-cli list                  # View rules"
echo "   firewall-cli logs                  # View logs"
echo "   firewall-cli stats                 # View statistics"
echo "   firewall-cli add <name> <action>   # Add rule"
echo ""
echo "Configuration files:"
echo "   Local:  $(pwd)/firewall_rules.json"
echo "   System: /etc/personal-firewall/firewall_rules.json"
echo ""
echo "Documentation:"
echo "   README.md              - User guide"
echo "   DEPLOYMENT_GUIDE.md    - Deployment instructions"
echo "   QUICK_REFERENCE.md     - Command cheat sheet"
echo ""
echo "Important: This firewall requires root privileges to run."
echo ""
