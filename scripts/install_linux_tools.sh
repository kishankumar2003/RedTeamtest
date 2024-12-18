#!/bin/bash

echo "Installing NexusGuard dependencies..."

# Check for root privileges
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Update package lists
apt-get update

# Install basic requirements
apt-get install -y python3-pip python3-venv nmap git golang

# Install Python dependencies
pip3 install -r ../requirements.txt

# Install Go tools
if command -v go &> /dev/null; then
    echo "Installing Go-based tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/OWASP/Amass/v3/...@master
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/zricethezav/gitleaks/v8@latest
fi

# Install additional tools
apt-get install -y \
    sqlmap \
    dirb \
    nikto \
    whatweb \
    wapiti \
    hydra \
    whois \
    dig \
    host \
    dnsutils

# Create necessary directories
mkdir -p ../logs
mkdir -p ../reports
mkdir -p ../data/wordlists

# Set correct permissions
chown -R $SUDO_USER:$SUDO_USER ../logs ../reports ../data

echo "Installation completed!"
echo "Please check the documentation for additional configuration steps."
