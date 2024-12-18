#!/bin/bash

echo "Installing NexusGuard Security Framework..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed! Please install Python 3.8 or higher."
    exit 1
fi

# Create and activate virtual environment
echo "Creating virtual environment..."
python3 -m venv titan-env
source titan-env/bin/activate

# Install system dependencies for Kali Linux
echo "Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3-dev build-essential libyaml-dev dnsutils

# Install Go tools properly
echo "Installing Go tools..."
if ! command -v go &> /dev/null; then
    sudo apt-get install -y golang
fi

# Set GOPATH if not set
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install Amass properly
echo "Installing Amass..."
go install -v github.com/owasp-amass/amass/v3/...@master

# Upgrade pip in the virtual environment
echo "Upgrading pip..."
python3 -m pip install --upgrade pip

# Install requirements one by one
echo "Installing Python requirements..."
python3 -m pip install --no-cache-dir -r requirements/core.txt
python3 -m pip install --no-cache-dir -r requirements/network.txt
python3 -m pip install --no-cache-dir -r requirements/web.txt
python3 -m pip install --no-cache-dir -r requirements/dns.txt
python3 -m pip install --no-cache-dir -r requirements/ssl.txt
python3 -m pip install --no-cache-dir -r requirements/optional.txt

# Install additional Kali tools
echo "Installing additional tools..."
sudo apt-get install -y \
    nmap \
    bind9-utils \
    whois \
    nikto \
    dirb \
    whatweb

# Create necessary directories
mkdir -p reports logs wordlists

# Make scripts executable
chmod +x scripts/*.sh

echo "Installation complete!"
echo
echo "To start using NexusGuard:"
echo "1. Activate the virtual environment: source titan-env/bin/activate"
echo "2. Run a basic scan: python3 nexusguard.py -t example.com"
echo "3. For help: python3 nexusguard.py --help"
echo

# Verify installation
echo "Verifying installation..."
if python3 -c "import yaml; print('YAML module working correctly')" && \
   python3 -c "import rich; print('Rich module working correctly')" && \
   command -v nmap > /dev/null && \
   command -v amass > /dev/null; then
    echo "All core dependencies installed successfully!"
else
    echo "Some dependencies might be missing. Please check the output above for errors."
fi
