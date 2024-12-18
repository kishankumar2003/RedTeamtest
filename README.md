# NexusGuard Security Framework

A comprehensive security assessment framework for web applications and network infrastructure.

## Quick Start

### Windows
```batch
# Clone the repository
git clone https://github.com/yourusername/NexusGuard.git
cd NexusGuard

# Run installation script
scripts\install_windows.bat

# Activate virtual environment
venv\Scripts\activate
```

### Linux
```bash
# Clone the repository
git clone https://github.com/yourusername/NexusGuard.git
cd NexusGuard

# Make installation script executable
chmod +x scripts/install_linux.sh

# Run installation script
./scripts/install_linux.sh

# Activate virtual environment
source venv/bin/activate
```

## Features

- **Web Application Security**
  - Custom Web Fuzzing Engine
  - Directory Enumeration
  - Parameter Testing
  - Rate-Limited Scanning

- **Network Security**
  - Port Scanning
  - Service Detection
  - SSL/TLS Analysis

- **DNS Analysis**
  - Subdomain Enumeration
  - DNS Record Analysis
  - Zone Transfer Tests

## Usage Examples

1. Basic Scan
```bash
python nexusguard.py -t example.com
```

2. Web Fuzzing
```bash
python nexusguard.py -t example.com --web-fuzz --wordlist wordlists/directories.txt
```

3. Full Security Assessment
```bash
python nexusguard.py -t example.com --full-scan --report
```

## Documentation

For detailed documentation, please see:
- [Installation Guide](NOTION_DOCUMENTATION.md#installation-process)
- [Module Documentation](NOTION_DOCUMENTATION.md#module-organization)
- [API Reference](NOTION_DOCUMENTATION.md#web-fuzzing-capabilities)

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
