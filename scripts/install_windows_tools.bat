@echo off
echo Installing NexusGuard dependencies...

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run as administrator.
    pause
    exit /b 1
)

REM Check for Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Check for pip
pip --version >nul 2>&1
if %errorLevel% neq 0 (
    echo pip is not installed. Please install pip.
    pause
    exit /b 1
)

REM Install Python dependencies
echo Installing Python dependencies...
pip install -r ..\requirements.txt

REM Check for Go
go version >nul 2>&1
if %errorLevel% neq 0 (
    echo Go is not installed. Some tools may not work.
    echo Please install Go from https://golang.org/
    pause
)

REM Install Go tools if Go is available
if %errorLevel% equ 0 (
    echo Installing Go-based tools...
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/OWASP/Amass/v3/...@master
    go install github.com/tomnomnom/assetfinder@latest
)

REM Install Nmap
where nmap >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing Nmap...
    winget install -e --id Insecure.Nmap
)

REM Create necessary directories
mkdir ..\logs 2>nul
mkdir ..\reports 2>nul
mkdir ..\data\wordlists 2>nul

echo Installation completed!
echo Please check the documentation for additional configuration steps.
pause
