@echo off
echo Installing NexusGuard Security Framework...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed! Please install Python 3.8 or higher.
    exit /b 1
)

REM Check if pip is installed
pip --version >nul 2>&1
if errorlevel 1 (
    echo pip is not installed! Please install pip.
    exit /b 1
)

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv
call venv\Scripts\activate

REM Upgrade pip and install build tools
python -m pip install --upgrade pip
pip install wheel setuptools cython

REM Install core requirements first
echo Installing core requirements...
pip install --no-cache-dir -r requirements/core.txt

REM Install module requirements
echo Installing module requirements...
pip install --no-cache-dir -r requirements/network.txt || echo Network requirements installation had some issues, continuing...
pip install --no-cache-dir -r requirements/web.txt || echo Web requirements installation had some issues, continuing...
pip install --no-cache-dir -r requirements/dns.txt || echo DNS requirements installation had some issues, continuing...
pip install --no-cache-dir -r requirements/ssl.txt || echo SSL requirements installation had some issues, continuing...

REM Install optional requirements
echo Installing optional requirements...
pip install --no-cache-dir -r requirements/optional.txt || echo Optional requirements installation had some issues, continuing...

REM Check for system tools
where nmap >nul 2>&1
if errorlevel 1 (
    echo Nmap is not installed. Installing via chocolatey...
    where choco >nul 2>&1
    if errorlevel 1 (
        echo Installing Chocolatey...
        @"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    )
    choco install nmap -y
)

REM Create necessary directories
mkdir reports 2>nul
mkdir logs 2>nul
mkdir wordlists 2>nul

echo Installation complete!
echo.
echo To start using NexusGuard:
echo 1. Activate the virtual environment: venv\Scripts\activate
echo 2. Run a basic scan: python nexusguard.py -t example.com
echo 3. For help: python nexusguard.py --help
echo.

REM Check installation
python -c "import yaml; print('YAML module working correctly')" || echo Warning: YAML module not working, please check installation
python -c "import rich; print('Rich module working correctly')" || echo Warning: Rich module not working, please check installation
