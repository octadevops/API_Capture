@echo off
setlocal

title API Capture Framework - Auto Start
color 0A

REM Navigate to script directory
cd /d "%~dp0"

echo ╔═══════════════════════════════════════════════════════════╗
echo ║     API Capture Framework - Automatic Launcher            ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.7+
    pause
    exit /b 1
)


REM Auto-install missing packages (now with Firecrawl + Apify + Crawl4AI)
echo [*] Checking and installing dependencies...
python -m pip install --quiet --upgrade colorama selenium requests webdriver-manager pypdf trafilatura flask
echo [*] Installing optional crawling engines (Firecrawl/Apify/Crawl4AI) - failures are non-fatal...
python -m pip install --quiet firecrawl-py apify-client crawl4ai 2>nul
if errorlevel 1 echo [!] Optional engines not installed (app will fallback to Requests+Selenium)
REM Ensure PDF dirs
if not exist "api_captures\pdfs\press_releases" mkdir "api_captures\pdfs\press_releases"
if not exist "api_captures\pdfs\annual_reports" mkdir "api_captures\pdfs\annual_reports"

REM Create output directory
if not exist "api_captures" mkdir "api_captures"

REM Clear screen and start app
cls
echo [*] Starting API Capture Framework...
echo.

python app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application crashed with error code %errorlevel%
    pause
)

endlocal