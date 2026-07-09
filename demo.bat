@echo off
REM Demo script for Secret Scanner (Windows)

echo ==========================================
echo Secret Scanner Demo
echo ==========================================
echo.

REM Check if the tool is installed
python -c "import secret_scanner" 2>nul
if errorlevel 1 (
    echo Installing Secret Scanner...
    pip install -e .
    echo.
)

echo 1. Scanning a single file with secrets...
echo ----------------------------------------
secret-scanner scan-file test_files\config.py
echo.
pause

echo.
echo 2. Scanning a directory with multiple files...
echo ----------------------------------------------
secret-scanner scan-dir test_files
echo.
pause

echo.
echo 3. Exporting results in JSON format...
echo --------------------------------------
secret-scanner scan-file test_files\config.py --output json --output-file demo_results.json
echo Results saved to demo_results.json
echo.
pause

echo.
echo 4. Initializing custom configuration...
echo ----------------------------------------
secret-scanner init-config
echo Configuration file created: .secret-scanner.yml
echo.
pause

echo.
echo Demo complete!
echo ==========================================
echo.
echo Next steps:
echo - Review the detected secrets in the output above
echo - Check demo_results.json for the JSON output
echo - Customize .secret-scanner.yml for your needs
echo - Run 'secret-scanner install-hook' to add pre-commit protection
echo.
echo For more information, see DEMO.md
pause
