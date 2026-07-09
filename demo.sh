#!/bin/bash
# Demo script for Secret Scanner

echo "=========================================="
echo "Secret Scanner Demo"
echo "=========================================="
echo ""

# Check if the tool is installed
if ! command -v secret-scanner &> /dev/null; then
    echo "Installing Secret Scanner..."
    pip install -e .
    echo ""
fi

echo "1. Scanning a single file with secrets..."
echo "----------------------------------------"
secret-scanner scan-file test_files/config.py
echo ""
read -p "Press Enter to continue..."

echo ""
echo "2. Scanning a directory with multiple files..."
echo "----------------------------------------------"
secret-scanner scan-dir test_files
echo ""
read -p "Press Enter to continue..."

echo ""
echo "3. Exporting results in JSON format..."
echo "--------------------------------------"
secret-scanner scan-file test_files/config.py --output json --output-file demo_results.json
echo "Results saved to demo_results.json"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "4. Initializing custom configuration..."
echo "----------------------------------------"
secret-scanner init-config
echo "Configuration file created: .secret-scanner.yml"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "5. Demo complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "- Review the detected secrets in the output above"
echo "- Check demo_results.json for the JSON output"
echo "- Customize .secret-scanner.yml for your needs"
echo "- Run 'secret-scanner install-hook' to add pre-commit protection"
echo ""
echo "For more information, see DEMO.md"
