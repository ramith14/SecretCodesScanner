# Secret Scanner

A security tool that scans files and GitHub repositories to detect accidentally exposed sensitive information such as API keys, passwords, tokens, and secret credentials.

## Features

- **Automatic Commit Protection**: Scans every commit and blocks if secrets are detected
- **Pattern-based Detection**: Identifies common secret patterns including:
  - API Keys (AWS, Google, Stripe, etc.)
  - Database connection strings
  - JWT tokens
  - Private keys (SSH, PGP, etc.)
  - Passwords and authentication tokens
  - OAuth tokens
  - Slack tokens
  - And many more...

- **File Scanning**: Scan individual files or entire directories
- **GitHub Repository Scanning**: Clone and scan remote repositories
- **Pre-commit Hook Integration**: Automatically scan files before committing (blocks commits with secrets)
- **Configurable Patterns**: Customize detection patterns via configuration file
- **Detailed Reports**: Get detailed information about detected secrets
- **JSON/Text Output**: Export results in multiple formats

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secret-scanner.git
cd secret-scanner

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Scan a single file

```bash
secret-scanner scan-file path/to/file.py
```

### Scan a directory

```bash
secret-scanner scan-dir path/to/directory
```

### Scan a GitHub repository

```bash
secret-scanner scan-repo https://github.com/username/repo
```

### Scan staged files for pre-commit

```bash
secret-scanner pre-commit
```

### Configuration

Create a `.secret-scanner.yml` file in your project root:

```yaml
# Custom patterns to detect
patterns:
  - name: "Custom API Key"
    pattern: "CUSTOM_API_KEY\\s*=\\s*['\"]([a-zA-Z0-9]{32,})['\"]"
    severity: "high"

# Files to exclude
exclude:
  - "*.log"
  - "node_modules/**"
  - ".git/**"

# Maximum file size to scan (in MB)
max_file_size: 10
```

## Pre-commit Hook

Add this to your `.git/hooks/pre-commit` file:

```bash
#!/bin/bash
secret-scanner pre-commit
if [ $? -ne 0 ]; then
    echo "❌ Secrets detected! Please remove them before committing."
    exit 1
fi
```

## Output Formats

### JSON Output

```bash
secret-scanner scan-file file.py --output json --output-file results.json
```

### Text Output (default)

```bash
secret-scanner scan-file file.py --output text
```

## Examples

### Example 1: Scan a Python file

```bash
$ secret-scanner scan-file app.py

Scanning app.py...
⚠️  Secret detected!
  File: app.py
  Line: 42
  Pattern: AWS Access Key
  Match: AKIAIOSFODNN7EXAMPLE
  Severity: HIGH

Found 1 secret(s) in 1 file(s)
```

### Example 2: Scan a directory

```bash
$ secret-scanner scan-dir ./src

Scanning directory: ./src
Scanning 150 files...
⚠️  Secret detected!
  File: src/config.py
  Line: 15
  Pattern: Database Password
  Match: mysecretpassword123
  Severity: CRITICAL

⚠️  Secret detected!
  File: src/api.py
  Line: 89
  Pattern: API Key
  Match: sk-1234567890abcdef
  Severity: HIGH

Found 2 secret(s) in 2 file(s)
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is designed to help identify potential security vulnerabilities. However, it may produce false positives or miss some secrets. Always review findings manually and follow security best practices.
