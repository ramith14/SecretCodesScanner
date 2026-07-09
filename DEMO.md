# Secret Scanner Demo Guide

This guide demonstrates how to use the Secret Scanner tool to detect exposed secrets in files and repositories.

## Installation

```bash
# Navigate to the project directory
cd secret-scanner

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

## Demo Scenarios

### 1. Scan a Single File

Let's scan a Python file that contains exposed secrets:

```bash
secret-scanner scan-file test_files/config.py
```

**Expected Output:**
```
Scanning file: test_files/config.py

⚠️  Found 10 secret(s) in 1 file(s)

File: test_files/config.py
  ⚠️  AWS Access Key [CRITICAL]
    Line: 6
    Match: AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    Description: AWS access key identifier

  ⚠️  AWS Secret Key [CRITICAL]
    Line: 7
    Match: AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    Description: AWS secret access key

  ⚠️  Database URL [HIGH]
    Line: 16
    Match: DATABASE_URL = "postgresql://admin:mysecretpassword123@localhost:5432/mydb"
    Description: Database connection string with credentials

  ⚠️  JWT Token [HIGH]
    Line: 28
    Match: JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    Description: JSON Web Token

Files scanned: 1
Files with secrets: 1
```

### 2. Scan a Directory

Scan all files in a directory:

```bash
secret-scanner scan-dir test_files
```

**Expected Output:**
```
Scanning directory: test_files

⚠️  Found 15 secret(s) in 3 file(s)

File: test_files/config.py
  ⚠️  AWS Access Key [CRITICAL]
    Line: 6
    Match: AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    Description: AWS access key identifier

  ...

File: test_files/api.js
  ⚠️  Generic API Key [MEDIUM]
    Line: 4
    Match: apiKey: "sk-1234567890abcdefghijklmnopqrstuvwxyz123456"
    Description: Generic API key

  ...

File: test_files/private_key.pem
  ⚠️  RSA Private Key [CRITICAL]
    Line: 1
    Match: -----BEGIN RSA PRIVATE KEY-----
    Description: RSA private key

Files scanned: 3
Files with secrets: 3
```

### 3. JSON Output Format

Export results in JSON format:

```bash
secret-scanner scan-file test_files/config.py --output json --output-file results.json
```

**Expected Output:**
```json
{
  "matches": [
    {
      "file_path": "test_files/config.py",
      "line_number": 6,
      "pattern_name": "AWS Access Key",
      "match": "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"",
      "severity": "CRITICAL",
      "description": "AWS access key identifier",
      "context": "..."
    }
  ],
  "files_scanned": 1,
  "files_with_secrets": 1,
  "scan_duration": 0.123
}
```

### 4. Initialize Configuration

Create a custom configuration file:

```bash
secret-scanner init-config
```

This creates a `.secret-scanner.yml` file with default settings:

```yaml
patterns:
  - name: 'Custom API Key'
    pattern: 'CUSTOM_API_KEY\\s*=\\s*["\']([a-zA-Z0-9]{32,})["\']'
    severity: 'high'
    description: 'Custom API key pattern'

exclude:
  - '*.log'
  - 'node_modules/**'
  - '.git/**'
  - 'venv/**'
  - '__pycache__/**'
  - 'dist/**'
  - 'build/**'

max_file_size: 10
```

### 5. Scan with Custom Configuration

Use a custom configuration file:

```bash
secret-scanner scan-dir test_files --config .secret-scanner.yml
```

### 6. Pre-commit Hook Integration

Install the pre-commit hook in your repository:

```bash
secret-scanner install-hook
```

This installs a hook at `.git/hooks/pre-commit` that will automatically scan staged files before each commit.

**Test the pre-commit hook:**

```bash
# Add a file with secrets
git add test_files/config.py

# Try to commit (will be blocked if secrets are found)
git commit -m "Add config file"
```

**Expected Output:**
```
Running Secret Scanner...
Scanning 1 staged file(s)...

⚠️  Found 10 secret(s) in 1 file(s)

❌ Commit blocked: Secrets detected in staged files
Please remove the secrets before committing.
To bypass this hook (not recommended), use: git commit --no-verify
```

### 7. Scan Staged Files Manually

Scan staged files without committing:

```bash
secret-scanner pre-commit
```

### 8. GitHub Repository Scanning

Scan a GitHub repository (requires git):

```bash
secret-scanner scan-repo https://github.com/username/repository
```

## Pattern Categories

The tool detects the following types of secrets:

### CRITICAL Severity
- AWS Access Keys
- AWS Secret Keys
- AWS Session Tokens
- RSA Private Keys
- OpenSSH Private Keys
- EC Private Keys
- PGP Private Keys
- Stripe API Keys
- GitHub Tokens
- Heroku API Keys
- SendGrid API Keys
- Twilio API Keys
- Mailchimp API Keys
- Azure Storage Keys
- Azure Client Secrets
- Firebase Service Accounts

### HIGH Severity
- Google API Keys
- Slack Tokens
- JWT Tokens
- Database URLs
- Secret Keys
- Passwords
- OAuth Tokens
- Auth Tokens
- Access Tokens
- PagerDuty API Keys
- Datadog API Keys
- New Relic License Keys
- Shopify API Keys
- Square Access Tokens

### MEDIUM Severity
- Generic API Keys

## Best Practices

1. **Never commit secrets**: Use environment variables or secret management systems
2. **Use pre-commit hooks**: Automatically catch secrets before they're committed
3. **Review findings**: The tool may produce false positives - review each finding
4. **Customize patterns**: Add custom patterns specific to your organization
5. **Exclude safe files**: Configure exclusions for files that don't contain real secrets
6. **Regular scans**: Scan your codebase regularly, especially after integrating new services

## Troubleshooting

### Issue: "Git not found"
**Solution**: Ensure Git is installed and you're in a git repository for pre-commit functionality.

### Issue: Too many false positives
**Solution**: 
- Customize the configuration file to adjust patterns
- Add exclude patterns for files that don't contain real secrets
- Review and refine the pattern definitions

### Issue: Scan is slow
**Solution**:
- Use the `max_file_size` configuration to skip large files
- Add more exclude patterns for directories you don't need to scan
- Scan specific directories instead of the entire project

## Video Demo Instructions

To create a demo video:

1. **Introduction** (30 seconds)
   - Explain what Secret Scanner does
   - Mention key features

2. **Installation** (1 minute)
   - Show cloning the repository
   - Demonstrate installing dependencies

3. **Basic Usage** (2 minutes)
   - Scan a single file with secrets
   - Show the output and explain the findings
   - Scan a directory

4. **Advanced Features** (2 minutes)
   - Demonstrate JSON output
   - Show custom configuration
   - Install and test pre-commit hook

5. **GitHub Repository Scanning** (1 minute)
   - Show scanning a remote repository
   - Explain the process

6. **Conclusion** (30 seconds)
   - Summarize benefits
   - Provide next steps

**Total video length**: ~7 minutes

**Recording Tips**:
- Use a clear, readable terminal font
- Keep commands simple and easy to follow
- Explain each step as you go
- Show actual secret detections
- Demonstrate both success and failure cases
