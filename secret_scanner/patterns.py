"""
Predefined patterns for detecting secrets
"""

import re
from typing import List, Dict, Pattern

# Default patterns for common secrets
DEFAULT_PATTERNS: List[Dict[str, str]] = [
    # AWS Access Key
    {
        "name": "AWS Access Key",
        "pattern": r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?[A-Z0-9]{20}['\"]?",
        "severity": "CRITICAL",
        "description": "AWS access key identifier"
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        "severity": "CRITICAL",
        "description": "AWS secret access key"
    },
    # AWS Session Token
    {
        "name": "AWS Session Token",
        "pattern": r"(?i)aws_session_token\s*=\s*['\"]?[A-Za-z0-9/+=]{100,}['\"]?",
        "severity": "CRITICAL",
        "description": "AWS temporary session token"
    },
    # Google API Key
    {
        "name": "Google API Key",
        "pattern": r"(?i)google_api_key\s*=\s*['\"]?AIza[0-9A-Za-z\-_]{35}['\"]?",
        "severity": "HIGH",
        "description": "Google Cloud API key"
    },
    {
        "name": "Google Cloud Service Account",
        "pattern": r'"type":\s*"service_account"',
        "severity": "CRITICAL",
        "description": "Google Cloud service account credentials"
    },
    # Stripe API Key
    {
        "name": "Stripe API Key",
        "pattern": r"(?i)stripe_(api_key|secret_key|publishable_key)\s*=\s*['\"]?(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}['\"]?",
        "severity": "CRITICAL",
        "description": "Stripe API key"
    },
    # GitHub Token
    {
        "name": "GitHub Token",
        "pattern": r"(?i)github_token\s*=\s*['\"]?(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}['\"]?",
        "severity": "CRITICAL",
        "description": "GitHub personal access token"
    },
    # Slack Token
    {
        "name": "Slack Token",
        "pattern": r"(?i)slack_(token|api_token|bot_token)\s*=\s*['\"]?xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}['\"]?",
        "severity": "HIGH",
        "description": "Slack API token"
    },
    # JWT Token
    {
        "name": "JWT Token",
        "pattern": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "severity": "HIGH",
        "description": "JSON Web Token"
    },
    # Private Keys
    {
        "name": "RSA Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "RSA private key"
    },
    {
        "name": "OpenSSH Private Key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "OpenSSH private key"
    },
    {
        "name": "EC Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Elliptic Curve private key"
    },
    {
        "name": "PGP Private Key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "CRITICAL",
        "description": "PGP private key block"
    },
    # Database URLs
    {
        "name": "Database URL",
        "pattern": r"(?i)(mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_\-]+:[^@]+@",
        "severity": "HIGH",
        "description": "Database connection string with credentials"
    },
    # API Keys (generic)
    {
        "name": "Generic API Key",
        "pattern": r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?",
        "severity": "MEDIUM",
        "description": "Generic API key"
    },
    # Secret Keys
    {
        "name": "Secret Key",
        "pattern": r"(?i)(secret_key|secretkey|secret-key)\s*[:=]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?",
        "severity": "HIGH",
        "description": "Secret key"
    },
    # Password
    {
        "name": "Password",
        "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
        "severity": "HIGH",
        "description": "Password field"
    },
    # OAuth Token
    {
        "name": "OAuth Token",
        "pattern": r"(?i)oauth_token\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
        "severity": "HIGH",
        "description": "OAuth access token"
    },
    # Auth Token
    {
        "name": "Auth Token",
        "pattern": r"(?i)(auth_token|authentication_token|auth-token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
        "severity": "HIGH",
        "description": "Authentication token"
    },
    # Access Token
    {
        "name": "Access Token",
        "pattern": r"(?i)(access_token|access-token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
        "severity": "HIGH",
        "description": "Access token"
    },
    # Heroku API Key
    {
        "name": "Heroku API Key",
        "pattern": r"(?i)heroku_api_key\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?",
        "severity": "CRITICAL",
        "description": "Heroku API key"
    },
    # SendGrid API Key
    {
        "name": "SendGrid API Key",
        "pattern": r"(?i)sendgrid_api_key\s*[:=]\s*['\"]?SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}['\"]?",
        "severity": "CRITICAL",
        "description": "SendGrid API key"
    },
    # Twilio API Key
    {
        "name": "Twilio API Key",
        "pattern": r"(?i)twilio_(account_sid|auth_token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?",
        "severity": "CRITICAL",
        "description": "Twilio API credentials"
    },
    # Mailchimp API Key
    {
        "name": "Mailchimp API Key",
        "pattern": r"(?i)mailchimp_api_key\s*[:=]\s*['\"]?[a-f0-9]{32}-us[0-9]{1,2}['\"]?",
        "severity": "CRITICAL",
        "description": "Mailchimp API key"
    },
    # PagerDuty API Key
    {
        "name": "PagerDuty API Key",
        "pattern": r"(?i)pagerduty_api_key\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?",
        "severity": "HIGH",
        "description": "PagerDuty API key"
    },
    # Datadog API Key
    {
        "name": "Datadog API Key",
        "pattern": r"(?i)datadog_api_key\s*[:=]\s*['\"]?[a-f0-9]{32}['\"]?",
        "severity": "HIGH",
        "description": "Datadog API key"
    },
    # New Relic License Key
    {
        "name": "New Relic License Key",
        "pattern": r"(?i)newrelic_license_key\s*[:=]\s*['\"]?[a-f0-9]{40}['\"]?",
        "severity": "HIGH",
        "description": "New Relic license key"
    },
    # Shopify API Key
    {
        "name": "Shopify API Key",
        "pattern": r"(?i)shopify_(api_key|password|shared_secret)\s*[:=]\s*['\"]?[a-zA-Z0-9]{32,}['\"]?",
        "severity": "HIGH",
        "description": "Shopify API credentials"
    },
    # Square Access Token
    {
        "name": "Square Access Token",
        "pattern": r"(?i)square_access_token\s*[:=]\s*['\"]?EAAA[0-9A-Za-z_-]{60}['\"]?",
        "severity": "HIGH",
        "description": "Square access token"
    },
    # Azure Storage Key
    {
        "name": "Azure Storage Key",
        "pattern": r"(?i)azure_storage_(account_name|account_key)\s*[:=]\s*['\"]?[a-zA-Z0-9+/]{88}==['\"]?",
        "severity": "CRITICAL",
        "description": "Azure storage account key"
    },
    # Azure Client Secret
    {
        "name": "Azure Client Secret",
        "pattern": r"(?i)azure_client_secret\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.~]{36}['\"]?",
        "severity": "CRITICAL",
        "description": "Azure client secret"
    },
    # Firebase Service Account
    {
        "name": "Firebase Service Account",
        "pattern": r'"firebase_adminsdk"',
        "severity": "CRITICAL",
        "description": "Firebase service account credentials"
    },
]


def compile_patterns(patterns: List[Dict[str, str]]) -> List[Dict[str, any]]:
    """
    Compile regex patterns for efficient matching
    
    Args:
        patterns: List of pattern dictionaries
        
    Returns:
        List of pattern dictionaries with compiled regex
    """
    compiled = []
    for pattern in patterns:
        try:
            compiled_pattern = re.compile(pattern["pattern"])
            compiled.append({
                "name": pattern["name"],
                "pattern": compiled_pattern,
                "severity": pattern.get("severity", "MEDIUM"),
                "description": pattern.get("description", "")
            })
        except re.error as e:
            print(f"Warning: Failed to compile pattern '{pattern['name']}': {e}")
    return compiled
