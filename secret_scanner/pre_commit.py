"""
Pre-commit hook integration for secret scanning
"""

import subprocess
import os
from typing import List

from secret_scanner.scanner import SecretScanner, ScanResult


class PreCommitScanner:
    """Scanner for pre-commit hooks"""
    
    def __init__(self, scanner: SecretScanner = None):
        """
        Initialize pre-commit scanner
        
        Args:
            scanner: SecretScanner instance to use
        """
        self.scanner = scanner or SecretScanner()
    
    def get_staged_files(self) -> List[str]:
        """
        Get list of staged files in git
        
        Returns:
            List of staged file paths
        """
        try:
            # Get staged files
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
                capture_output=True,
                text=True,
                check=True
            )
            
            staged_files = result.stdout.strip().split('\n')
            return [f for f in staged_files if f and os.path.exists(f)]
            
        except subprocess.CalledProcessError as e:
            print(f"Error getting staged files: {e}")
            return []
        except FileNotFoundError:
            print("Git not found. Are you in a git repository?")
            return []
    
    def scan_staged_files(self) -> ScanResult:
        """
        Scan all staged files for secrets
        
        Returns:
            ScanResult containing any found secrets
        """
        result = ScanResult()
        staged_files = self.get_staged_files()
        
        if not staged_files:
            print("No staged files to scan")
            return result
        
        print(f"Scanning {len(staged_files)} staged file(s)...")
        
        for file_path in staged_files:
            if os.path.isfile(file_path):
                file_result = self.scanner.scan_file(file_path)
                result.matches.extend(file_result.matches)
                result.files_scanned += 1
                if file_result.matches:
                    result.files_with_secrets += 1
        
        return result
    
    def check_commit_allowed(self) -> bool:
        """
        Check if commit should be allowed based on secret scan
        
        Returns:
            True if no secrets found, False otherwise
        """
        result = self.scan_staged_files()
        
        if result.matches:
            print("\n❌ Secrets detected in staged files!")
            print(f"Found {len(result.matches)} secret(s) in {result.files_with_secrets} file(s)")
            print("\nPlease remove these secrets before committing.\n")
            return False
        
        print("✅ No secrets detected in staged files")
        return True


def generate_pre_commit_hook() -> str:
    """
    Generate pre-commit hook script content
    
    Returns:
        String content for pre-commit hook
    """
    return """#!/bin/bash
# Secret Scanner Pre-commit Hook
# This hook scans staged files for exposed secrets

echo "Running Secret Scanner..."
secret-scanner pre-commit

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Commit blocked: Secrets detected in staged files"
    echo "Please remove the secrets before committing."
    echo "To bypass this hook (not recommended), use: git commit --no-verify"
    exit 1
fi

echo "[OK] Pre-commit check passed"
exit 0
"""


def install_pre_commit_hook(hook_path: str = ".git/hooks/pre-commit") -> bool:
    """
    Install pre-commit hook in git repository
    
    Args:
        hook_path: Path where to install the hook
        
    Returns:
        True if successful, False otherwise
    """
    if not os.path.isdir(".git"):
        print("Error: Not in a git repository")
        return False
    
    try:
        hook_content = generate_pre_commit_hook()
        
        with open(hook_path, 'w') as f:
            f.write(hook_content)
        
        # Make hook executable on Unix systems
        try:
            os.chmod(hook_path, 0o755)
        except:
            pass
        
        print(f"Pre-commit hook installed at: {hook_path}")
        return True
        
    except Exception as e:
        print(f"Error installing pre-commit hook: {e}")
        return False
