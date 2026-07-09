"""
GitHub repository scanning functionality
"""

import os
import tempfile
import shutil
from typing import Optional
from git import Repo
from urllib.parse import urlparse

from secret_scanner.scanner import SecretScanner, ScanResult


class GitHubScanner:
    """Scanner for GitHub repositories"""
    
    def __init__(self, scanner: Optional[SecretScanner] = None):
        """
        Initialize GitHub scanner
        
        Args:
            scanner: SecretScanner instance to use. If None, creates a new one.
        """
        self.scanner = scanner or SecretScanner()
        self.temp_dir = None
    
    def scan_repository(self, repo_url: str, branch: str = "main") -> ScanResult:
        """
        Clone and scan a GitHub repository
        
        Args:
            repo_url: URL of the GitHub repository
            branch: Branch to scan (default: main)
            
        Returns:
            ScanResult containing any found secrets
        """
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix="secret_scanner_")
        
        try:
            print(f"Cloning repository: {repo_url}")
            print(f"Branch: {branch}")
            
            # Clone the repository
            repo = Repo.clone_from(repo_url, self.temp_dir, branch=branch)
            
            # Scan the cloned repository
            print(f"Scanning repository in: {self.temp_dir}")
            result = self.scanner.scan_directory(self.temp_dir)
            
            # Update file paths in results to be relative to repo root
            for match in result.matches:
                match.file_path = match.file_path.replace(self.temp_dir + os.sep, "")
            
            return result
            
        except Exception as e:
            print(f"Error scanning repository: {e}")
            return ScanResult()
        finally:
            # Clean up temporary directory
            self._cleanup()
    
    def scan_repository_local(self, repo_path: str) -> ScanResult:
        """
        Scan a local repository directory
        
        Args:
            repo_path: Path to local repository
            
        Returns:
            ScanResult containing any found secrets
        """
        if not os.path.isdir(repo_path):
            print(f"Error: {repo_path} is not a valid directory")
            return ScanResult()
        
        print(f"Scanning local repository: {repo_path}")
        return self.scanner.scan_directory(repo_path)
    
    def _cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                print(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                print(f"Error cleaning up temporary directory: {e}")
    
    def __del__(self):
        """Cleanup on destruction"""
        self._cleanup()


def parse_github_url(url: str) -> dict:
    """
    Parse GitHub URL to extract owner and repo name
    
    Args:
        url: GitHub repository URL
        
    Returns:
        Dictionary with owner and repo name
    """
    parsed = urlparse(url)
    path_parts = parsed.path.strip('/').split('/')
    
    if len(path_parts) >= 2:
        return {
            "owner": path_parts[0],
            "repo": path_parts[1].replace('.git', '')
        }
    
    return {}
