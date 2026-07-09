"""
Core secret detection engine
"""

import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from secret_scanner.patterns import DEFAULT_PATTERNS, compile_patterns


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SecretMatch:
    """Represents a detected secret"""
    file_path: str
    line_number: int
    pattern_name: str
    match: str
    severity: str
    description: str
    context: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "pattern_name": self.pattern_name,
            "match": self.match,
            "severity": self.severity,
            "description": self.description,
            "context": self.context
        }


@dataclass
class ScanResult:
    """Represents the result of a scan"""
    matches: List[SecretMatch] = field(default_factory=list)
    files_scanned: int = 0
    files_with_secrets: int = 0
    scan_duration: float = 0.0
    
    def add_match(self, match: SecretMatch):
        """Add a secret match to the result"""
        self.matches.append(match)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "matches": [m.to_dict() for m in self.matches],
            "files_scanned": self.files_scanned,
            "files_with_secrets": self.files_with_secrets,
            "scan_duration": self.scan_duration
        }


class SecretScanner:
    """Main secret scanning engine"""
    
    def __init__(self, patterns: Optional[List[Dict[str, str]]] = None):
        """
        Initialize the scanner
        
        Args:
            patterns: Custom patterns to use. If None, uses default patterns.
        """
        if patterns is None:
            patterns = DEFAULT_PATTERNS
        
        self.patterns = compile_patterns(patterns)
        self.max_file_size = 10 * 1024 * 1024  # 10 MB default
        self.exclude_patterns = [
            "*.log",
            "*.min.js",
            "*.min.css",
            "node_modules/**",
            ".git/**",
            "venv/**",
            "env/**",
            "__pycache__/**",
            "*.pyc",
            "dist/**",
            "build/**"
        ]
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file for secrets
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult containing any found secrets
        """
        result = ScanResult()
        
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                print(f"Skipping {file_path}: File too large ({file_size} bytes)")
                return result
            
            # Check if file should be excluded
            if self._is_excluded(file_path):
                return result
            
            # Read file content
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                return result
            
            # Scan content line by line
            lines = content.split('\n')
            for line_num, line in enumerate(lines, start=1):
                for pattern in self.patterns:
                    matches = pattern["pattern"].finditer(line)
                    for match in matches:
                        # Get context (surrounding lines)
                        context_start = max(0, line_num - 2)
                        context_end = min(len(lines), line_num + 3)
                        context = '\n'.join(lines[context_start:context_end])
                        
                        secret_match = SecretMatch(
                            file_path=file_path,
                            line_number=line_num,
                            pattern_name=pattern["name"],
                            match=match.group(),
                            severity=pattern["severity"],
                            description=pattern["description"],
                            context=context
                        )
                        result.add_match(secret_match)
            
            result.files_scanned = 1
            if result.matches:
                result.files_with_secrets = 1
                
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        
        return result
    
    def scan_directory(self, directory: str) -> ScanResult:
        """
        Scan all files in a directory recursively
        
        Args:
            directory: Path to the directory to scan
            
        Returns:
            ScanResult containing any found secrets
        """
        result = ScanResult()
        files_scanned = 0
        files_with_secrets = set()
        
        if not os.path.isdir(directory):
            print(f"Error: {directory} is not a valid directory")
            return result
        
        for root, dirs, files in os.walk(directory):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                if not self._is_excluded(file_path):
                    file_result = self.scan_file(file_path)
                    result.matches.extend(file_result.matches)
                    files_scanned += 1
                    if file_result.matches:
                        files_with_secrets.add(file_path)
        
        result.files_scanned = files_scanned
        result.files_with_secrets = len(files_with_secrets)
        return result
    
    def _is_excluded(self, path: str) -> bool:
        """
        Check if a path should be excluded from scanning
        
        Args:
            path: Path to check
            
        Returns:
            True if path should be excluded
        """
        import fnmatch
        
        # Normalize path for comparison
        path = path.replace('\\', '/')
        
        for pattern in self.exclude_patterns:
            pattern = pattern.replace('\\', '/')
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, f"**/{pattern}"):
                return True
        
        return False
    
    def set_max_file_size(self, size_mb: int):
        """
        Set maximum file size to scan
        
        Args:
            size_mb: Maximum file size in megabytes
        """
        self.max_file_size = size_mb * 1024 * 1024
    
    def add_exclude_pattern(self, pattern: str):
        """
        Add a pattern to exclude from scanning
        
        Args:
            pattern: Glob pattern to exclude
        """
        self.exclude_patterns.append(pattern)
    
    def clear_exclude_patterns(self):
        """Clear all exclude patterns"""
        self.exclude_patterns = []
