"""
Configuration file support for secret scanner
"""

import os
import yaml
from typing import Dict, List, Optional, Any

from secret_scanner.patterns import DEFAULT_PATTERNS


class Config:
    """Configuration manager for secret scanner"""
    
    DEFAULT_CONFIG_FILE = ".secret-scanner.yml"
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to configuration file. If None, looks for default file.
        """
        self.config_path = config_path or self.DEFAULT_CONFIG_FILE
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Returns:
            Configuration dictionary
        """
        if not os.path.exists(self.config_path):
            return {}
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Error loading config file: {e}")
            return {}
    
    def get_patterns(self) -> List[Dict[str, str]]:
        """
        Get custom patterns from config
        
        Returns:
            List of custom pattern dictionaries
        """
        custom_patterns = self.config.get('patterns', [])
        
        # Validate custom patterns
        validated_patterns = []
        for pattern in custom_patterns:
            if 'name' in pattern and 'pattern' in pattern:
                validated_patterns.append({
                    'name': pattern['name'],
                    'pattern': pattern['pattern'],
                    'severity': pattern.get('severity', 'MEDIUM'),
                    'description': pattern.get('description', '')
                })
        
        return validated_patterns
    
    def get_exclude_patterns(self) -> List[str]:
        """
        Get exclude patterns from config
        
        Returns:
            List of glob patterns to exclude
        """
        return self.config.get('exclude', [])
    
    def get_max_file_size(self) -> int:
        """
        Get maximum file size from config
        
        Returns:
            Maximum file size in MB
        """
        return self.config.get('max_file_size', 10)
    
    def get_all_patterns(self) -> List[Dict[str, str]]:
        """
        Get all patterns (default + custom)
        
        Returns:
            List of all pattern dictionaries
        """
        custom_patterns = self.get_patterns()
        
        # If custom patterns are defined, use only those
        # Otherwise use default patterns
        if custom_patterns:
            return custom_patterns
        
        return DEFAULT_PATTERNS
    
    def save_default_config(self, path: Optional[str] = None) -> bool:
        """
        Save a default configuration file
        
        Args:
            path: Path to save config file. If None, uses default path.
            
        Returns:
            True if successful, False otherwise
        """
        config_path = path or self.config_path
        
        default_config = {
            'patterns': [
                {
                    'name': 'Custom API Key',
                    'pattern': 'CUSTOM_API_KEY\\s*=\\s*["\']([a-zA-Z0-9]{32,})["\']',
                    'severity': 'high',
                    'description': 'Custom API key pattern'
                }
            ],
            'exclude': [
                '*.log',
                'node_modules/**',
                '.git/**',
                'venv/**',
                '__pycache__/**',
                'dist/**',
                'build/**'
            ],
            'max_file_size': 10
        }
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            print(f"Default configuration saved to: {config_path}")
            return True
        except Exception as e:
            print(f"Error saving config file: {e}")
            return False
