"""
Command-line interface for secret scanner
"""

import json
import sys
import time
from typing import Optional

import click
from colorama import init, Fore, Style

from secret_scanner.scanner import SecretScanner, ScanResult
from secret_scanner.github_scanner import GitHubScanner
from secret_scanner.pre_commit import PreCommitScanner, install_pre_commit_hook
from secret_scanner.config import Config

# Initialize colorama
init(autoreset=True)


def print_result(result: ScanResult, output_format: str = "text"):
    """
    Print scan results in specified format
    
    Args:
        result: ScanResult to print
        output_format: Format to use ('text' or 'json')
    """
    if output_format == "json":
        print(json.dumps(result.to_dict(), indent=2))
        return
    
    # Text format
    if not result.matches:
        print(f"{Fore.GREEN}✅ No secrets detected")
        print(f"Files scanned: {result.files_scanned}")
        return
    
    print(f"\n{Fore.YELLOW}⚠️  Found {len(result.matches)} secret(s) in {result.files_with_secrets} file(s)\n")
    
    # Group matches by file
    matches_by_file = {}
    for match in result.matches:
        if match.file_path not in matches_by_file:
            matches_by_file[match.file_path] = []
        matches_by_file[match.file_path].append(match)
    
    # Print matches grouped by file
    for file_path, matches in matches_by_file.items():
        print(f"{Fore.CYAN}File: {file_path}")
        for match in matches:
            severity_color = {
                "CRITICAL": Fore.RED,
                "HIGH": Fore.YELLOW,
                "MEDIUM": Fore.BLUE,
                "LOW": Fore.WHITE
            }.get(match.severity, Fore.WHITE)
            
            print(f"  {severity_color}⚠️  {match.pattern_name} [{match.severity}]")
            print(f"  {Fore.WHITE}    Line: {match.line_number}")
            print(f"  {Fore.WHITE}    Match: {match.match[:100]}{'...' if len(match.match) > 100 else ''}")
            if match.description:
                print(f"  {Fore.WHITE}    Description: {match.description}")
            print()
    
    print(f"{Fore.WHITE}Files scanned: {result.files_scanned}")
    print(f"{Fore.WHITE}Files with secrets: {result.files_with_secrets}")


@click.group()
@click.version_option(version="1.0.0")
def main():
    """Secret Scanner - Detect exposed secrets in files and repositories"""
    pass


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output-file', type=click.Path(), help='Save output to file')
@click.option('--config', type=click.Path(), help='Path to config file')
def scan_file(file_path: str, output: str, output_file: Optional[str], config: Optional[str]):
    """Scan a single file for secrets"""
    # Load config
    cfg = Config(config) if config else Config()
    patterns = cfg.get_all_patterns()
    
    # Initialize scanner
    scanner = SecretScanner(patterns)
    
    # Apply config settings
    scanner.set_max_file_size(cfg.get_max_file_size())
    for exclude_pattern in cfg.get_exclude_patterns():
        scanner.add_exclude_pattern(exclude_pattern)
    
    # Scan file
    print(f"{Fore.CYAN}Scanning file: {file_path}")
    start_time = time.time()
    result = scanner.scan_file(file_path)
    result.scan_duration = time.time() - start_time
    
    # Print results
    print_result(result, output)
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            if output == 'json':
                json.dump(result.to_dict(), f, indent=2)
            else:
                f.write(str(result))
        print(f"\n{Fore.GREEN}Results saved to: {output_file}")
    
    # Exit with error code if secrets found
    sys.exit(1 if result.matches else 0)


@main.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False))
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output-file', type=click.Path(), help='Save output to file')
@click.option('--config', type=click.Path(), help='Path to config file')
def scan_dir(directory: str, output: str, output_file: Optional[str], config: Optional[str]):
    """Scan a directory for secrets"""
    # Load config
    cfg = Config(config) if config else Config()
    patterns = cfg.get_all_patterns()
    
    # Initialize scanner
    scanner = SecretScanner(patterns)
    
    # Apply config settings
    scanner.set_max_file_size(cfg.get_max_file_size())
    for exclude_pattern in cfg.get_exclude_patterns():
        scanner.add_exclude_pattern(exclude_pattern)
    
    # Scan directory
    print(f"{Fore.CYAN}Scanning directory: {directory}")
    start_time = time.time()
    result = scanner.scan_directory(directory)
    result.scan_duration = time.time() - start_time
    
    # Print results
    print_result(result, output)
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            if output == 'json':
                json.dump(result.to_dict(), f, indent=2)
            else:
                f.write(str(result))
        print(f"\n{Fore.GREEN}Results saved to: {output_file}")
    
    # Exit with error code if secrets found
    sys.exit(1 if result.matches else 0)


@main.command()
@click.argument('repo_url')
@click.option('--branch', default='main', help='Branch to scan')
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output-file', type=click.Path(), help='Save output to file')
@click.option('--config', type=click.Path(), help='Path to config file')
def scan_repo(repo_url: str, branch: str, output: str, output_file: Optional[str], config: Optional[str]):
    """Scan a GitHub repository for secrets"""
    # Load config
    cfg = Config(config) if config else Config()
    patterns = cfg.get_all_patterns()
    
    # Initialize scanner
    scanner = SecretScanner(patterns)
    
    # Apply config settings
    scanner.set_max_file_size(cfg.get_max_file_size())
    for exclude_pattern in cfg.get_exclude_patterns():
        scanner.add_exclude_pattern(exclude_pattern)
    
    # Initialize GitHub scanner
    github_scanner = GitHubScanner(scanner)
    
    # Scan repository
    start_time = time.time()
    result = github_scanner.scan_repository(repo_url, branch)
    result.scan_duration = time.time() - start_time
    
    # Print results
    print_result(result, output)
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            if output == 'json':
                json.dump(result.to_dict(), f, indent=2)
            else:
                f.write(str(result))
        print(f"\n{Fore.GREEN}Results saved to: {output_file}")
    
    # Exit with error code if secrets found
    sys.exit(1 if result.matches else 0)


@main.command()
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
@click.option('--output-file', type=click.Path(), help='Save output to file')
@click.option('--config', type=click.Path(), help='Path to config file')
def pre_commit(output: str, output_file: Optional[str], config: Optional[str]):
    """Scan staged files for secrets (pre-commit hook)"""
    # Load config
    cfg = Config(config) if config else Config()
    patterns = cfg.get_all_patterns()
    
    # Initialize scanner
    scanner = SecretScanner(patterns)
    
    # Apply config settings
    scanner.set_max_file_size(cfg.get_max_file_size())
    for exclude_pattern in cfg.get_exclude_patterns():
        scanner.add_exclude_pattern(exclude_pattern)
    
    # Initialize pre-commit scanner
    pre_commit_scanner = PreCommitScanner(scanner)
    
    # Scan staged files
    start_time = time.time()
    result = pre_commit_scanner.scan_staged_files()
    result.scan_duration = time.time() - start_time
    
    # Print results
    print_result(result, output)
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            if output == 'json':
                json.dump(result.to_dict(), f, indent=2)
            else:
                f.write(str(result))
        print(f"\n{Fore.GREEN}Results saved to: {output_file}")
    
    # Exit with error code if secrets found
    sys.exit(1 if result.matches else 0)


@main.command()
@click.option('--hook-path', default='.git/hooks/pre-commit', help='Path to install hook')
def install_hook(hook_path: str):
    """Install pre-commit hook in current repository"""
    success = install_pre_commit_hook(hook_path)
    if success:
        print(f"{Fore.GREEN}✅ Pre-commit hook installed successfully")
        sys.exit(0)
    else:
        print(f"{Fore.RED}❌ Failed to install pre-commit hook")
        sys.exit(1)


@main.command()
@click.option('--path', type=click.Path(), help='Path to save config file')
def init_config(path: Optional[str]):
    """Initialize a default configuration file"""
    cfg = Config()
    success = cfg.save_default_config(path)
    if success:
        print(f"{Fore.GREEN}✅ Configuration file initialized")
        sys.exit(0)
    else:
        print(f"{Fore.RED}❌ Failed to initialize configuration file")
        sys.exit(1)


if __name__ == '__main__':
    main()
