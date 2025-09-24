#!/usr/bin/env python3
"""
Dependency installation script for Advanced Web Discovery Tool
"""

import subprocess
import sys
import os

def run_command(command):
    """Run shell command"""
    try:
        result = subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    print("Installing dependencies for Advanced Web Discovery Tool...")
    
    # Required packages
    packages = [
        "aiohttp",
        "requests",
        "beautifulsoup4",
        "python-nmap",
        "pandas",
        "pyyaml",
        "dnspython",
        "urllib3"
    ]
    
    # Optional packages
    optional_packages = [
        "playwright",
        "python-wappalyzer",
        "builtwith"
    ]
    
    # Install required packages
    print("\nInstalling required packages...")
    for package in packages:
        print(f"Installing {package}...")
        if run_command(f"{sys.executable} -m pip install {package}"):
            print(f"✓ {package} installed successfully")
        else:
            print(f"✗ Failed to install {package}")
    
    # Install optional packages
    print("\nInstalling optional packages...")
    for package in optional_packages:
        print(f"Installing {package}...")
        if run_command(f"{sys.executable} -m pip install {package}"):
            print(f"✓ {package} installed successfully")
        else:
            print(f"✗ Failed to install {package}")
    
    # Install Playwright browser
    if "playwright" in optional_packages:
        print("\nInstalling Playwright browser...")
        if run_command(f"{sys.executable} -m playwright install chromium"):
            print("✓ Playwright browser installed successfully")
        else:
            print("✗ Failed to install Playwright browser")
    
    print("\nInstallation completed!")
    print("\nUsage: python advanced_scanner.py https://example.com")

if __name__ == "__main__":
    main()
