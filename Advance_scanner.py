#!/usr/bin/env python3
"""
Advanced Web Discovery Tool - Comprehensive Security Scanner
Author: Security Researcher
Version: 2.0
Description: Advanced multi-threaded web directory, API, and infrastructure discovery tool
"""

import asyncio
import aiohttp
import requests
import argparse
import os
import sys
import json
import yaml
import re
import time
import threading
import random
import string
from urllib.parse import urljoin, urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import pandas as pd
import dns.resolver
import socket
import ssl
import subprocess
import shlex
from datetime import datetime
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import nmap
import warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import wappalyzer
    from wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

class AdvancedWebDiscoveryTool:
    def __init__(self, base_url, max_threads=20, timeout=10, output_dir="scan_results"):
        self.base_url = base_url.rstrip('/')
        self.max_threads = max_threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.found_resources = []
        self.session = None
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "downloads").mkdir(exist_ok=True)
        
        # Enhanced wordlists
        self.common_dirs = self.load_wordlist('directories')
        self.common_files = self.load_wordlist('files')
        self.subdomains = self.load_wordlist('subdomains')
        self.api_patterns = self.load_wordlist('api_patterns')
        
        # Results storage
        self.results = {
            'directories': [],
            'files': [],
            'subdomains': [],
            'apis': [],
            'technologies': {},
            'ports': [],
            'cloud_resources': [],
            'js_endpoints': []
        }

    def load_wordlist(self, list_type):
        """Load or generate wordlists"""
        wordlists = {
            'directories': [
                'admin', 'administrator', 'backend', 'api', 'service', 'sql',
                'database', 'config', 'include', 'inc', 'lib', 'src', 'handlers',
                'handler', 'uploads', 'files', 'data', 'log', 'logs', 'temp',
                'tmp', 'backup', 'old', 'new', 'dev', 'test', 'staging', 'prod',
                'web', 'www', 'public', 'private', 'secure', 'auth', 'login'
            ],
            'files': [
                'admin.php', 'admin.html', 'admin.aspx', 'admin.jsp', 'api.php',
                'api.html', 'api.aspx', 'api.jsp', 'service.php', 'sql.php',
                'database.php', 'config.php', 'handlers_api.php', 'server.php',
                'login.php', 'config.json', 'database.sql', 'backup.sql',
                '.env', '.git/config', 'robots.txt', 'sitemap.xml',
                'web.config', '.htaccess', 'phpinfo.php', 'test.php'
            ],
            'subdomains': [
                'www', 'api', 'admin', 'test', 'dev', 'staging', 'backup',
                'mail', 'ftp', 'cpanel', 'webmail', 'blog', 'shop', 'store',
                'cdn', 'assets', 'media', 'static', 'app', 'mobile', 'secure'
            ],
            'api_patterns': [
                'api/v1', 'api/v2', 'api/v3', 'rest/api', 'graphql', 'oauth',
                'auth', 'token', 'user', 'users', 'product', 'products',
                'order', 'orders', 'payment', 'payments', 'customer', 'customers'
            ]
        }
        return wordlists.get(list_type, [])

    async def async_session(self):
        """Create async session"""
        connector = aiohttp.TCPConnector(limit=self.max_threads, verify_ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        return aiohttp.ClientSession(connector=connector, timeout=timeout)

    async def check_url(self, session, url):
        """Check if URL exists"""
        try:
            async with session.head(url, allow_redirects=True) as response:
                if response.status == 200:
                    async with session.get(url) as full_response:
                        content = await full_response.text()
                        return True, full_response.status, content, dict(full_response.headers)
                return response.status in [200, 301, 302, 403], response.status, "", dict(response.headers)
        except Exception as e:
            return False, 0, str(e), {}

    async def discover_directories(self):
        """Discover directories"""
        print("[+] Discovering directories...")
        urls_to_check = [urljoin(self.base_url, f"{dir}/") for dir in self.common_dirs]
        
        async with await self.async_session() as session:
            tasks = [self.check_directory(session, url) for url in urls_to_check]
            results = await asyncio.gather(*tasks)
            
            for url, exists in zip(urls_to_check, results):
                if exists:
                    self.results['directories'].append(url)
                    self.found_resources.append(('directory', url))

    async def check_directory(self, session, url):
        """Check if directory exists"""
        try:
            async with session.get(url, allow_redirects=False) as response:
                return response.status in [200, 301, 302, 403]
        except:
            return False

    async def discover_files(self):
        """Discover files"""
        print("[+] Discovering files...")
        urls_to_check = []
        
        # Add common files
        for file in self.common_files:
            urls_to_check.append(urljoin(self.base_url, file))
        
        # Add file extensions
        extensions = ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.json', '.xml', '.txt']
        for base in ['admin', 'api', 'config', 'test', 'backup']:
            for ext in extensions:
                urls_to_check.append(urljoin(self.base_url, f"{base}{ext}"))
        
        async with await self.async_session() as session:
            tasks = [self.check_file(session, url) for url in urls_to_check]
            results = await asyncio.gather(*tasks)
            
            for url, exists in zip(urls_to_check, results):
                if exists:
                    self.results['files'].append(url)
                    self.found_resources.append(('file', url))

    async def check_file(self, session, url):
        """Check if file exists"""
        exists, status, content, headers = await self.check_url(session, url)
        return exists

    async def discover_subdomains(self):
        """Discover subdomains"""
        print("[+] Discovering subdomains...")
        domain = urlparse(self.base_url).netloc
        
        async with await self.async_session() as session:
            tasks = []
            for subdomain in self.subdomains:
                test_url = f"https://{subdomain}.{domain}"
                tasks.append(self.check_subdomain(session, test_url, subdomain))
            
            results = await asyncio.gather(*tasks)
            
            for subdomain, exists in results:
                if exists:
                    self.results['subdomains'].append(subdomain)

    async def check_subdomain(self, session, url, subdomain):
        """Check if subdomain exists"""
        try:
            async with session.get(url) as response:
                return subdomain, response.status == 200
        except:
            return subdomain, False

    async def discover_api_endpoints(self):
        """Discover API endpoints"""
        print("[+] Discovering API endpoints...")
        urls_to_check = [urljoin(self.base_url, pattern) for pattern in self.api_patterns]
        
        async with await self.async_session() as session:
            tasks = [self.check_api_endpoint(session, url) for url in urls_to_check]
            results = await asyncio.gather(*tasks)
            
            for url, exists in zip(urls_to_check, results):
                if exists:
                    self.results['apis'].append(url)
                    self.found_resources.append(('api', url))

    async def check_api_endpoint(self, session, url):
        """Check if API endpoint exists"""
        exists, status, content, headers = await self.check_url(session, url)
        return exists and ('json' in str(headers.get('content-type', '')).lower() or 
                          'api' in str(headers.get('x-powered-by', '')).lower() or
                          'api' in url.lower())

    async def analyze_technologies(self):
        """Analyze technology stack"""
        print("[+] Analyzing technology stack...")
        
        tech_info = {}
        
        # Header-based analysis
        async with await self.async_session() as session:
            async with session.get(self.base_url) as response:
                headers = dict(response.headers)
                
                # Server detection
                if 'server' in headers:
                    tech_info['server'] = headers['server']
                
                # Framework detection
                if 'x-powered-by' in headers:
                    tech_info['framework'] = headers['x-powered-by']
                
                # Security headers
                security_headers = ['x-frame-options', 'x-content-type-options', 
                                  'x-xss-protection', 'strict-transport-security']
                tech_info['security_headers'] = {h: headers.get(h) for h in security_headers if h in headers}
        
        # Wappalyzer detection if available
        if WAPPALYZER_AVAILABLE:
            try:
                wappalyzer = Wappalyzer.latest()
                webpage = await WebPage.new_from_url(self.base_url)
                tech_info['wappalyzer'] = wappalyzer.analyze(webpage)
            except:
                pass
        
        self.results['technologies'] = tech_info

    async def extract_js_endpoints(self):
        """Extract endpoints from JavaScript files"""
        if not PLAYWRIGHT_AVAILABLE:
            print("[-] Playwright not available, skipping JS analysis")
            return
            
        print("[+] Extracting JavaScript endpoints...")
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                
                # Capture network requests
                requests = []
                page.on('request', lambda req: requests.append(req.url))
                
                await page.goto(self.base_url)
                await page.wait_for_timeout(3000)  # Wait for JS to load
                
                # Extract from script tags
                scripts = await page.query_selector_all('script[src]')
                for script in scripts:
                    src = await script.get_attribute('src')
                    if src:
                        full_url = urljoin(self.base_url, src)
                        endpoints = await self.analyze_js_file(full_url)
                        self.results['js_endpoints'].extend(endpoints)
                
                self.results['js_endpoints'].extend(requests)
                await browser.close()
                
        except Exception as e:
            print(f"[-] JS analysis failed: {e}")

    async def analyze_js_file(self, js_url):
        """Analyze JavaScript file for endpoints"""
        endpoints = set()
        try:
            async with await self.async_session() as session:
                async with session.get(js_url) as response:
                    content = await response.text()
                    
                    # Regex patterns for endpoints
                    patterns = [
                        r'[\'"]url[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]',
                        r'fetch\([\'"]([^\'"]+)[\'"]\)',
                        r'axios\.\w+\([\'"]([^\'"]+)[\'"]\)',
                        r'\.ajax\([^)]*[\'"]url[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        endpoints.update(matches)
                        
        except:
            pass
        
        return list(endpoints)

    def port_scan(self, target=None):
        """Basic port scanning"""
        if target is None:
            target = urlparse(self.base_url).netloc
            
        print(f"[+] Scanning ports for {target}...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_port, common_ports)
            open_ports = [port for port in results if port is not None]
        
        self.results['ports'] = open_ports
        return open_ports

    async def download_resources(self):
        """Download discovered resources"""
        print("[+] Downloading discovered resources...")
        download_dir = self.output_dir / "downloads"
        
        async with await self.async_session() as session:
            for resource_type, url in self.found_resources:
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            # Create safe filename
                            filename = urlparse(url).path.strip('/').replace('/', '_')
                            if not filename:
                                filename = 'index.html'
                            
                            filepath = download_dir / filename
                            content = await response.read()
                            
                            with open(filepath, 'wb') as f:
                                f.write(content)
                            
                            print(f"[DOWNLOADED] {url} -> {filepath}")
                            
                except Exception as e:
                    print(f"[-] Failed to download {url}: {e}")

    def run_external_tools(self):
        """Run external security tools"""
        tools = {
            'nmap': f"nmap -sV -T4 {urlparse(self.base_url).netloc}",
            'whatweb': f"whatweb {self.base_url}",
            'subfinder': f"subfinder -d {urlparse(self.base_url).netloc} -silent"
        }
        
        external_results = {}
        
        for tool, command in tools.items():
            try:
                print(f"[+] Running {tool}...")
                result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=300)
                external_results[tool] = result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
                external_results[tool] = f"Error: {str(e)}"
        
        return external_results

    def generate_report(self):
        """Generate comprehensive report"""
        print("[+] Generating report...")
        
        report_file = self.output_dir / f"scan_report_{self.scan_id}.json"
        
        # Prepare report data
        report_data = {
            'scan_info': {
                'target': self.base_url,
                'scan_id': self.scan_id,
                'timestamp': datetime.now().isoformat(),
                'total_found': len(self.found_resources)
            },
            'results': self.results,
            'summary': {
                'directories_found': len(self.results['directories']),
                'files_found': len(self.results['files']),
                'subdomains_found': len(self.results['subdomains']),
                'apis_found': len(self.results['apis']),
                'ports_open': len(self.results['ports']),
                'js_endpoints': len(self.results['js_endpoints'])
            }
        }
        
        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Generate text summary
        summary_file = self.output_dir / f"summary_{self.scan_id}.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Web Discovery Scan Report\n")
            f.write(f"="*50 + "\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Scan ID: {self.scan_id}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"\nSummary:\n")
            f.write(f"- Directories found: {len(self.results['directories'])}\n")
            f.write(f"- Files found: {len(self.results['files'])}\n")
            f.write(f"- Subdomains found: {len(self.results['subdomains'])}\n")
            f.write(f"- API endpoints: {len(self.results['apis'])}\n")
            f.write(f"- Open ports: {len(self.results['ports'])}\n")
            f.write(f"- JS endpoints: {len(self.results['js_endpoints'])}\n")
            
            f.write(f"\nTechnologies detected:\n")
            for tech, info in self.results['technologies'].items():
                f.write(f"- {tech}: {info}\n")
            
            f.write(f"\nCritical Findings:\n")
            critical_files = [f for f in self.results['files'] if any(x in f for x in ['admin', 'config', 'backup', '.env', '.sql'])]
            for file in critical_files:
                f.write(f"- {file}\n")
        
        print(f"[+] Report saved to {report_file}")
        print(f"[+] Summary saved to {summary_file}")

    async def comprehensive_scan(self, download=False, port_scan=False, external_tools=False):
        """Run comprehensive scan"""
        print(f"[+] Starting comprehensive scan of {self.base_url}")
        print(f"[+] Scan ID: {self.scan_id}")
        print(f"[+] Output directory: {self.output_dir}")
        
        start_time = time.time()
        
        # Run discovery techniques
        await asyncio.gather(
            self.discover_directories(),
            self.discover_files(),
            self.discover_subdomains(),
            self.discover_api_endpoints(),
            self.analyze_technologies(),
            self.extract_js_endpoints(),
            return_exceptions=True
        )
        
        # Port scanning (synchronous)
        if port_scan:
            self.port_scan()
        
        # External tools (synchronous)
        if external_tools:
            external_results = self.run_external_tools()
            self.results['external_tools'] = external_results
        
        # Download resources
        if download:
            await self.download_resources()
        
        # Generate report
        self.generate_report()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print(f"\n[+] Scan completed in {scan_duration:.2f} seconds")
        print(f"[+] Total resources found: {len(self.found_resources)}")
        
        # Print quick summary
        print("\n[QUICK SUMMARY]")
        print(f"Directories: {len(self.results['directories'])}")
        print(f"Files: {len(self.results['files'])}")
        print(f"Subdomains: {len(self.results['subdomains'])}")
        print(f"APIs: {len(self.results['apis'])}")
        print(f"Open ports: {len(self.results['ports'])}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Discovery Tool')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-d', '--download', action='store_true', help='Download discovered resources')
    parser.add_argument('-p', '--port-scan', action='store_true', help='Enable port scanning')
    parser.add_argument('-e', '--external-tools', action='store_true', help='Run external tools')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory')
    parser.add_argument('-x', '--timeout', type=int, default=10, help='Request timeout')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Create scanner instance
    scanner = AdvancedWebDiscoveryTool(
        base_url=args.url,
        max_threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output
    )
    
    try:
        # Run comprehensive scan
        results = asyncio.run(scanner.comprehensive_scan(
            download=args.download,
            port_scan=args.port_scan,
            external_tools=args.external_tools
        ))
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Banner
    print("""
    ╔═══════════════════════════════════════════════╗
    ║           Advanced Web Discovery Tool         ║
    ║           Comprehensive Security Scanner      ║
    ║                 Version 2.0                   ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    # Check if running with arguments
    if len(sys.argv) > 1:
        main()
    else:
        # Show usage examples
        print("Usage examples:")
        print("  python advanced_scanner.py https://example.com")
        print("  python advanced_scanner.py https://example.com -d -p -e")
        print("  python advanced_scanner.py https://example.com -t 50 -o my_scan")
        print("\nOptions:")
        print("  -d, --download        Download discovered resources")
        print("  -p, --port-scan       Enable port scanning")
        print("  -e, --external-tools  Run external security tools")
        print("  -t THREADS, --threads THREADS  Number of threads")
        print("  -o OUTPUT, --output OUTPUT  Output directory")
        print("  -x TIMEOUT, --timeout TIMEOUT  Request timeout")
        
        # Check dependencies
        print("\nDependency check:")
        print(f"  Playwright: {'Available' if PLAYWRIGHT_AVAILABLE else 'Not available (pip install playwright)'}")
        print(f"  Wappalyzer: {'Available' if WAPPALYZER_AVAILABLE else 'Not available (pip install python-wappalyzer)'}")
        print(f"  BuiltWith: {'Available' if BUILTWITH_AVAILABLE else 'Not available (pip install builtwith)'}")
        
        # Offer to install missing dependencies
        missing_deps = []
        if not PLAYWRIGHT_AVAILABLE:
            missing_deps.append("playwright")
        if not WAPPALYZER_AVAILABLE:
            missing_deps.append("python-wappalyzer")
        if not BUILTWITH_AVAILABLE:
            missing_deps.append("builtwith")
        
        if missing_deps:
            print(f"\nTo install missing dependencies:")
            print(f"  pip install {' '.join(missing_deps)}")
            if "playwright" in missing_deps:
                print("  playwright install chromium")
