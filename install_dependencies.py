#!/usr/bin/env python3
"""
Advanced Dependency Installer for Web Discovery Tool
Version: 2.0
Description: Automated dependency installation with advanced features
"""

import subprocess
import sys
import os
import platform
import time
import threading
from pathlib import Path
import urllib.request
import zipfile
import tarfile
import ssl

class DependencyInstaller:
    def __init__(self):
        self.system = platform.system().lower()
        self.python_version = sys.version_info
        self.install_log = []
        self.errors = []
        
        # Colors for output
        self.colors = {
            'RED': '\033[91m',
            'GREEN': '\033[92m',
            'YELLOW': '\033[93m',
            'BLUE': '\033[94m',
            'MAGENTA': '\033[95m',
            'CYAN': '\033[96m',
            'WHITE': '\033[97m',
            'RESET': '\033[0m',
            'BOLD': '\033[1m'
        }
        
    def print_banner(self):
        """Print installation banner"""
        banner = f"""
{self.colors['CYAN']}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║           🚀 Web Discovery Tool - Dependency Installer         ║
║                       Version 2.0                              ║
║                                                                ║
║            Advanced Web Security Scanner Setup                 ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{self.colors['RESET']}
"""
        print(banner)
    
    def check_python_version(self):
        """Check if Python version is compatible"""
        print(f"{self.colors['YELLOW']}[*] Checking Python version...{self.colors['RESET']}")
        
        if self.python_version.major < 3 or (self.python_version.major == 3 and self.python_version.minor < 8):
            print(f"{self.colors['RED']}[!] Python 3.8 or higher is required!{self.colors['RESET']}")
            print(f"[!] Current version: {self.python_version.major}.{self.python_version.minor}")
            return False
        else:
            print(f"{self.colors['GREEN']}[✓] Python {self.python_version.major}.{self.python_version.minor} is compatible{self.colors['RESET']}")
            return True
    
    def check_system_requirements(self):
        """Check system requirements"""
        print(f"\n{self.colors['YELLOW']}[*] Checking system requirements...{self.colors['RESET']}")
        
        # Check available disk space
        try:
            if self.system == 'windows':
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p('.'), None, None, ctypes.pointer(free_bytes))
                free_gb = free_bytes.value / (1024**3)
            else:
                stat = os.statvfs('.')
                free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            
            if free_gb < 1:
                print(f"{self.colors['RED']}[!] Low disk space: {free_gb:.2f} GB available (1 GB required){self.colors['RESET']}")
                return False
            else:
                print(f"{self.colors['GREEN']}[✓] Disk space: {free_gb:.2f} GB available{self.colors['RESET']}")
                
        except Exception as e:
            print(f"{self.colors['YELLOW']}[!] Could not check disk space: {e}{self.colors['RESET']}")
        
        return True
    
    def run_command(self, command, description, shell=False):
        """Run shell command with progress indication"""
        print(f"{self.colors['BLUE']}[*] {description}...{self.colors['RESET']}")
        
        def animate():
            chars = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']
            i = 0
            while not self.command_completed:
                print(f'\r{self.colors['CYAN']}[{chars[i % len(chars)]}] Working...{self.colors['RESET']}', end='', flush=True)
                i += 1
                time.sleep(0.1)
        
        self.command_completed = False
        animation_thread = threading.Thread(target=animate)
        animation_thread.daemon = True
        animation_thread.start()
        
        try:
            if shell:
                result = subprocess.run(command, shell=True, check=True, 
                                      capture_output=True, text=True, timeout=300)
            else:
                result = subprocess.run(command, check=True, 
                                      capture_output=True, text=True, timeout=300)
            
            self.command_completed = True
            print(f'\r{self.colors['GREEN']}[✓] {description} completed{self.colors['RESET']}')
            self.install_log.append(f"✓ {description}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.command_completed = True
            print(f'\r{self.colors['RED']}[✗] {description} failed{self.colors['RESET']}')
            print(f"Error: {e.stderr}")
            self.errors.append(f"✗ {description}: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self.command_completed = True
            print(f'\r{self.colors['RED']}[✗] {description} timed out{self.colors['RESET']}')
            self.errors.append(f"✗ {description}: Timeout")
            return False
    
    def install_pip_packages(self):
        """Install Python packages"""
        packages = [
            "aiohttp==3.9.1",
            "requests==2.31.0",
            "beautifulsoup4==4.12.2",
            "python-nmap==0.7.1",
            "pandas==2.0.3",
            "PyYAML==6.0.1",
            "dnspython==2.4.2",
            "urllib3==2.0.4",
            "colorama==0.4.6",
            "tqdm==4.65.0",
            "psutil==5.9.5",
            "netifaces==0.11.0"
        ]
        
        optional_packages = [
            "playwright==1.37.0",
            "python-wappalyzer==1.3.0",
            "builtwith==1.3.4",
            "selenium==4.11.2",
            "pymongo==4.5.0",
            "sqlalchemy==2.0.20",
            "pillow==10.0.0",
            "openpyxl==3.1.2"
        ]
        
        print(f"\n{self.colors['MAGENTA']}[*] Installing required packages...{self.colors['RESET']}")
        
        # Upgrade pip first
        self.run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], "Upgrading pip")
        
        # Install required packages
        for package in packages:
            self.run_command([sys.executable, "-m", "pip", "install", package], f"Installing {package}")
        
        print(f"\n{self.colors['MAGENTA']}[*] Installing optional packages...{self.colors['RESET']}")
        
        # Install optional packages
        for package in optional_packages:
            self.run_command([sys.executable, "-m", "pip", "install", package], f"Installing {package}")
    
    def install_playwright_browsers(self):
        """Install Playwright browsers"""
        print(f"\n{self.colors['MAGENTA']}[*] Installing Playwright browsers...{self.colors['RESET']}")
        
        browsers = ["chromium", "firefox", "webkit"]
        for browser in browsers:
            self.run_command([sys.executable, "-m", "playwright", "install", browser], 
                           f"Installing {browser} browser")
    
    def install_system_dependencies(self):
        """Install system-specific dependencies"""
        print(f"\n{self.colors['MAGENTA']}[*] Installing system dependencies...{self.colors['RESET']}")
        
        if self.system == "linux":
            # Ubuntu/Debian
            if os.path.exists("/etc/debian_version"):
                packages = ["nmap", "whatweb", "dnsutils", "net-tools"]
                self.run_command(f"sudo apt-get update && sudo apt-get install -y {' '.join(packages)}", 
                               "Installing Linux packages")
            
            # CentOS/RHEL
            elif os.path.exists("/etc/redhat-release"):
                packages = ["nmap", "whatweb", "bind-utils", "net-tools"]
                self.run_command(f"sudo yum install -y {' '.join(packages)}", 
                               "Installing Linux packages")
        
        elif self.system == "darwin":  # macOS
            self.run_command("brew update && brew install nmap whatweb", 
                           "Installing macOS packages")
        
        elif self.system == "windows":
            # Download Nmap for Windows
            nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
            nmap_installer = "nmap_setup.exe"
            
            print(f"{self.colors['YELLOW']}[*] Downloading Nmap for Windows...{self.colors['RESET']}")
            try:
                urllib.request.urlretrieve(nmap_url, nmap_installer)
                print(f"{self.colors['GREEN']}[✓] Nmap downloaded{self.colors['RESET']}")
                print(f"{self.colors['YELLOW']}[!] Please install Nmap manually from: {nmap_installer}{self.colors['RESET']}")
            except Exception as e:
                print(f"{self.colors['RED']}[!] Failed to download Nmap: {e}{self.colors['RESET']}")
    
    def create_wordlists(self):
        """Create comprehensive wordlists"""
        print(f"\n{self.colors['MAGENTA']}[*] Creating wordlists...{self.colors['RESET']}")
        
        wordlist_dir = Path("wordlists")
        wordlist_dir.mkdir(exist_ok=True)
        
        # Comprehensive directory wordlist
        directories = self.generate_directory_wordlist()
        with open(wordlist_dir / "directories.txt", "w") as f:
            f.write("\n".join(directories))
        print(f"{self.colors['GREEN']}[✓] Created directories.txt with {len(directories)} entries{self.colors['RESET']}")
        
        # Subdomain wordlist
        subdomains = self.generate_subdomain_wordlist()
        with open(wordlist_dir / "subdomains.txt", "w") as f:
            f.write("\n".join(subdomains))
        print(f"{self.colors['GREEN']}[✓] Created subdomains.txt with {len(subdomains)} entries{self.colors['RESET']}")
        
        # API patterns wordlist
        api_patterns = self.generate_api_wordlist()
        with open(wordlist_dir / "api_patterns.txt", "w") as f:
            f.write("\n".join(api_patterns))
        print(f"{self.colors['GREEN']}[✓] Created api_patterns.txt with {len(api_patterns)} entries{self.colors['RESET']}")
        
        # File extensions wordlist
        file_extensions = self.generate_file_extensions()
        with open(wordlist_dir / "file_extensions.txt", "w") as f:
            f.write("\n".join(file_extensions))
        print(f"{self.colors['GREEN']}[✓] Created file_extensions.txt with {len(file_extensions)} entries{self.colors['RESET']}")
    
    def generate_directory_wordlist(self):
        """Generate comprehensive directory wordlist"""
        base_dirs = [
            'admin', 'administrator', 'backend', 'api', 'service', 'sql', 'database',
            'config', 'include', 'inc', 'lib', 'src', 'handlers', 'handler', 'uploads',
            'files', 'data', 'log', 'logs', 'temp', 'tmp', 'backup', 'old', 'new', 'dev',
            'test', 'staging', 'prod', 'web', 'www', 'public', 'private', 'secure', 'auth',
            'login', 'logout', 'register', 'signup', 'signin', 'dashboard', 'panel',
            'control', 'manager', 'system', 'app', 'application', 'portal', 'cms',
            'content', 'media', 'assets', 'static', 'images', 'img', 'css', 'js',
            'scripts', 'styles', 'fonts', 'download', 'uploads', 'export', 'import',
            'backup', 'restore', 'recovery', 'trash', 'bin', 'cache', 'temp', 'tmp',
            'session', 'sessions', 'user', 'users', 'member', 'members', 'account',
            'accounts', 'profile', 'profiles', 'settings', 'options', 'preferences',
            'configs', 'configuration', 'setup', 'install', 'installation', 'update',
            'upgrade', 'patch', 'debug', 'test', 'testing', 'demo', 'sample', 'example',
            'doc', 'docs', 'documentation', 'help', 'support', 'faq', 'contact', 'about',
            'info', 'information', 'status', 'health', 'metrics', 'stats', 'statistics',
            'analytics', 'monitor', 'monitoring', 'log', 'logs', 'audit', 'auditing',
            'security', 'secure', 'protected', 'private', 'hidden', 'secret', 'keys',
            'token', 'tokens', 'auth', 'authentication', 'authorization', 'oauth',
            'sso', 'ldap', 'ad', 'active-directory', 'kerberos', 'saml', 'openid',
            'jwt', 'api-key', 'apikey', 'credentials', 'password', 'passwords', 'hash',
            'hashes', 'encryption', 'crypto', 'cryptography', 'ssl', 'tls', 'cert',
            'certificate', 'ca', 'pki', 'vpn', 'proxy', 'gateway', 'firewall', 'waf',
            'ids', 'ips', 'siem', 'soc', 'monitor', 'monitoring', 'alert', 'alerts',
            'incident', 'incidents', 'response', 'ir', 'forensics', 'dfir', 'threat',
            'threats', 'intelligence', 'ti', 'ioc', 'iocs', 'malware', 'virus', 'viruses',
            'ransomware', 'trojan', 'trojans', 'worm', 'worms', 'botnet', 'botnets',
            'exploit', 'exploits', 'vulnerability', 'vulnerabilities', 'cve', 'cves',
            'patch', 'patches', 'update', 'updates', 'upgrade', 'upgrades', 'version',
            'versions', 'release', 'releases', 'build', 'builds', 'deploy', 'deployment',
            'ci', 'cd', 'pipeline', 'pipelines', 'jenkins', 'gitlab', 'github', 'bitbucket',
            'docker', 'kubernetes', 'k8s', 'helm', 'terraform', 'ansible', 'puppet',
            'chef', 'salt', 'vagrant', 'virtualbox', 'vmware', 'hyperv', 'aws', 'azure',
            'gcp', 'google', 'cloud', 'cloudformation', 'terraform', 'serverless',
            'lambda', 'functions', 'microservices', 'containers', 'pods', 'nodes',
            'cluster', 'clusters', 'namespace', 'namespaces', 'deployment', 'deployments',
            'service', 'services', 'ingress', 'ingresses', 'configmap', 'configmaps',
            'secret', 'secrets', 'volume', 'volumes', 'storage', 'database', 'databases',
            'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'kibana',
            'logstash', 'filebeat', 'metricbeat', 'packetbeat', 'heartbeat', 'auditbeat',
            'journalbeat', 'functionbeat', 'communitybeat', 'xpack', 'security', 'monitoring',
            'alerting', 'reporting', 'dashboard', 'visualize', 'discover', 'canvas',
            'maps', 'machinelearning', 'graph', 'uptime', 'apm', 'infrastructure', 'logs',
            'metrics', 'traces', 'profiling', 'siem', 'endpoint', 'cloud', 'beats',
            'agent', 'agents', 'fleet', 'integrations', 'savedobjects', 'indexpatterns',
            'index-patterns', 'templates', 'component-templates', 'index-templates',
            'ilm-policies', 'rollup', 'transform', 'snapshot', 'restore', 'reindex',
            'shrink', 'split', 'forcemerge', 'upgrade', 'migration', 'migrations',
            'upgrade-assistant', 'remote-clusters', 'cross-cluster-search', 'ccs',
            'ccr', 'cross-cluster-replication', 'security', 'roles', 'users', 'api-keys',
            'tokens', 'privileges', 'permissions', 'policies', 'realms', 'providers',
            'saml', 'oidc', 'kerberos', 'pki', 'jwt', 'native', 'file', 'ldap', 'ad',
            'active-directory', 'anonymous', 'custom', 'internal', 'reserved', 'built-in'
        ]
        
        # Add variations
        variations = []
        for base in base_dirs:
            variations.extend([
                base,
                f"{base}-v1",
                f"{base}-v2",
                f"{base}-v3",
                f"{base}-old",
                f"{base}-new",
                f"{base}-backup",
                f"{base}-test",
                f"{base}-dev",
                f"{base}-prod",
                f"{base}-staging",
                f"{base}-live",
                f"{base}-demo"
            ])
        
        return list(set(variations))
    
    def generate_subdomain_wordlist(self):
        """Generate comprehensive subdomain wordlist"""
        base_subs = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'backup', 'mail', 'ftp',
            'cpanel', 'webmail', 'blog', 'shop', 'store', 'cdn', 'assets', 'media',
            'static', 'app', 'mobile', 'secure', 'portal', 'gateway', 'vpn', 'proxy',
            'ns1', 'ns2', 'ns3', 'ns4', 'mail1', 'mail2', 'smtp', 'pop', 'imap',
            'forum', 'community', 'support', 'help', 'docs', 'wiki', 'knowledgebase',
            'download', 'uploads', 'files', 'data', 'db', 'database', 'sql', 'mysql',
            'postgres', 'mongodb', 'redis', 'elasticsearch', 'kibana', 'logstash',
            'grafana', 'prometheus', 'alertmanager', 'node-exporter', 'blackbox',
            'pushgateway', 'thanos', 'cortex', 'loki', 'tempo', 'jaeger', 'zipkin',
            'opentelemetry', 'otel', 'collector', 'agent', 'fleet', 'integrations',
            'apm', 'rum', 'synthetics', 'heartbeat', 'uptime', 'monitoring', 'alerting',
            'reporting', 'dashboard', 'visualize', 'discover', 'canvas', 'maps',
            'machinelearning', 'graph', 'security', 'siem', 'endpoint', 'cloud',
            'beats', 'functionbeat', 'communitybeat', 'xpack', 'stack', 'elastic',
            'kibana', 'logstash', 'beats', 'agent', 'agents', 'fleet', 'integrations',
            'savedobjects', 'indexpatterns', 'index-patterns', 'templates',
            'component-templates', 'index-templates', 'ilm-policies', 'rollup',
            'transform', 'snapshot', 'restore', 'reindex', 'shrink', 'split',
            'forcemerge', 'upgrade', 'migration', 'migrations', 'upgrade-assistant',
            'remote-clusters', 'cross-cluster-search', 'ccs', 'ccr',
            'cross-cluster-replication', 'security', 'roles', 'users', 'api-keys',
            'tokens', 'privileges', 'permissions', 'policies', 'realms', 'providers',
            'saml', 'oidc', 'kerberos', 'pki', 'jwt', 'native', 'file', 'ldap', 'ad',
            'active-directory', 'anonymous', 'custom', 'internal', 'reserved', 'built-in'
        ]
        
        # Add number variations
        variations = []
        for base in base_subs:
            variations.extend([
                base,
                f"{base}1",
                f"{base}2",
                f"{base}3",
                f"{base}01",
                f"{base}02",
                f"{base}03"
            ])
        
        return list(set(variations))
    
    def generate_api_wordlist(self):
        """Generate API patterns wordlist"""
        return [
            'api', 'api/v1', 'api/v2', 'api/v3', 'api/v4', 'rest', 'rest/api',
            'graphql', 'gql', 'oauth', 'oauth2', 'auth', 'authentication',
            'token', 'jwt', 'session', 'login', 'logout', 'register', 'signup',
            'user', 'users', 'profile', 'profiles', 'account', 'accounts',
            'admin', 'administrator', 'moderator', 'manager', 'superuser',
            'product', 'products', 'item', 'items', 'catalog', 'inventory',
            'order', 'orders', 'cart', 'checkout', 'payment', 'payments',
            'customer', 'customers', 'client', 'clients', 'partner', 'partners',
            'document', 'documents', 'file', 'files', 'upload', 'download',
            'image', 'images', 'video', 'videos', 'audio', 'audios',
            'message', 'messages', 'chat', 'notification', 'notifications',
            'settings', 'configuration', 'config', 'preferences', 'options',
            'system', 'health', 'status', 'metrics', 'analytics', 'stats',
            'log', 'logs', 'audit', 'monitor', 'alert', 'report', 'export',
            'import', 'backup', 'restore', 'migrate', 'sync', 'webhook',
            'callback', 'hook', 'event', 'events', 'queue', 'task', 'tasks',
            'job', 'jobs', 'worker', 'workers', 'service', 'services',
            'microservice', 'microservices', 'function', 'functions',
            'lambda', 'endpoint', 'endpoints', 'resource', 'resources'
        ]
    
    def generate_file_extensions(self):
        """Generate file extensions wordlist"""
        return [
            '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.jspx',
            '.py', '.rb', '.pl', '.cgi', '.sql', '.json', '.xml', '.yml',
            '.yaml', '.ini', '.cfg', '.conf', '.bak', '.old', '.tmp',
            '.log', '.txt', '.md', '.rst', '.csv', '.tsv', '.xls', '.xlsx',
            '.doc', '.docx', '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.swf',
            '.exe', '.msi', '.dmg', '.pkg', '.deb', '.rpm', '.apk'
        ]
    
    def generate_config_files(self):
        """Generate configuration files"""
        print(f"\n{self.colors['MAGENTA']}[*] Creating configuration files...{self.colors['RESET']}")
        
        # Create config directory
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        # Main configuration file
        config_content = {
            "scanning": {
                "max_threads": 50,
                "timeout": 10,
                "user_agent": "Mozilla/5.0 (compatible; AdvancedWebScanner/2.0)",
                "follow_redirects": True,
                "verify_ssl": False
            },
            "wordlists": {
                "directories": "wordlists/directories.txt",
                "subdomains": "wordlists/subdomains.txt",
                "api_patterns": "wordlists/api_patterns.txt",
                "file_extensions": "wordlists/file_extensions.txt"
            },
            "plugins": {
                "enabled": ["sql_injection", "xss_detector", "lfi_scanner"],
                "scanning_depth": "medium"
            },
            "reporting": {
                "format": ["json", "html", "txt"],
                "output_dir": "scan_results",
                "save_downloads": True
            }
        }
        
        with open(config_dir / "scanner_config.yaml", "w") as f:
            yaml.dump(config_content, f, default_flow_style=False)
        
        print(f"{self.colors['GREEN']}[✓] Created scanner configuration{self.colors['RESET']}")
    
    def run_health_check(self):
        """Run health check to verify installation"""
        print(f"\n{self.colors['MAGENTA']}[*] Running health check...{self.colors['RESET']}")
        
        health_checks = [
            ("Python version", lambda: sys.version_info >= (3, 8)),
            ("aiohttp", lambda: self.check_module("aiohttp")),
            ("requests", lambda: self.check_module("requests")),
            ("beautifulsoup4", lambda: self.check_module("bs4")),
            ("pandas", lambda: self.check_module("pandas")),
        ]
        
        all_passed = True
        for check_name, check_func in health_checks:
            try:
                if check_func():
                    print(f"{self.colors['GREEN']}[✓] {check_name}: OK{self.colors['RESET']}")
                else:
                    print(f"{self.colors['RED']}[✗] {check_name}: FAILED{self.colors['RESET']}")
                    all_passed = False
            except Exception as e:
                print(f"{self.colors['RED']}[✗] {check_name}: ERROR - {e}{self.colors['RESET']}")
                all_passed = False
        
        return all_passed
    
    def check_module(self, module_name):
        """Check if a module can be imported"""
        try:
            __import__(module_name)
            return True
        except ImportError:
            return False
    
    def print_summary(self):
        """Print installation summary"""
        print(f"\n{self.colors['CYAN']}{'='*60}{self.colors['RESET']}")
        print(f"{self.colors['BOLD']}{self.colors['WHITE']}INSTALLATION SUMMARY{self.colors['RESET']}")
        print(f"{self.colors['CYAN']}{'='*60}{self.colors['RESET']}")
        
        for log_entry in self.install_log:
            if log_entry.startswith("✓"):
                print(f"{self.colors['GREEN']}{log_entry}{self.colors['RESET']}")
            else:
                print(f"{self.colors['YELLOW']}{log_entry}{self.colors['RESET']}")
        
        if self.errors:
            print(f"\n{self.colors['RED']}{'='*60}{self.colors['RESET']}")
            print(f"{self.colors['BOLD']}ERRORS ENCOUNTERED:{self.colors['RESET']}")
            for error in self.errors:
                print(f"{self.colors['RED']}{error}{self.colors['RESET']}")
        
        print(f"\n{self.colors['GREEN']}{'='*60}{self.colors['RESET']}")
        print(f"{self.colors['BOLD']}NEXT STEPS:{self.colors['RESET']}")
        print(f"1. Run: python advanced_scanner.py https://example.com")
        print(f"2. Check the 'wordlists/' directory for customization")
        print(f"3. Review 'config/scanner_config.yaml' for settings")
        print(f"4. Explore the 'plugins/' directory for additional features")
        print(f"{self.colors['GREEN']}{'='*60}{self.colors['RESET']}")
    
    def install(self):
        """Main installation method"""
        self.print_banner()
        
        if not self.check_python_version():
            return False
        
        if not self.check_system_requirements():
            return False
        
        self.install_pip_packages()
        self.install_playwright_browsers()
        self.install_system_dependencies()
        self.create_wordlists()
        self.generate_config_files()
        
        health_ok = self.run_health_check()
        self.print_summary()
        
        return health_ok and len(self.errors) == 0

def main():
    """Main function"""
    installer = DependencyInstaller()
    
    try:
        success = installer.install()
        if success:
            print(f"\n{installer.colors['BOLD']}{installer.colors['GREEN']}🎉 Installation completed successfully!{installer.colors['RESET']}")
            sys.exit(0)
        else:
            print(f"\n{installer.colors['BOLD']}{installer.colors['RED']}❌ Installation completed with errors.{installer.colors['RESET']}")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{installer.colors['YELLOW']}[!] Installation interrupted by user.{installer.colors['RESET']}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{installer.colors['RED']}[!] Unexpected error: {e}{installer.colors['RESET']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
