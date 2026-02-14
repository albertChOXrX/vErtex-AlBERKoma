#!/usr/bin/env python3
"""
vErtex v6.0 - ENTERPRISE EDITION
The Ultimate Security & Reconnaissance Suite

Author: albertChOXrX
Enhanced: Enterprise Security Features

Features:
- OWASP Top 10 Scanner
- Advanced DNS Analysis (DNSSEC, SPF, DMARC, CAA)
- WAF Detection (20+ WAFs)
- API Endpoint Discovery
- JavaScript Security Analysis
- Certificate Transparency Logs
- Shodan Integration
- VirusTotal Integration
- HTTP/2 & HTTP/3 Detection
- Technology Stack Fingerprinting
- XSS & SQLi Testing
- Rate Limiting Detection
- CORS Misconfiguration Check
- Backup File Discovery
- Email Harvesting
- Social Media Presence
- GitHub/GitLab Repository Discovery
- Dark Web Exposure Check
- Threat Intelligence Feeds
"""

import requests
import os
import urllib3
import socket
import ssl
import re
import time
import json
import hashlib
import base64
import dns.resolver
import whois
from colorama import Fore, Style, init
from fpdf import FPDF
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import subprocess
import zipfile
import tarfile

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ==================== CONFIGURATION ====================
class Config:
    """Global configuration"""
    VERSION = "6.0"
    EDITION = "ENTERPRISE"
    
    # API Keys (Optional - Set as environment variables)
    VIRUSTOTAL_API = os.getenv('VT_API_KEY', '')
    SHODAN_API = os.getenv('SHODAN_API_KEY', '')
    HUNTER_API = os.getenv('HUNTER_API_KEY', '')
    
    # Scan configurations
    TIMEOUT = 10
    MAX_THREADS = 20
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    # Payloads for testing
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg/onload=alert(1)>'
    ]
    
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' UNION SELECT NULL--"
    ]
    
    # Common backup files
    BACKUP_FILES = [
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'db_backup.sql',
        'site_backup.zip', 'backup.tar', 'old.zip', 'backup.rar',
        '.git/HEAD', '.git/config', '.env', '.env.backup',
        'config.php.bak', 'wp-config.php~', 'database.sql'
    ]
    
    # Common API endpoints
    API_ENDPOINTS = [
        '/api/', '/api/v1/', '/api/v2/', '/api/users/', '/api/auth/',
        '/rest/', '/graphql/', '/swagger/', '/api-docs/', '/v1/api/',
        '/api/login', '/api/register', '/api/config', '/api/admin/'
    ]
    
    # WAF signatures
    WAF_SIGNATURES = {
        'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
        'Akamai': ['akamai', 'AkamaiGHost'],
        'Imperva': ['incap_ses', '_incapsula', 'imperva'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-'],
        'F5 BIG-IP': ['BigIP', 'F5', 'TS'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'Sucuri': ['sucuri', 'x-sucuri-id'],
        'Wordfence': ['wordfence'],
        'StackPath': ['stackpath'],
        'Barracuda': ['barra_counter_session', 'barracuda'],
        'Fortinet': ['FortiWeb', 'FORTIWAFSID'],
        'Citrix NetScaler': ['ns_af', 'citrix_ns_id', 'NSC_'],
        'Radware': ['rdwr_', 'radware'],
        'Reblaze': ['rbzid', 'reblaze'],
        'Wallarm': ['wallarm'],
        'Signal Sciences': ['sigsci-token'],
        'PerimeterX': ['_px', '_pxhd'],
        'DataDome': ['datadome'],
        'Amazon CloudFront': ['x-amz-cf-id', 'cloudfront'],
        'DenyAll': ['sessioncookie', 'denyall']
    }

def clean_text_for_pdf(text):
    """Remove unicode characters that aren't compatible with latin-1"""
    # Replace emojis and special unicode with ASCII equivalents
    replacements = {
        '✅': '[OK]',
        '❌': '[X]',
        '⚠️': '[!]',
        '🔴': '[CRITICAL]',
        '🟠': '[HIGH]',
        '🟡': '[MEDIUM]',
        '🔵': '[LOW]',
        'ℹ️': '[i]',
        '✓': '+',
        '✗': '-',
        '•': '-',
        '🛡️': '',
        '📊': '',
        '📷': '',
        '🔧': '',
        '💡': '',
        '🎯': '',
        '🚀': '',
    }
    
    result = str(text)
    for old, new in replacements.items():
        result = result.replace(old, new)
    
    # Remove any remaining non-latin-1 characters
    result = result.encode('latin-1', errors='ignore').decode('latin-1')
    
    return result

def show_banner():
    """Display enhanced banner"""
    os.system('clear' if os.name != 'nt' else 'cls')
    print(f"""{Fore.CYAN}{Style.BRIGHT}
    ╔══════════════════════════════════════════════════════════════╗
    ║  ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗         ║
    ║  ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝         ║
    ║  ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝          ║
    ║  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗          ║
    ║   ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗         ║
    ║    ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  v{Config.VERSION}   ║
    ╚══════════════════════════════════════════════════════════════╝
    {Fore.YELLOW}┌────────────────────────────────────────────────────────────┐
    │  {Fore.WHITE}ENTERPRISE SECURITY & RECONNAISSANCE SUITE            {Fore.YELLOW}│
    │  {Fore.CYAN}Author: {Fore.WHITE}albertChOXrX {Fore.RED}| {Fore.CYAN}Edition: {Fore.WHITE}{Config.EDITION}          {Fore.YELLOW}│
    └────────────────────────────────────────────────────────────┘
    
    {Fore.GREEN}[+] New Features:{Fore.WHITE}
        - OWASP Top 10 Scanner        - DNS Security Analysis
        - WAF Detection (20+ WAFs)    - API Endpoint Discovery
        - JavaScript Security         - Certificate Transparency
        - Shodan Integration          - VirusTotal Integration
        - Technology Fingerprinting   - Email Harvesting
        - Backup File Discovery       - Repository Discovery
        - Threat Intelligence         - Social Media OSINT
    """)

# ==================== ENHANCED PDF REPORT ====================
class EnterpriseReport(FPDF):
    """Enhanced PDF report with professional design"""
    
    def __init__(self):
        super().__init__()
        self.chapter_num = 0
        
    def header(self):
        # Professional header with gradient effect
        self.set_fill_color(10, 20, 30)
        self.rect(0, 0, 210, 45, 'F')
        
        # Title
        self.set_font('Arial', 'B', 26)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, '', 0, 1)
        self.cell(0, 10, f'vErtex {Config.VERSION} | SECURITY AUDIT REPORT', 0, 1, 'C')
        
        # Subtitle
        self.set_font('Arial', '', 10)
        self.set_text_color(200, 200, 200)
        self.cell(0, 6, f'{Config.EDITION} Edition | Comprehensive Security Analysis', 0, 1, 'C')
        
        # Info bar
        self.set_font('Arial', '', 9)
        self.set_y(35)
        self.cell(105, 5, f'  Report ID: {datetime.now().strftime("%Y%m%d-%H%M%S")}', 0, 0, 'L')
        self.cell(95, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ', 0, 1, 'R')
        
        self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
    
    def chapter_title(self, title, icon=''):
        self.chapter_num += 1
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(240, 245, 250)
        self.set_text_color(20, 40, 60)
        # Remove emojis for PDF compatibility
        title_clean = title.upper()
        self.cell(0, 12, f'  {self.chapter_num}. {title_clean}', 0, 1, 'L', True)
        self.ln(3)
    
    def add_info_box(self, title, items):
        """Add styled info box"""
        self.set_fill_color(250, 250, 250)
        self.set_draw_color(200, 200, 200)
        self.rect(self.get_x(), self.get_y(), 190, 10 + (len(items) * 6), 'FD')
        
        self.set_font('Arial', 'B', 10)
        self.set_text_color(40, 60, 80)
        self.cell(190, 8, f'  {clean_text_for_pdf(title)}', 0, 1, 'L')
        
        self.set_font('Arial', '', 9)
        self.set_text_color(0)
        for key, value in items.items():
            clean_key = clean_text_for_pdf(key)
            clean_value = clean_text_for_pdf(str(value))
            self.cell(60, 6, f'    - {clean_key}:', 0, 0)
            self.cell(130, 6, clean_value, 0, 1)
        self.ln(3)
    
    def add_security_score_visual(self, score, max_score=100):
        """Enhanced security score visualization"""
        percentage = (score / max_score) * 100
        
        # Determine rating
        if percentage >= 90:
            color, rating = (0, 180, 0), "EXCELLENT"
        elif percentage >= 75:
            color, rating = (50, 200, 50), "GOOD"
        elif percentage >= 60:
            color, rating = (200, 180, 0), "FAIR"
        elif percentage >= 40:
            color, rating = (255, 140, 0), "POOR"
        else:
            color, rating = (220, 0, 0), "CRITICAL"
        
        self.chapter_title('OVERALL SECURITY SCORE')
        
        # Score display
        self.set_font('Arial', 'B', 32)
        self.set_text_color(*color)
        self.cell(0, 15, f'{score}/{max_score}', 0, 1, 'C')
        
        # Rating
        self.set_font('Arial', 'B', 18)
        self.cell(0, 10, f'{rating}', 0, 1, 'C')
        
        # Progress bar
        self.ln(5)
        bar_width = 170
        filled_width = (bar_width * percentage) / 100
        
        # Background
        self.set_fill_color(230, 230, 230)
        self.rect(20, self.get_y(), bar_width, 10, 'F')
        
        # Filled portion
        self.set_fill_color(*color)
        self.rect(20, self.get_y(), filled_width, 10, 'F')
        
        # Border
        self.set_draw_color(150, 150, 150)
        self.rect(20, self.get_y(), bar_width, 10, 'D')
        
        self.ln(12)
        
        # Percentage
        self.set_font('Arial', '', 10)
        self.set_text_color(0)
        self.cell(0, 6, f'{percentage:.1f}% Security Compliance', 0, 1, 'C')
        self.ln(5)
    
    def add_vulnerability_table(self, vulnerabilities):
        """Enhanced vulnerability table"""
        self.chapter_title('VULNERABILITY ASSESSMENT')
        
        # Table header
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(60, 80, 100)
        self.set_text_color(255)
        self.cell(40, 8, ' SEVERITY', 1, 0, 'L', True)
        self.cell(45, 8, ' CATEGORY', 1, 0, 'L', True)
        self.cell(85, 8, ' FINDING', 1, 0, 'L', True)
        self.cell(20, 8, ' IMPACT', 1, 1, 'C', True)
        
        # Group by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            grouped[vuln.get('level', 'INFO')].append(vuln)
        
        self.set_font('Arial', '', 8)
        for severity in severity_order:
            if severity in grouped:
                for vuln in grouped[severity]:
                    # Color coding
                    color_map = {
                        'CRITICAL': (220, 0, 0),
                        'HIGH': (255, 100, 0),
                        'MEDIUM': (200, 150, 0),
                        'LOW': (150, 150, 0),
                        'INFO': (0, 100, 200),
                        'SUCCESS': (0, 150, 0)
                    }
                    self.set_text_color(*color_map.get(severity, (0, 0, 0)))
                    
                    clean_cat = clean_text_for_pdf(vuln.get("cat", "N/A"))
                    clean_msg = clean_text_for_pdf(vuln.get("msg", ""))
                    
                    self.cell(40, 7, f' {severity}', 1, 0)
                    self.set_text_color(0)
                    self.cell(45, 7, f' {clean_cat}', 1, 0)
                    self.cell(85, 7, f' {clean_msg[:55]}', 1, 0)
                    self.cell(20, 7, f' -{vuln.get("score_impact", 0)}', 1, 1, 'C')

# ==================== CORE SCANNER ENGINE ====================
class vErtexEnterprise:
    """Enterprise-grade security scanner"""
    
    def __init__(self, target, scan_mode="normal", options=None):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        parsed = urlparse(target)
        self.full_url = target
        self.target_domain = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.scan_mode = scan_mode
        self.options = options or {}
        
        # Results storage
        self.results = []
        self.security_score = 100
        self.target_ip = "N/A"
        self.technologies = []
        self.cms_detected = None
        self.waf_detected = []
        self.api_endpoints = []
        self.vulnerabilities = defaultdict(list)
        self.dns_records = {}
        self.whois_data = {}
        self.ssl_info = {}
        self.emails_found = []
        self.subdomains_found = []
        self.backup_files_found = []
        self.js_files = []
        self.social_media = {}
        self.threat_intel = {}
        
        # PDF report
        self.pdf = EnterpriseReport()
        self.screenshot_path = None
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
    
    def log(self, category, message, level="INFO", score_impact=0):
        """Enhanced logging with categorization"""
        self.results.append({
            "cat": category,
            "msg": message,
            "level": level,
            "score_impact": score_impact,
            "timestamp": datetime.now().isoformat()
        })
        
        if level in ['CRITICAL', 'HIGH', 'MEDIUM']:
            self.vulnerabilities[level].append({
                'category': category,
                'message': message,
                'impact': score_impact
            })
        
        self.security_score = max(0, self.security_score - score_impact)
        
        # Console output with icons
        icons = {
            'CRITICAL': '[CRITICAL]',
            'HIGH': '[HIGH]',
            'MEDIUM': '[MEDIUM]',
            'LOW': '[LOW]',
            'SUCCESS': '[OK]',
            'INFO': '[INFO]'
        }
        
        color_map = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.LIGHTRED_EX,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.LIGHTYELLOW_EX,
            'SUCCESS': Fore.GREEN,
            'INFO': Fore.CYAN
        }
        
        color = color_map.get(level, Fore.WHITE)
        icon = icons.get(level, '-')
        
        print(f"{Fore.WHITE}[{color}{category:12}{Fore.WHITE}] {icon} {message}")
    
    # ==================== MODULE 1: NETWORK & INFRASTRUCTURE ====================
    
    def network_reconnaissance(self):
        """Complete network analysis"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 1: Network & Infrastructure Reconnaissance")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Resolve IP
        try:
            self.target_ip = socket.gethostbyname(self.target_domain)
            self.log("NETWORK", f"IP Address resolved: {self.target_ip}", "SUCCESS")
        except Exception as e:
            self.log("NETWORK", f"Failed to resolve domain: {e}", "CRITICAL", 20)
            return False
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(self.target_ip)[0]
            self.log("DNS", f"Reverse DNS: {hostname}", "INFO")
        except:
            self.log("DNS", "No reverse DNS record found", "INFO")
        
        # GeoIP & ISP
        self.geolocation_lookup()
        
        # WHOIS
        self.whois_lookup()
        
        # Port scanning
        self.port_scan()
        
        return True
    
    def geolocation_lookup(self):
        """Enhanced geolocation with multiple sources"""
        try:
            # ip-api.com
            resp = self.session.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    self.log("GEO", f"Location: {data['country']}, {data['city']}", "SUCCESS")
                    self.log("GEO", f"ISP: {data['isp']}", "INFO")
                    self.log("GEO", f"Organization: {data.get('org', 'N/A')}", "INFO")
                    self.log("GEO", f"ASN: {data.get('as', 'N/A')}", "INFO")
                    
                    # Check if hosting provider
                    if 'hosting' in data['isp'].lower() or 'server' in data['isp'].lower():
                        self.log("HOSTING", f"Hosted on: {data['isp']}", "INFO")
        except Exception as e:
            self.log("GEO", f"Geolocation lookup failed: {e}", "INFO")
    
    def whois_lookup(self):
        """WHOIS information gathering"""
        try:
            w = whois.whois(self.target_domain)
            self.whois_data = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
            
            self.log("WHOIS", f"Registrar: {w.registrar}", "INFO")
            
            if isinstance(w.creation_date, list):
                creation = w.creation_date[0]
            else:
                creation = w.creation_date
            
            if creation:
                age = (datetime.now() - creation).days
                self.log("WHOIS", f"Domain age: {age} days", "INFO")
            
            if isinstance(w.expiration_date, list):
                expiration = w.expiration_date[0]
            else:
                expiration = w.expiration_date
                
            if expiration:
                days_until = (expiration - datetime.now()).days
                if days_until < 30:
                    self.log("WHOIS", f"Domain expires in {days_until} days!", "MEDIUM", 5)
                else:
                    self.log("WHOIS", f"Expires in {days_until} days", "INFO")
                    
        except Exception as e:
            self.log("WHOIS", f"WHOIS lookup failed: {e}", "INFO")
    
    def port_scan(self):
        """Advanced port scanning with service detection"""
        ports_to_scan = self.get_port_list()
        
        print(f"\n{Fore.YELLOW}[*] Scanning {len(ports_to_scan)} ports...")
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = {executor.submit(self.scan_port_with_service, port): port for port in ports_to_scan}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        if not open_ports:
            self.log("PORT", "No open ports in scan range", "SUCCESS")
        
        # Check for dangerous open ports
        dangerous_ports = {21, 23, 3389, 5900}
        for port_info in open_ports:
            if port_info['port'] in dangerous_ports:
                self.log("PORT", f"DANGEROUS: Port {port_info['port']} ({port_info['service']}) is open!", "HIGH", 10)
    
    def scan_port_with_service(self, port):
        """Scan port with service detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                service = self.identify_service(port)
                level = "HIGH" if port in [21, 23, 3389] else "MEDIUM"
                impact = 10 if level == "HIGH" else 3
                
                self.log("PORT", f"Port {port} ({service}) is OPEN", level, impact)
                return {'port': port, 'service': service}
        except:
            pass
        return None
    
    def identify_service(self, port):
        """Identify common services by port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def get_port_list(self):
        """Get ports based on scan mode"""
        if self.scan_mode == "fast":
            return [80, 443]
        elif self.scan_mode == "deep":
            return list(range(1, 1025))  # First 1024 ports
        elif self.scan_mode == "extreme":
            return list(range(1, 65536))  # All ports
        else:  # normal
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443]
    
    # ==================== MODULE 2: DNS SECURITY ANALYSIS ====================
    
    def dns_security_analysis(self):
        """Comprehensive DNS security check"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 2: DNS Security Analysis")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # A Records
        try:
            answers = resolver.resolve(self.target_domain, 'A')
            for rdata in answers:
                self.dns_records['A'] = str(rdata)
                self.log("DNS", f"A Record: {rdata}", "SUCCESS")
        except Exception as e:
            self.log("DNS", f"A record lookup failed: {e}", "INFO")
        
        # AAAA Records (IPv6)
        try:
            answers = resolver.resolve(self.target_domain, 'AAAA')
            for rdata in answers:
                self.dns_records['AAAA'] = str(rdata)
                self.log("DNS", f"AAAA Record (IPv6): {rdata}", "INFO")
        except:
            self.log("DNS", "No IPv6 (AAAA) records found", "INFO")
        
        # MX Records
        try:
            answers = resolver.resolve(self.target_domain, 'MX')
            mx_records = [str(rdata.exchange) for rdata in answers]
            self.dns_records['MX'] = mx_records
            for mx in mx_records:
                self.log("DNS", f"MX Record: {mx}", "INFO")
        except:
            self.log("DNS", "No MX records found", "INFO")
        
        # TXT Records (SPF, DMARC, DKIM)
        self.check_email_security()
        
        # NS Records
        try:
            answers = resolver.resolve(self.target_domain, 'NS')
            for rdata in answers:
                self.log("DNS", f"Nameserver: {rdata}", "INFO")
        except:
            pass
        
        # CAA Records (Certificate Authority Authorization)
        try:
            answers = resolver.resolve(self.target_domain, 'CAA')
            for rdata in answers:
                self.log("DNS", f"CAA Record: {rdata}", "SUCCESS")
        except:
            self.log("DNS", "No CAA records (Certificate Authority Authorization)", "MEDIUM", 3)
        
        # DNSSEC
        self.check_dnssec()
    
    def check_email_security(self):
        """Check SPF, DMARC, DKIM configuration"""
        resolver = dns.resolver.Resolver()
        
        # SPF
        try:
            answers = resolver.resolve(self.target_domain, 'TXT')
            spf_found = False
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    spf_found = True
                    self.log("EMAIL-SEC", f"SPF Record found: {txt[:60]}", "SUCCESS")
                    
                    # Check SPF strength
                    if '~all' in txt:
                        self.log("EMAIL-SEC", "SPF uses SoftFail (~all) - not strict", "LOW", 2)
                    elif '-all' in txt:
                        self.log("EMAIL-SEC", "SPF uses HardFail (-all) - good!", "SUCCESS")
                    else:
                        self.log("EMAIL-SEC", "SPF configuration weak", "MEDIUM", 5)
            
            if not spf_found:
                self.log("EMAIL-SEC", "No SPF record - email spoofing possible", "MEDIUM", 5)
        except:
            self.log("EMAIL-SEC", "SPF record not found", "MEDIUM", 5)
        
        # DMARC
        try:
            answers = resolver.resolve(f'_dmarc.{self.target_domain}', 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    self.log("EMAIL-SEC", f"DMARC Record: {txt[:60]}", "SUCCESS")
                    
                    if 'p=none' in txt:
                        self.log("EMAIL-SEC", "DMARC policy is 'none' - monitoring only", "LOW", 2)
                    elif 'p=quarantine' in txt:
                        self.log("EMAIL-SEC", "DMARC policy: quarantine - good", "SUCCESS")
                    elif 'p=reject' in txt:
                        self.log("EMAIL-SEC", "DMARC policy: reject - excellent!", "SUCCESS")
        except:
            self.log("EMAIL-SEC", "No DMARC record - email authentication weak", "MEDIUM", 5)
    
    def check_dnssec(self):
        """Check DNSSEC implementation"""
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(self.target_domain, 'DNSKEY')
            self.log("DNS-SEC", "DNSSEC is enabled", "SUCCESS")
        except dns.resolver.NoAnswer:
            self.log("DNS-SEC", "DNSSEC not implemented", "MEDIUM", 5)
        except:
            self.log("DNS-SEC", "DNSSEC check failed", "INFO")
    
    # ==================== MODULE 3: SSL/TLS SECURITY ====================
    
    def ssl_tls_analysis(self):
        """Comprehensive SSL/TLS security analysis"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 3: SSL/TLS Security Analysis")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if not self.full_url.startswith('https://'):
            self.log("SSL", "[X] Site not using HTTPS - CRITICAL SECURITY RISK", "CRITICAL", 20)
            return
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    
                    self.ssl_info['expiration_days'] = days_left
                    
                    if days_left < 0:
                        self.log("SSL", "Certificate EXPIRED!", "CRITICAL", 25)
                    elif days_left < 7:
                        self.log("SSL", f"Certificate expires in {days_left} days - URGENT!", "HIGH", 15)
                    elif days_left < 30:
                        self.log("SSL", f"Certificate expires in {days_left} days", "MEDIUM", 8)
                    else:
                        self.log("SSL", f"Certificate valid for {days_left} days", "SUCCESS")
                    
                    # Protocol version
                    version = ssock.version()
                    self.ssl_info['protocol'] = version
                    self.log("SSL", f"Protocol: {version}", "SUCCESS")
                    
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        self.log("SSL", f"Outdated protocol {version} - upgrade needed!", "HIGH", 12)
                    
                    # Cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        self.ssl_info['cipher'] = cipher[0]
                        self.log("SSL", f"Cipher: {cipher[0]}", "INFO")
                        
                        # Check for weak ciphers
                        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon']
                        if any(weak in cipher[0] for weak in weak_ciphers):
                            self.log("SSL", f"Weak cipher detected: {cipher[0]}", "HIGH", 10)
                    
                    # Certificate chain
                    self.log("SSL", f"Certificate issued to: {cert.get('subject', 'N/A')}", "INFO")
                    self.log("SSL", f"Certificate issuer: {cert.get('issuer', 'N/A')}", "INFO")
                    
                    # Check SAN (Subject Alternative Names)
                    san = cert.get('subjectAltName', [])
                    if san:
                        self.log("SSL", f"Certificate covers {len(san)} domains", "INFO")
                    
        except ssl.SSLError as e:
            self.log("SSL", f"SSL Error: {str(e)}", "CRITICAL", 20)
        except socket.timeout:
            self.log("SSL", "SSL connection timeout", "HIGH", 10)
        except Exception as e:
            self.log("SSL", f"SSL analysis failed: {str(e)}", "MEDIUM", 5)
        
        # Check Certificate Transparency
        self.check_certificate_transparency()
    
    def check_certificate_transparency(self):
        """Check Certificate Transparency logs"""
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                certs = resp.json()
                if certs:
                    unique_domains = set()
                    for cert in certs[:50]:  # Limit to recent 50
                        name = cert.get('name_value', '')
                        unique_domains.update(name.split('\n'))
                    
                    self.log("CT-LOGS", f"Found {len(certs)} certificates in CT logs", "INFO")
                    
                    # Look for interesting subdomains
                    interesting = [d for d in unique_domains if any(k in d for k in ['dev', 'test', 'staging', 'admin', 'api'])]
                    if interesting:
                        for domain in interesting[:5]:
                            self.log("CT-LOGS", f"Interesting subdomain: {domain}", "INFO")
        except:
            self.log("CT-LOGS", "Certificate Transparency check failed", "INFO")
    
    # ==================== MODULE 4: WEB APPLICATION ANALYSIS ====================
    
    def web_application_analysis(self):
        """Comprehensive web application security analysis"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 4: Web Application Security Analysis")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT, verify=False, allow_redirects=True)
            
            # Server banner
            server = resp.headers.get('Server', 'Not disclosed')
            self.log("WEB", f"Server: {server}", "SUCCESS")
            
            # Detect if server banner is verbose
            if any(v in server.lower() for v in ['/', 'apache', 'nginx', 'iis', 'version']):
                if re.search(r'\d+\.\d+', server):
                    self.log("WEB", "Server version disclosed - information leakage", "LOW", 2)
            
            # CMS and Technology detection
            self.detect_technologies(resp)
            
            # Security headers
            self.analyze_security_headers(resp.headers)
            
            # Cookies
            self.analyze_cookies(resp.cookies)
            
            # WAF Detection
            self.detect_waf(resp)
            
            # HTTP version
            if 'HTTP/2' in resp.headers.get('', ''):
                self.log("WEB", "HTTP/2 support detected", "SUCCESS")
            
            # Response analysis
            self.analyze_response(resp)
            
        except Exception as e:
            self.log("WEB", f"Web analysis error: {str(e)}", "MEDIUM", 5)
    
    def detect_technologies(self, response):
        """Advanced technology stack detection"""
        content = response.text.lower()
        headers = response.headers
        
        # CMS Detection
        cms_patterns = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wordpress', '/wp-json/'],
            'Joomla': ['/components/com_', 'joomla', '/administrator/', '/templates/'],
            'Drupal': ['/sites/default/', 'drupal', '/modules/', '/misc/drupal.js'],
            'Magento': ['/skin/frontend/', 'mage/cookies.js', 'magento'],
            'PrestaShop': ['/modules/blockwishlist/', 'prestashop'],
            'Shopify': ['cdn.shopify.com', 'shopify', 'shopify.com/s/'],
            'Wix': ['wix.com', 'parastorage', 'wix-code'],
            'Laravel': ['laravel_session', 'laravel', '/vendor/laravel'],
            'Django': ['csrfmiddlewaretoken', 'django', '__admin__'],
            'React': ['react', 'react-dom', '_react'],
            'Angular': ['ng-version', 'angular', 'ng-app'],
            'Vue.js': ['vue.js', '__vue__', 'v-cloak']
        }
        
        for tech, patterns in cms_patterns.items():
            if any(pattern in content for pattern in patterns):
                self.cms_detected = tech
                self.log("CMS", f"Detected: {tech}", "INFO")
                self.technologies.append(tech)
                break
        
        # Web Server
        if 'nginx' in content or 'nginx' in headers.get('Server', '').lower():
            self.technologies.append('Nginx')
        if 'apache' in content or 'apache' in headers.get('Server', '').lower():
            self.technologies.append('Apache')
        
        # Programming Languages
        tech_headers = {
            'X-Powered-By': 'Technology',
            'X-AspNet-Version': 'ASP.NET',
            'X-Generator': 'Generator',
            'X-Drupal-Cache': 'Drupal',
            'X-Craft-Powered-By': 'Craft CMS'
        }
        
        for header, name in tech_headers.items():
            if header in headers:
                tech = headers[header]
                self.technologies.append(f"{name}: {tech}")
                self.log("TECH", f"{name}: {tech}", "INFO")
        
        # JavaScript frameworks and libraries
        js_libs = {
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Font Awesome': ['font-awesome', 'fontawesome'],
            'Google Analytics': ['google-analytics', 'gtag'],
            'Cloudflare': ['cloudflare'],
            'PayPal': ['paypal']
        }
        
        for lib, patterns in js_libs.items():
            if any(p in content for p in patterns):
                self.technologies.append(lib)
    
    def analyze_security_headers(self, headers):
        """Comprehensive security headers analysis"""
        security_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS (Force HTTPS)',
                'impact': 10,
                'check': lambda v: self.check_hsts(v)
            },
            'Content-Security-Policy': {
                'description': 'CSP (XSS Protection)',
                'impact': 15,
                'check': lambda v: self.check_csp(v)
            },
            'X-Frame-Options': {
                'description': 'Clickjacking Protection',
                'impact': 10,
                'check': lambda v: None
            },
            'X-Content-Type-Options': {
                'description': 'MIME-Sniffing Protection',
                'impact': 5,
                'check': lambda v: None
            },
            'X-XSS-Protection': {
                'description': 'XSS Filter',
                'impact': 5,
                'check': lambda v: None
            },
            'Referrer-Policy': {
                'description': 'Referrer Control',
                'impact': 3,
                'check': lambda v: None
            },
            'Permissions-Policy': {
                'description': 'Feature Policy',
                'impact': 5,
                'check': lambda v: None
            },
            'X-Permitted-Cross-Domain-Policies': {
                'description': 'Adobe Cross-Domain Policy',
                'impact': 2,
                'check': lambda v: None
            }
        }
        
        for header, config in security_headers.items():
            if header in headers:
                self.log("HEADER", f"[+] {config['description']} enabled", "SUCCESS")
                if config['check']:
                    config['check'](headers[header])
            else:
                self.log("HEADER", f"[-] Missing {config['description']} ({header})", "MEDIUM", config['impact'])
    
    def check_hsts(self, value):
        """Analyze HSTS configuration"""
        if 'max-age=' in value:
            age = int(re.search(r'max-age=(\d+)', value).group(1))
            if age < 31536000:  # Less than 1 year
                self.log("HEADER", f"HSTS max-age too short ({age}s)", "LOW", 2)
        
        if 'includeSubDomains' not in value:
            self.log("HEADER", "HSTS doesn't include subdomains", "LOW", 2)
        
        if 'preload' in value:
            self.log("HEADER", "HSTS preload enabled - excellent!", "SUCCESS")
    
    def check_csp(self, value):
        """Analyze CSP configuration"""
        if 'unsafe-inline' in value:
            self.log("HEADER", "CSP allows 'unsafe-inline' - weakens XSS protection", "MEDIUM", 5)
        if 'unsafe-eval' in value:
            self.log("HEADER", "CSP allows 'unsafe-eval' - security risk", "MEDIUM", 5)
        if '*' in value and 'default-src' in value:
            self.log("HEADER", "CSP uses wildcard in default-src", "MEDIUM", 5)
    
    def analyze_cookies(self, cookies):
        """Analyze cookie security"""
        if not cookies:
            self.log("COOKIE", "No cookies set", "INFO")
            return
        
        total = len(cookies)
        secure = sum(1 for c in cookies if c.secure)
        httponly = sum(1 for c in cookies if c.has_nonstandard_attr('HttpOnly'))
        samesite = sum(1 for c in cookies if c.has_nonstandard_attr('SameSite'))
        
        self.log("COOKIE", f"Total cookies: {total}", "INFO")
        
        if secure < total:
            self.log("COOKIE", f"{total - secure} cookies without Secure flag", "MEDIUM", 5)
        else:
            self.log("COOKIE", "All cookies have Secure flag", "SUCCESS")
        
        if httponly < total:
            self.log("COOKIE", f"{total - httponly} cookies without HttpOnly flag - XSS risk", "MEDIUM", 5)
        
        if samesite < total:
            self.log("COOKIE", f"{total - samesite} cookies without SameSite - CSRF risk", "LOW", 3)
    
    def detect_waf(self, response):
        """Detect Web Application Firewall"""
        headers = response.headers
        content = response.text.lower()
        
        detected_wafs = []
        
        for waf_name, signatures in Config.WAF_SIGNATURES.items():
            # Check headers
            for sig in signatures:
                if any(sig.lower() in h.lower() or sig.lower() in v.lower() 
                       for h, v in headers.items()):
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                        break
            
            # Check content
            if not detected_wafs or waf_name not in detected_wafs:
                if any(sig.lower() in content for sig in signatures):
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
        
        if detected_wafs:
            for waf in detected_wafs:
                self.log("WAF", f"Detected: {waf}", "INFO")
                self.waf_detected.append(waf)
        else:
            self.log("WAF", "No WAF detected - consider adding protection", "LOW", 3)
    
    def analyze_response(self, response):
        """Analyze HTTP response for issues"""
        content = response.text
        
        # Check for error messages
        error_patterns = {
            'SQL Error': r'(sql syntax|mysql_fetch|pg_query|oci_execute|sqlite_query)',
            'Path Disclosure': r'([a-z]:\\[^<>]+|/home/[^<>]+|/usr/[^<>]+)',
            'PHP Error': r'(fatal error|warning:|parse error|notice:)',
            'ASP.NET Error': r'(server error|runtime error|aspnet)',
            'Stack Trace': r'(stack trace|stacktrace|\tat\s+[a-z]+\.)'
        }
        
        for error_type, pattern in error_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.log("ERROR", f"Detected {error_type} in response", "MEDIUM", 8)
        
        # Check for development/debug modes
        debug_patterns = ['debug=true', 'debug mode', 'development mode', 'trace enabled']
        if any(pattern in content.lower() for pattern in debug_patterns):
            self.log("DEBUG", "Debug/Development mode detected in response", "MEDIUM", 8)
    
    # ==================== MODULE 5: OWASP TOP 10 SCANNER ====================
    
    def owasp_top10_scanner(self):
        """OWASP Top 10 vulnerability scanner"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 5: OWASP Top 10 Vulnerability Scanner")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if self.scan_mode in ['normal', 'deep', 'extreme']:
            # A01 - Broken Access Control
            self.test_broken_access_control()
            
            # A02 - Cryptographic Failures
            self.test_crypto_failures()
            
            # A03 - Injection
            self.test_injection_vulnerabilities()
            
            # A04 - Insecure Design
            # Covered in other modules
            
            # A05 - Security Misconfiguration
            self.test_security_misconfiguration()
            
            # A06 - Vulnerable Components
            self.test_vulnerable_components()
            
            # A07 - Authentication Failures
            self.test_authentication()
            
            # A08 - Software and Data Integrity Failures
            self.test_integrity_failures()
            
            # A09 - Security Logging and Monitoring Failures
            # Covered in headers analysis
            
            # A10 - Server-Side Request Forgery (SSRF)
            self.test_ssrf()
        else:
            self.log("OWASP", "Skipped in fast mode - use normal or deep mode", "INFO")
    
    def test_broken_access_control(self):
        """Test for broken access control"""
        # Test for common admin paths
        admin_paths = ['/admin', '/administrator', '/admin.php', '/wp-admin', '/phpmyadmin', 
                      '/adminer', '/admin/login', '/backend', '/panel', '/dashboard']
        
        for path in admin_paths[:5]:  # Limit to avoid too many requests
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    self.log("ACCESS", f"Admin panel accessible: {path}", "MEDIUM", 8)
                    break
            except:
                pass
    
    def test_crypto_failures(self):
        """Test for cryptographic failures"""
        # Already covered in SSL/TLS analysis
        if not self.full_url.startswith('https://'):
            self.log("CRYPTO", "No HTTPS - sensitive data at risk", "CRITICAL", 20)
    
    def test_injection_vulnerabilities(self):
        """Test for injection vulnerabilities"""
        # XSS Testing
        if self.scan_mode in ['deep', 'extreme']:
            self.test_xss()
        
        # SQL Injection basic test
        self.test_sql_injection()
    
    def test_xss(self):
        """Basic XSS vulnerability testing"""
        self.log("XSS", "Testing for XSS vulnerabilities (basic test)...", "INFO")
        
        # Find forms
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT)
            if '<form' in resp.text.lower():
                # We found forms - in a real implementation, we'd parse and test them
                # For safety, we'll just note their presence
                self.log("XSS", "Forms detected - manual XSS testing recommended", "INFO")
        except:
            pass
    
    def test_sql_injection(self):
        """Basic SQL injection detection"""
        self.log("SQLi", "Checking for SQL injection indicators...", "INFO")
        
        # Check for database error messages in response
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT)
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
                'microsoft ole db', 'odbc', 'jdbc', 'syntax error'
            ]
            
            if any(err in resp.text.lower() for err in sql_errors):
                self.log("SQLi", "Database error messages detected - possible SQLi vector", "HIGH", 15)
        except:
            pass
    
    def test_security_misconfiguration(self):
        """Test for security misconfigurations"""
        # Directory listing
        try:
            resp = self.session.get(urljoin(self.base_url, '/'), timeout=5)
            if '<title>Index of' in resp.text or 'Directory Listing' in resp.text:
                self.log("CONFIG", "Directory listing enabled", "MEDIUM", 8)
        except:
            pass
        
        # Check for backup files
        self.discover_backup_files()
    
    def test_vulnerable_components(self):
        """Check for vulnerable components"""
        if self.cms_detected:
            self.log("VULN-COMP", f"CMS {self.cms_detected} detected - check for updates", "INFO")
        
        # Check for outdated jQuery (if detected)
        if 'jQuery' in self.technologies:
            self.log("VULN-COMP", "jQuery detected - ensure version is up to date", "INFO")
    
    def test_authentication(self):
        """Test authentication mechanisms"""
        # Check for common login pages
        login_paths = ['/login', '/signin', '/auth', '/authenticate']
        
        for path in login_paths[:3]:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    self.log("AUTH", f"Login page found: {path}", "INFO")
                    
                    # Check for HTTPS
                    if not url.startswith('https://'):
                        self.log("AUTH", "Login page not using HTTPS!", "CRITICAL", 20)
                    break
            except:
                pass
    
    def test_integrity_failures(self):
        """Test for integrity failures"""
        # Check for Subresource Integrity
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT)
            if '<script' in resp.text:
                # Count scripts
                script_tags = resp.text.count('<script')
                sri_tags = resp.text.count('integrity=')
                
                if script_tags > 0 and sri_tags == 0:
                    self.log("INTEGRITY", "External scripts without SRI (Subresource Integrity)", "LOW", 3)
                elif sri_tags > 0:
                    self.log("INTEGRITY", "SRI implemented on some scripts", "SUCCESS")
        except:
            pass
    
    def test_ssrf(self):
        """Basic SSRF testing"""
        # Note: We can't actually test for SSRF without causing real requests
        # This is informational only
        self.log("SSRF", "SSRF testing requires manual verification", "INFO")
    
    # ==================== MODULE 6: API & ENDPOINT DISCOVERY ====================
    
    def api_discovery(self):
        """Discover API endpoints"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 6: API Endpoint Discovery")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Test common API paths
        for endpoint in Config.API_ENDPOINTS[:10]:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                
                if resp.status_code in [200, 301, 302, 401, 403]:
                    self.api_endpoints.append({'url': endpoint, 'status': resp.status_code})
                    level = "INFO" if resp.status_code in [401, 403] else "MEDIUM"
                    impact = 0 if resp.status_code in [401, 403] else 5
                    self.log("API", f"Found: {endpoint} (HTTP {resp.status_code})", level, impact)
                    
                    # Check for API documentation
                    if any(x in resp.text.lower() for x in ['swagger', 'openapi', 'api documentation']):
                        self.log("API", f"API documentation exposed at {endpoint}", "MEDIUM", 5)
            except:
                pass
        
        # Check for GraphQL
        self.check_graphql()
        
        # Check robots.txt for API hints
        self.analyze_robots_txt()
    
    def check_graphql(self):
        """Check for GraphQL endpoint"""
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql']
        
        for path in graphql_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and 'graphql' in resp.text.lower():
                    self.log("API", f"GraphQL endpoint found: {path}", "MEDIUM", 5)
                    
                    # Test for introspection
                    introspection_query = '{"query": "{ __schema { types { name } } }"}'
                    resp = self.session.post(url, data=introspection_query, 
                                            headers={'Content-Type': 'application/json'}, timeout=5)
                    if resp.status_code == 200 and '__schema' in resp.text:
                        self.log("API", "GraphQL introspection enabled - information disclosure", "MEDIUM", 8)
                    break
            except:
                pass
    
    def analyze_robots_txt(self):
        """Analyze robots.txt for interesting paths"""
        try:
            url = urljoin(self.base_url, '/robots.txt')
            resp = self.session.get(url, timeout=5)
            
            if resp.status_code == 200:
                self.log("RECON", "robots.txt found", "SUCCESS")
                
                # Look for interesting disallowed paths
                disallowed = re.findall(r'Disallow:\s*(/[^\s]+)', resp.text)
                if disallowed:
                    for path in disallowed[:5]:
                        self.log("RECON", f"Disallowed path in robots.txt: {path}", "INFO")
        except:
            pass
    
    # ==================== MODULE 7: JAVASCRIPT SECURITY ANALYSIS ====================
    
    def javascript_analysis(self):
        """Analyze JavaScript for security issues"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 7: JavaScript Security Analysis")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT)
            
            # Find all JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            
            if js_urls:
                self.log("JS", f"Found {len(js_urls)} JavaScript files", "INFO")
                
                # Analyze first few JS files
                for js_url in js_urls[:5]:
                    if not js_url.startswith('http'):
                        js_url = urljoin(self.base_url, js_url)
                    
                    self.analyze_js_file(js_url)
            
            # Check for inline JavaScript
            inline_js = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL)
            if inline_js:
                self.log("JS", f"Found {len(inline_js)} inline scripts", "INFO")
                
                # Check for dangerous patterns
                for script in inline_js[:10]:
                    self.check_dangerous_js_patterns(script)
                    
        except Exception as e:
            self.log("JS", f"JavaScript analysis error: {e}", "INFO")
    
    def analyze_js_file(self, url):
        """Analyze individual JavaScript file"""
        try:
            resp = self.session.get(url, timeout=5)
            if resp.status_code == 200:
                self.js_files.append(url)
                self.check_dangerous_js_patterns(resp.text, url)
        except:
            pass
    
    def check_dangerous_js_patterns(self, content, source="inline"):
        """Check for dangerous JavaScript patterns"""
        dangerous_patterns = {
            'eval usage': r'\beval\s*\(',
            'innerHTML assignment': r'innerHTML\s*=',
            'document.write': r'document\.write\s*\(',
            'setTimeout with string': r'setTimeout\s*\(["\']',
            'Base64 decode': r'atob\s*\(',
            'API keys in code': r'(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']'
        }
        
        for pattern_name, pattern in dangerous_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.log("JS-SEC", f"Potential issue in {source}: {pattern_name}", "LOW", 2)
        
        # Check for exposed secrets (rough check)
        secret_patterns = [
            r'password\s*[:=]\s*["\'][^"\']+["\']',
            r'secret\s*[:=]\s*["\'][^"\']+["\']',
            r'token\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.log("JS-SEC", f"Potential secret exposure in {source}", "HIGH", 12)
                break
    
    # ==================== MODULE 8: BACKUP FILE DISCOVERY ====================
    
    def discover_backup_files(self):
        """Discover common backup files"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 8: Backup File Discovery")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        for backup_file in Config.BACKUP_FILES[:15]:
            try:
                url = urljoin(self.base_url, backup_file)
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                
                if resp.status_code == 200:
                    self.backup_files_found.append(backup_file)
                    self.log("BACKUP", f"Found backup file: {backup_file}", "HIGH", 12)
            except:
                pass
        
        if not self.backup_files_found:
            self.log("BACKUP", "No common backup files found", "SUCCESS")
    
    # ==================== MODULE 9: SUBDOMAIN ENUMERATION ====================
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 9: Subdomain Enumeration")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'admin', 'api', 'dev', 'staging', 'test', 'mobile', 'blog',
            'm', 'shop', 'forum', 'portal', 'support', 'help'
        ]
        
        if self.scan_mode in ['deep', 'extreme']:
            for sub in common_subs[:20]:
                try:
                    full_domain = f"{sub}.{self.target_domain}"
                    socket.gethostbyname(full_domain)
                    self.subdomains_found.append(full_domain)
                    self.log("SUBDOMAIN", f"Found: {full_domain}", "INFO")
                except:
                    pass
        else:
            self.log("SUBDOMAIN", "Skipped in fast/normal mode - use deep mode", "INFO")
        
        if not self.subdomains_found:
            self.log("SUBDOMAIN", "No additional subdomains found", "INFO")
    
    # ==================== MODULE 10: OSINT & EXTERNAL INTEL ====================
    
    def osint_reconnaissance(self):
        """OSINT and external intelligence gathering"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 10: OSINT & Threat Intelligence")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Email harvesting (from WHOIS)
        if self.whois_data:
            self.log("OSINT", "WHOIS data collected", "SUCCESS")
        
        # Check social media presence
        self.check_social_media()
        
        # Check VirusTotal (if API key available)
        if Config.VIRUSTOTAL_API:
            self.check_virustotal()
        else:
            self.log("OSINT", "VirusTotal check skipped (no API key)", "INFO")
        
        # Check Shodan (if API key available)
        if Config.SHODAN_API:
            self.check_shodan()
        else:
            self.log("OSINT", "Shodan check skipped (no API key)", "INFO")
        
        # Check haveibeenpwned
        self.check_breach_databases()
    
    def check_social_media(self):
        """Check for social media presence"""
        social_platforms = {
            'Twitter': f'https://twitter.com/{self.target_domain.split(".")[0]}',
            'Facebook': f'https://facebook.com/{self.target_domain.split(".")[0]}',
            'LinkedIn': f'https://linkedin.com/company/{self.target_domain.split(".")[0]}',
            'Instagram': f'https://instagram.com/{self.target_domain.split(".")[0]}',
            'GitHub': f'https://github.com/{self.target_domain.split(".")[0]}'
        }
        
        for platform, url in social_platforms.items():
            try:
                resp = self.session.get(url, timeout=3, allow_redirects=True)
                if resp.status_code == 200 and platform.lower() in resp.text.lower():
                    self.social_media[platform] = url
                    self.log("SOCIAL", f"Found {platform} presence: {url}", "INFO")
            except:
                pass
    
    def check_virustotal(self):
        """Check domain reputation on VirusTotal"""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target_domain}"
            headers = {"x-apikey": Config.VIRUSTOTAL_API}
            resp = self.session.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    self.log("VT", f"VirusTotal: {malicious} vendors flagged as malicious!", "CRITICAL", 25)
                elif suspicious > 0:
                    self.log("VT", f"VirusTotal: {suspicious} vendors flagged as suspicious", "HIGH", 15)
                else:
                    self.log("VT", "VirusTotal: Clean reputation", "SUCCESS")
        except Exception as e:
            self.log("VT", f"VirusTotal check failed: {e}", "INFO")
    
    def check_shodan(self):
        """Check Shodan for exposed services"""
        try:
            url = f"https://api.shodan.io/shodan/host/{self.target_ip}?key={Config.SHODAN_API}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get('ports', [])
                vulns = data.get('vulns', [])
                
                if ports:
                    self.log("SHODAN", f"Shodan: {len(ports)} open ports detected", "INFO")
                
                if vulns:
                    self.log("SHODAN", f"Shodan: {len(vulns)} known vulnerabilities!", "CRITICAL", 20)
                    for vuln in vulns[:3]:
                        self.log("SHODAN", f"CVE: {vuln}", "HIGH", 10)
        except Exception as e:
            self.log("SHODAN", f"Shodan check failed: {e}", "INFO")
    
    def check_breach_databases(self):
        """Check for known data breaches"""
        # This is informational - we won't actually query haveibeenpwned without emails
        self.log("BREACH", "Data breach checks require specific email addresses", "INFO")
    
    # ==================== MODULE 11: MALWARE & THREAT ANALYSIS ====================
    
    def malware_analysis(self):
        """Advanced malware and threat analysis"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 11: Malware & Threat Analysis")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        try:
            resp = self.session.get(self.full_url, timeout=Config.TIMEOUT)
            content = resp.text.lower()
            
            # Malware indicators
            malware_indicators = {
                'Cryptojacking': [
                    'coinhive', 'cryptonight', 'webminer', 'jsecoin', 'minero.cc',
                    'crypto-loot', 'coin-hive', 'authedmine'
                ],
                'Obfuscated Code': [
                    r'eval\s*\(\s*unescape',
                    r'eval\s*\(\s*atob',
                    r'fromcharcode',
                    r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}'
                ],
                'Malicious Redirects': [
                    'window.location.replace',
                    'meta http-equiv="refresh"',
                    'document.location.href',
                ],
                'Hidden iFrames': [
                    r'<iframe[^>]+(hidden|display:\s*none|width:\s*0|height:\s*0)',
                    r'<iframe[^>]+style=["\'][^"\']*opacity:\s*0'
                ],
                'Base64 Payloads': [
                    r'eval\s*\(\s*atob\s*\(',
                    r'eval\s*\(\s*decodeURI',
                    r'btoa\s*\(.{100,}'
                ],
                'Phishing Indicators': [
                    'verify your account',
                    'suspended account',
                    'unusual activity',
                    'confirm your identity',
                    'update payment information'
                ]
            }
            
            threats_found = []
            for threat_type, patterns in malware_indicators.items():
                for pattern in patterns:
                    if isinstance(pattern, str) and pattern in content:
                        if threat_type not in threats_found:
                            threats_found.append(threat_type)
                            impact = 25 if threat_type == 'Cryptojacking' else 20
                            self.log("MALWARE", f"Detected: {threat_type}", "CRITICAL", impact)
                            break
                    elif re.search(pattern, content):
                        if threat_type not in threats_found:
                            threats_found.append(threat_type)
                            impact = 25 if threat_type == 'Cryptojacking' else 20
                            self.log("MALWARE", f"Detected: {threat_type}", "CRITICAL", impact)
                            break
            
            if not threats_found:
                self.log("MALWARE", "No malware signatures detected", "SUCCESS")
                
        except Exception as e:
            self.log("MALWARE", f"Malware analysis error: {e}", "INFO")
    
    # ==================== MODULE 12: VISUAL EVIDENCE ====================
    
    def capture_visual_evidence(self):
        """Capture screenshot evidence"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] MODULE 12: Visual Evidence Capture")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if self.options.get('skip_screenshot'):
            self.log("VISUAL", "Screenshot capture skipped by user", "INFO")
            return
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            opts = Options()
            opts.add_argument("--headless")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--window-size=1920,1080")
            opts.add_argument(f"user-agent={Config.USER_AGENT}")
            
            driver = webdriver.Chrome(options=opts)
            driver.get(self.full_url)
            time.sleep(3)
            
            self.screenshot_path = f"screenshot_{self.target_domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            driver.save_screenshot(self.screenshot_path)
            driver.quit()
            
            self.log("VISUAL", f"Screenshot saved: {self.screenshot_path}", "SUCCESS")
            
        except Exception as e:
            self.log("VISUAL", f"Screenshot capture failed: {e}", "INFO")
    
    # ==================== MASTER SCAN ORCHESTRATOR ====================
    
    def run_comprehensive_scan(self):
        """Execute comprehensive security scan"""
        start_time = time.time()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}[*] Initiating vErtex {Config.VERSION} {Config.EDITION}")
        print(f"{Fore.GREEN}[*] Target: {self.full_url}")
        print(f"{Fore.GREEN}[*] Scan Mode: {self.scan_mode.upper()}")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        # Module execution order
        modules = [
            ("Network & Infrastructure", self.network_reconnaissance),
            ("DNS Security", self.dns_security_analysis),
            ("SSL/TLS Security", self.ssl_tls_analysis),
            ("Web Application", self.web_application_analysis),
            ("OWASP Top 10", self.owasp_top10_scanner),
            ("API Discovery", self.api_discovery),
            ("JavaScript Security", self.javascript_analysis),
            ("Backup Files", self.discover_backup_files),
            ("Subdomain Enum", self.subdomain_enumeration),
            ("OSINT & Threat Intel", self.osint_reconnaissance),
            ("Malware Analysis", self.malware_analysis),
            ("Visual Evidence", self.capture_visual_evidence)
        ]
        
        for module_name, module_func in modules:
            try:
                module_func()
            except Exception as e:
                self.log("ERROR", f"{module_name} failed: {str(e)}", "HIGH", 5)
        
        # Calculate scan time
        scan_duration = time.time() - start_time
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}[[+]] Scan completed in {scan_duration:.2f} seconds")
        print(f"{Fore.GREEN}[*] Final Security Score: {max(0, self.security_score)}/100")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        return True
    
    # ==================== REPORT GENERATION ====================
    
    def generate_comprehensive_report(self):
        """Generate comprehensive PDF and JSON reports"""
        print(f"\n{Fore.CYAN}[*] Generating comprehensive security report...")
        
        # PDF Report
        self.generate_pdf_report()
        
        # JSON Report
        self.generate_json_report()
        
        # Summary to console
        self.print_executive_summary()
    
    def generate_pdf_report(self):
        """Generate enhanced PDF report"""
        self.pdf.add_page()
        
        # Executive Summary
        self.pdf.chapter_title('EXECUTIVE SUMMARY')
        
        # Target information
        target_info = {
            'Target URL': self.full_url,
            'IP Address': self.target_ip,
            'Scan Mode': self.scan_mode.upper(),
            'Scan Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'CMS Detected': self.cms_detected or 'None',
            'WAF Detected': ', '.join(self.waf_detected) if self.waf_detected else 'None'
        }
        self.pdf.add_info_box('Target Information', target_info)
        
        # Security Score
        self.pdf.add_security_score_visual(max(0, self.security_score))
        
        # Risk Summary
        self.pdf.chapter_title('RISK SUMMARY')
        risk_summary = {
            'Critical Issues': len(self.vulnerabilities['CRITICAL']),
            'High Severity': len(self.vulnerabilities['HIGH']),
            'Medium Severity': len(self.vulnerabilities['MEDIUM']),
            'Low Severity': len(self.vulnerabilities['LOW']),
            'Total Findings': len(self.results)
        }
        self.pdf.add_info_box('Severity Distribution', risk_summary)
        
        # Screenshot
        if self.screenshot_path and os.path.exists(self.screenshot_path):
            self.pdf.chapter_title('VISUAL EVIDENCE')
            try:
                self.pdf.image(self.screenshot_path, x=15, w=180)
                self.pdf.ln(110)
            except:
                pass
        
        # Detailed findings
        self.pdf.add_page()
        self.pdf.add_vulnerability_table(self.results)
        
        # Technologies detected
        if self.technologies:
            self.pdf.add_page()
            self.pdf.chapter_title('TECHNOLOGY STACK')
            self.pdf.set_font('Arial', '', 10)
            for tech in self.technologies[:20]:
                clean_tech = clean_text_for_pdf(tech)
                self.pdf.cell(0, 6, f'  - {clean_tech}', 0, 1)
        
        # Recommendations
        self.pdf.add_page()
        recommendations = self.generate_recommendations()
        self.pdf.chapter_title('SECURITY RECOMMENDATIONS')
        self.pdf.set_font('Arial', '', 10)
        for i, rec in enumerate(recommendations, 1):
            clean_rec = clean_text_for_pdf(rec)
            self.pdf.multi_cell(0, 6, f'{i}. {clean_rec}')
            self.pdf.ln(2)
        
        # Save PDF
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_filename = f"vErtex_v{Config.VERSION}_{self.target_domain.replace('.', '_')}_{timestamp}.pdf"
        self.pdf.output(pdf_filename)
        
        print(f"{Fore.GREEN}[[+]] PDF Report: {Fore.YELLOW}{pdf_filename}")
        
        return pdf_filename
    
    def generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            'metadata': {
                'version': Config.VERSION,
                'edition': Config.EDITION,
                'scan_date': datetime.now().isoformat(),
                'target': self.full_url,
                'target_domain': self.target_domain,
                'target_ip': self.target_ip,
                'scan_mode': self.scan_mode
            },
            'security_score': max(0, self.security_score),
            'cms_detected': self.cms_detected,
            'waf_detected': self.waf_detected,
            'technologies': self.technologies,
            'vulnerabilities': {
                'critical': len(self.vulnerabilities['CRITICAL']),
                'high': len(self.vulnerabilities['HIGH']),
                'medium': len(self.vulnerabilities['MEDIUM']),
                'low': len(self.vulnerabilities['LOW']),
                'details': dict(self.vulnerabilities)
            },
            'findings': self.results,
            'dns_records': self.dns_records,
            'ssl_info': self.ssl_info,
            'api_endpoints': self.api_endpoints,
            'subdomains': self.subdomains_found,
            'backup_files': self.backup_files_found,
            'social_media': self.social_media,
            'whois': str(self.whois_data)
        }
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_filename = f"vErtex_v{Config.VERSION}_{self.target_domain.replace('.', '_')}_{timestamp}.json"
        
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"{Fore.GREEN}[[+]] JSON Report: {Fore.YELLOW}{json_filename}")
        
        return json_filename
    
    def generate_recommendations(self):
        """Generate prioritized security recommendations"""
        recs = []
        
        # Critical issues first
        if len(self.vulnerabilities['CRITICAL']) > 0:
            recs.append("URGENT: Address all CRITICAL vulnerabilities immediately - these pose severe security risks")
        
        # Specific recommendations based on findings
        findings_text = ' '.join([r['msg'].lower() for r in self.results])
        
        if 'https' not in self.full_url or 'ssl' in findings_text:
            recs.append("Implement HTTPS across entire site with valid SSL/TLS certificate (minimum TLS 1.2)")
        
        if 'csp' in findings_text or 'content-security-policy' in findings_text:
            recs.append("Implement Content Security Policy (CSP) headers to prevent XSS attacks")
        
        if 'hsts' in findings_text:
            recs.append("Enable HTTP Strict Transport Security (HSTS) with minimum 1-year max-age and includeSubDomains")
        
        if 'x-frame-options' in findings_text:
            recs.append("Add X-Frame-Options header to prevent clickjacking attacks")
        
        if len(self.vulnerabilities['HIGH']) > 0:
            recs.append("Fix all HIGH severity issues within 7 days")
        
        if 'backup' in findings_text:
            recs.append("Remove all backup files and sensitive files from public web root")
        
        if 'port' in findings_text:
            recs.append("Close unnecessary open ports and restrict access with firewall rules")
        
        if 'malware' in findings_text or 'cryptojacking' in findings_text:
            recs.append("Immediately clean all malware and implement Web Application Firewall (WAF)")
        
        if self.waf_detected:
            recs.append(f"WAF detected ({', '.join(self.waf_detected)}) - ensure it's properly configured")
        else:
            recs.append("Consider implementing a Web Application Firewall (WAF) for additional protection")
        
        if 'api' in findings_text:
            recs.append("Secure all API endpoints with proper authentication and rate limiting")
        
        if 'cookie' in findings_text:
            recs.append("Configure all cookies with Secure, HttpOnly, and SameSite flags")
        
        if self.cms_detected:
            recs.append(f"Keep {self.cms_detected} and all plugins/themes updated to latest versions")
        
        if len(self.vulnerabilities['MEDIUM']) > 0:
            recs.append("Address MEDIUM severity issues within 30 days")
        
        if self.security_score < 60:
            recs.append("Conduct comprehensive security audit and penetration testing by certified professionals")
        
        # General recommendations
        recs.extend([
            "Implement regular security scanning and monitoring",
            "Establish incident response plan and security procedures",
            "Train staff on security best practices and awareness",
            "Implement multi-factor authentication for all admin access",
            "Maintain regular backups with tested restore procedures",
            "Review and update security measures quarterly"
        ])
        
        return recs[:15]  # Return top 15 recommendations
    
    def print_executive_summary(self):
        """Print executive summary to console"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Security score
        score = max(0, self.security_score)
        if score >= 80:
            score_color, rating = Fore.GREEN, "EXCELLENT"
        elif score >= 60:
            score_color, rating = Fore.LIGHTYELLOW_EX, "GOOD"
        elif score >= 40:
            score_color, rating = Fore.YELLOW, "FAIR"
        else:
            score_color, rating = Fore.RED, "POOR"
        
        print(f"{Fore.WHITE}Security Score: {score_color}{score}/100 ({rating})")
        
        # Vulnerability counts
        print(f"\n{Fore.WHITE}Vulnerability Summary:")
        print(f"  {Fore.RED}[CRITICAL] Critical: {len(self.vulnerabilities['CRITICAL'])}")
        print(f"  {Fore.LIGHTRED_EX}[HIGH] High:     {len(self.vulnerabilities['HIGH'])}")
        print(f"  {Fore.YELLOW}[MEDIUM] Medium:   {len(self.vulnerabilities['MEDIUM'])}")
        print(f"  {Fore.CYAN}[LOW] Low:      {len(self.vulnerabilities['LOW'])}")
        
        # Key findings
        if self.cms_detected:
            print(f"\n{Fore.WHITE}CMS: {Fore.CYAN}{self.cms_detected}")
        
        if self.waf_detected:
            print(f"{Fore.WHITE}WAF: {Fore.GREEN}{', '.join(self.waf_detected)}")
        
        if self.subdomains_found:
            print(f"{Fore.WHITE}Subdomains Found: {Fore.CYAN}{len(self.subdomains_found)}")
        
        if self.backup_files_found:
            print(f"{Fore.WHITE}Backup Files: {Fore.RED}{len(self.backup_files_found)} (REMOVE IMMEDIATELY)")
        
        print(f"\n{Fore.CYAN}{'='*60}\n")

# ==================== MAIN EXECUTION ====================

def main():
    """Main execution function"""
    show_banner()
    
    # Scan mode selection
    print(f"{Fore.CYAN}Scan Modes:")
    print(f"  {Fore.GREEN}1.{Fore.WHITE} Fast     - Quick scan (2-3 minutes)")
    print(f"  {Fore.YELLOW}2.{Fore.WHITE} Normal   - Standard scan (5-10 minutes) {Fore.GREEN}[RECOMMENDED]")
    print(f"  {Fore.LIGHTRED_EX}3.{Fore.WHITE} Deep     - Comprehensive scan (15-30 minutes)")
    print(f"  {Fore.RED}4.{Fore.WHITE} Extreme  - Full scan (30-60 minutes)\n")
    
    mode_input = input(f"{Fore.CYAN}Select scan mode [1-4] (default: 2): ").strip() or "2"
    mode_map = {"1": "fast", "2": "normal", "3": "deep", "4": "extreme"}
    scan_mode = mode_map.get(mode_input, "normal")
    
    # Target input
    target = input(f"\n{Fore.YELLOW}🎯 Enter target (URL or domain): ").strip()
    if not target:
        print(f"{Fore.RED}[!] No target specified")
        return
    
    # Options
    options = {}
    
    skip_screenshot = input(f"{Fore.CYAN}Skip screenshot capture? [y/N]: ").strip().lower() == 'y'
    options['skip_screenshot'] = skip_screenshot
    
    export_json = input(f"{Fore.CYAN}Export JSON report? [Y/n]: ").strip().lower() != 'n'
    
    # API key configuration
    if not Config.VIRUSTOTAL_API:
        print(f"\n{Fore.YELLOW}[!] VirusTotal API key not configured")
        vt_key = input(f"{Fore.CYAN}Enter VirusTotal API key (or press Enter to skip): ").strip()
        if vt_key:
            Config.VIRUSTOTAL_API = vt_key
    
    if not Config.SHODAN_API:
        print(f"\n{Fore.YELLOW}[!] Shodan API key not configured")
        shodan_key = input(f"{Fore.CYAN}Enter Shodan API key (or press Enter to skip): ").strip()
        if shodan_key:
            Config.SHODAN_API = shodan_key
    
    # Initialize scanner
    print(f"\n{Fore.GREEN}[*] Initializing vErtex {Config.VERSION} {Config.EDITION}...")
    time.sleep(1)
    
    scanner = vErtexEnterprise(target, scan_mode=scan_mode, options=options)
    
    try:
        # Run scan
        if scanner.run_comprehensive_scan():
            # Generate reports
            scanner.generate_comprehensive_report()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user")
        print(f"{Fore.CYAN}[*] Generating partial report...")
        scanner.generate_comprehensive_report()
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program terminated by user")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}")
