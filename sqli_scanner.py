import os
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
from concurrent.futures import ThreadPoolExecutor
import time
from typing import List, Set, Dict
import json
from colorama import init, Fore, Style, Back
import random
import argparse
from fake_useragent import UserAgent
import threading
from queue import Queue
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init()

class SQLiScanner:
    def __init__(self, threads: int = 5, timeout: int = 10, verbose: bool = True):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.visited_urls: Set[str] = set()
        self.forms_found: List[dict] = []
        self.payloads: List[str] = []
        self.headers: Dict[str, str] = {}
        self.url_queue = Queue()
        self.user_agent = UserAgent()
        self.print_lock = threading.Lock()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='sqli_scan.log'
        )
        
        self.load_waf_bypass_headers()

    def verbose_print(self, message: str, status: str = 'info'):
        """Thread-safe verbose printing with color coding"""
        if self.verbose:
            with self.print_lock:
                timestamp = time.strftime('%H:%M:%S')
                if status == 'success':
                    print(f"{Fore.CYAN}[{timestamp}] {Fore.GREEN}[+] {message}{Style.RESET_ALL}")
                elif status == 'error':
                    print(f"{Fore.CYAN}[{timestamp}] {Fore.RED}[-] {message}{Style.RESET_ALL}")
                elif status == 'info':
                    print(f"{Fore.CYAN}[{timestamp}] {Fore.BLUE}[*] {message}{Style.RESET_ALL}")
                elif status == 'warning':
                    print(f"{Fore.CYAN}[{timestamp}] {Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

    def load_waf_bypass_headers(self):
        self.waf_bypass_headers = {
            'X-Forwarded-For': f'127.0.0.{random.randint(1, 255)}',
            'X-Originating-IP': f'[127.0.0.{random.randint(1, 255)}]',
            'X-Remote-IP': f'127.0.0.{random.randint(1, 255)}',
            'X-Remote-Addr': f'127.0.0.{random.randint(1, 255)}',
            'User-Agent': self.user_agent.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }

    def load_payloads(self, payload_path: str) -> None:
        try:
            if not os.path.exists(payload_path):
                self.verbose_print(f"Payload file not found: {payload_path}", 'error')
                sys.exit(1)
            
            with open(payload_path, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.verbose_print(f"Loaded {len(self.payloads)} payloads", 'success')
                
        except Exception as e:
            self.verbose_print(f"Error loading payloads: {str(e)}", 'error')
            sys.exit(1)

    def get_random_headers(self) -> Dict[str, str]:
        headers = self.waf_bypass_headers.copy()
        headers.update({
            'X-Forwarded-For': f'127.0.0.{random.randint(1, 255)}',
            'User-Agent': self.user_agent.random
        })
        return headers

    def test_sqli(self, url: str, method: str, data: dict) -> List[dict]:
        vulnerabilities = []
        total_payloads = len(self.payloads)
        
        for index, payload in enumerate(self.payloads, 1):
            try:
                test_data = data.copy()
                for key in test_data:
                    test_data[key] = payload
                
                self.verbose_print(f"Testing payload [{index}/{total_payloads}]: {payload}", 'info')
                
                response = requests.request(
                    method.upper(),
                    url,
                    params=test_data if method.upper() == 'GET' else None,
                    data=test_data if method.upper() == 'POST' else None,
                    headers=self.get_random_headers(),
                    timeout=self.timeout,
                    verify=False
                )
                
                # Error patterns to check
                error_indicators = [
                    "sql syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite/JDBCDriver",
                    "System.Data.SQLClient",
                    "Driver.*SQL",
                    "SQLServer JDBC Driver",
                    "Microsoft OLE DB Provider for SQL Server",
                    "mysql_num_rows()",
                    "Error Occurred While Processing Request",
                    "Server Error in '/' Application",
                    "Microsoft OLE DB Provider for ODBC Drivers error"
                ]
                
                vulnerable = False
                matched_error = None
                
                for error in error_indicators:
                    if error.lower() in response.text.lower():
                        vulnerable = True
                        matched_error = error
                        break
                
                if vulnerable:
                    self.verbose_print(f"Vulnerability found with payload: {payload}", 'success')
                    vulnerabilities.append({
                        'url': url,
                        'method': method,
                        'payload': payload,
                        'parameter': str(data.keys()),
                        'error': matched_error
                    })
                else:
                    self.verbose_print(f"No vulnerability found with payload: {payload}", 'error')
                
                # Add small delay between requests
                time.sleep(random.uniform(0.1, 0.3))
                
            except requests.RequestException as e:
                self.verbose_print(f"Error testing payload {payload}: {str(e)}", 'error')
                continue
                
        return vulnerabilities

    def scan_url(self, url: str) -> None:
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            self.verbose_print(f"Starting scan on: {url}", 'info')
            
            # Test GET parameters first
            parsed_url = urlparse(url)
            if parsed_url.query:
                self.verbose_print(f"Testing GET parameters: {parsed_url.query}", 'info')
                params = dict(param.split('=') for param in parsed_url.query.split('&'))
                vulnerabilities = self.test_sqli(url, 'GET', params)
                
                if vulnerabilities:
                    self.verbose_print("Vulnerabilities found in GET parameters!", 'success')
                    for vuln in vulnerabilities:
                        self.print_vulnerability(vuln)
            
            # Test forms
            try:
                response = requests.get(url, headers=self.get_random_headers(), verify=False, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                self.verbose_print(f"Found {len(forms)} forms to test", 'info')
                
                for form in forms:
                    action = form.get('action', '')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        action = urljoin(url, action)
                    
                    method = form.get('method', 'get').lower()
                    inputs = form.find_all(['input', 'textarea'])
                    
                    form_data = {}
                    for input_field in inputs:
                        name = input_field.get('name', '')
                        if name:
                            form_data[name] = 'test'
                    
                    self.verbose_print(f"Testing form: {action} [{method.upper()}]", 'info')
                    vulnerabilities = self.test_sqli(action, method, form_data)
                    
                    if vulnerabilities:
                        self.verbose_print("Vulnerabilities found in form!", 'success')
                        for vuln in vulnerabilities:
                            self.print_vulnerability(vuln)
                    
            except Exception as e:
                self.verbose_print(f"Error testing forms: {str(e)}", 'error')
                
        except Exception as e:
            self.verbose_print(f"Error scanning {url}: {str(e)}", 'error')

    def print_vulnerability(self, vuln: dict):
        print("\n" + "="*60)
        print(f"{Fore.RED}VULNERABILITY FOUND!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}URL:{Style.RESET_ALL} {vuln['url']}")
        print(f"{Fore.YELLOW}Method:{Style.RESET_ALL} {vuln['method'].upper()}")
        print(f"{Fore.YELLOW}Payload:{Style.RESET_ALL} {vuln['payload']}")
        print(f"{Fore.YELLOW}Parameter(s):{Style.RESET_ALL} {vuln['parameter']}")
        print(f"{Fore.YELLOW}Error Pattern:{Style.RESET_ALL} {vuln['error']}")
        print("="*60 + "\n")

def print_banner():
    banner = """
    ____    ___   *      *   ____
   / ___|  / * \\ | |    (*) / ___|   ___   ** *****  ***** **   *_*    ___  *_* 
   \\___ \\ | | | || |    | | \\___ \\  / __| / *` || '* \\ | '_ \\  / * \\| '*_|
    ___) || |_| || |___ | |  ___) || (__ | (_| || | | || | | ||  __/| |   
   |____/  \\__\\_\\|_____||_| |____/  \\___| \\__,_||_| |_||_| |_| \\___||_|   
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print("─" * 60)
    print(f"{Fore.YELLOW}Created by: Keizen{Style.RESET_ALL}")
    print("─" * 60)

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Scanner')
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-f', '--file', help='File containing URLs to scan')
    parser.add_argument('-p', '--payloads', required=True, help='Path to payload file')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    args = parser.parse_args()

    scanner = SQLiScanner(threads=args.threads, timeout=args.timeout, verbose=args.verbose)
    scanner.load_payloads(args.payloads)

    if args.url:
        scanner.scan_url(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                scanner.scan_url(url)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading URL file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":
    print_banner()
    main()