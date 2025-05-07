import socket
import requests
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style
import json
import os
import platform
import time
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# --- Configuration ---
COMMON_PATHS = [
    # WordPress specific
    'wp-json/wp/v2/users', '?rest_route=/wp/v2/users', 'wp-json/oembed/1.0/embed',
    'wp-json/', 'wp-admin/admin-ajax.php', 'wp-login.php', 'xmlrpc.php',
    # General admin paths
    'admin/', 'administrator/', 'login/', 'admin.php', 'administrator.php', 'login.php',
    'admin/login.php', 'administrator/login.php',
    # Other common files/dirs
    'feed/', 'rss/', 'sitemap.xml', 'robots.txt', 'config.php.bak', 'backup/', '.env',
    'api/', 'v1/', 'v2/', 'json/',
    # Common CMS paths (add more as needed)
    'user/login/', 'admin/account/login/', 'joomla/administrator/', 'drupal/user/login/',
    'magento/admin/'
]
COMMON_PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 2082, 2083, 2086, 2087,
    3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 9000, 9090, 27017
]
# More comprehensive list of security headers to check
SECURITY_HEADERS_TO_CHECK = {
    'Strict-Transport-Security': {'recommended': True, 'notes': 'Ensures browser only connects via HTTPS.'},
    'Content-Security-Policy': {'recommended': True, 'notes': 'Helps prevent XSS and data injection attacks.'},
    'X-Frame-Options': {'recommended': True, 'notes': 'Protects against clickjacking attacks.'},
    'X-Content-Type-Options': {'recommended_value': 'nosniff', 'notes': 'Prevents MIME-sniffing attacks.'},
    'Referrer-Policy': {'recommended': True, 'notes': 'Controls how much referrer information is sent.'},
    'Permissions-Policy': {'recommended': True, 'notes': 'Controls which browser features can be used.'},
    'X-XSS-Protection': {'recommended_value': '0', 'notes': 'Modern browsers use CSP. Value 1; mode=block can introduce XSS in older IE.'}
}
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 WebScannerTool/1.0'
REQUEST_TIMEOUT = 5 # seconds

# --- Global state for progress and reporting ---
current_task_progress = 0
total_tasks_in_current_stage = 1
current_stage_name = ""
scan_report_data = {}
overall_progress_bar_chars = ['\u258F', '\u258E', '\u258D', '\u258C', '\u258B', '\u258A', '\u2589', '\u2588'] # Growing block
progress_animation_chars = ['-', '\\', '|', '/']

# --- UI and Helper Functions ---
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    banner = f"""
{Fore.RED}{Style.BRIGHT}
    ███████╗ ██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝ ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║  ███╗███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║   ██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╔╝██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}                 Advanced Web Security Scanner{Style.RESET_ALL}
{Fore.BLUE}           Scanner Made By: {Style.BRIGHT}Anonymous Jordan Team{Style.RESET_ALL}
{Fore.BLUE}           Telegram: {Style.BRIGHT}https://t.me/AnonymousJordan{Style.RESET_ALL}
    """
    print(banner)

def print_status(message, level="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = f"{Fore.BLUE}[{timestamp}]{Style.RESET_ALL}"
    if level == "info":
        print(f"{prefix} {Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
    elif level == "found":
        print(f"{prefix} {Fore.GREEN}[FOUND]{Style.BRIGHT} {message}{Style.RESET_ALL}")
    elif level == "not_found":
        print(f"{prefix} {Fore.YELLOW}[NOT FOUND]{Style.RESET_ALL} {message}")
    elif level == "error":
        print(f"{prefix} {Fore.RED}[ERROR]{Style.BRIGHT} {message}{Style.RESET_ALL}")
    elif level == "stage":
        print(f"\n{prefix} {Fore.MAGENTA}{Style.BRIGHT}====== {message} ======{Style.RESET_ALL}")
    # Add to report log
    if 'log' not in scan_report_data:
        scan_report_data['log'] = []
    scan_report_data['log'].append(f"[{timestamp}] [{level.upper()}] {message}")

def display_progress(current, total, stage_name="Scanning", item_name="", bar_length=40):
    global progress_animation_chars
    progress = float(current) / total
    arrow = '=' * int(round(progress * bar_length) - 1) + '>'
    spaces = ' ' * (bar_length - len(arrow))
    percent = int(round(progress * 100))
    
    # Rotate animation character
    anim_char = progress_animation_chars[current % len(progress_animation_chars)]
    if current == total:
        anim_char = Fore.GREEN + Style.BRIGHT + '\u2713' + Style.RESET_ALL # Checkmark

    status_line = f"\r{Fore.YELLOW}{Style.BRIGHT}{stage_name}{Style.RESET_ALL} [{Fore.GREEN}{arrow}{Style.RESET_ALL}{spaces}] {percent}% ({current}/{total}) {anim_char} {item_name[:30]:<30}"
    print(status_line, end="")
    if current == total:
        print() # Newline when complete

def get_target_url():
    while True:
        target_url_input = input(f"{Fore.CYAN}{Style.BRIGHT}➤ Enter target website URL (e.g., http://example.com): {Style.RESET_ALL}").strip()
        if not target_url_input:
            print_status("No URL provided. Please enter a valid URL.", "error")
            continue
        if not (target_url_input.startswith('http://') or target_url_input.startswith('https://')):
            target_url_input = 'http://' + target_url_input
            print_status(f"No scheme provided. Assuming http. Using: {target_url_input}", "info")
        
        try:
            parsed_check = urlparse(target_url_input)
            if not parsed_check.netloc:
                print_status("Invalid URL format. Please include a domain name (e.g., example.com).", "error")
                continue
            return target_url_input
        except Exception:
            print_status("Invalid URL format. Please enter a valid URL.", "error")

# --- Scanning Modules (to be expanded in step 004) ---
def retrieve_ip_and_basic_info(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Initial Reconnaissance"
    total_tasks_in_current_stage = 2 # 1 for IP, 1 for initial headers
    current_task_progress = 0
    
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data['target_url'] = target_url
    scan_report_data['ip_info'] = {}

    # 1. Get IP Address
    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Resolving IP Address")
    try:
        hostname = urlparse(target_url).hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            print_status(f"IP Address: {ip_address}", "found")
            scan_report_data['ip_info']['ip_address'] = ip_address
        else:
            print_status("Could not determine hostname from URL.", "not_found")
            scan_report_data['ip_info']['ip_address'] = "Not Resolved"
    except socket.gaierror:
        print_status(f"Failed to resolve IP for {hostname}. Host may not exist or DNS issue.", "error")
        scan_report_data['ip_info']['ip_address'] = "Resolution Failed"
    except Exception as e:
        print_status(f"Error resolving IP: {str(e)}", "error")
        scan_report_data['ip_info']['ip_address'] = "Error"
    time.sleep(0.5) # Simulate work

    # 2. Initial Headers (Server Type)
    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Fetching initial headers")
    try:
        response = requests.head(target_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        server_type = response.headers.get('Server', 'Not Disclosed')
        print_status(f"Server Type (from HEAD): {server_type}", "info")
        scan_report_data['ip_info']['server_type_head'] = server_type
    except requests.exceptions.RequestException as e:
        print_status(f"Could not fetch initial headers: {str(e)}", "error")
        scan_report_data['ip_info']['server_type_head'] = "Error fetching"
    time.sleep(0.5)
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def advanced_port_scan(ip_address):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    if not ip_address or "Failed" in ip_address or "Error" in ip_address:
        print_status("Skipping port scan due to IP resolution failure.", "info")
        scan_report_data['port_scan'] = {'status': 'Skipped', 'open_ports': []}
        return

    current_stage_name = "Port Scanning"
    total_tasks_in_current_stage = len(COMMON_PORTS_TO_SCAN)
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {ip_address}", "stage")
    scan_report_data['port_scan'] = {'ip_address': ip_address, 'open_ports': [], 'closed_ports_checked': 0}
    open_ports_found = []

    for i, port in enumerate(COMMON_PORTS_TO_SCAN):
        current_task_progress += 1
        display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Checking port {port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2) # Faster timeout
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    service_name = "unknown"
                    try: service_name = socket.getservbyport(port) 
                    except: pass
                    print_status(f"Port {port} ({service_name}) is OPEN", "found")
                    open_ports_found.append({'port': port, 'service': service_name})
                else:
                    scan_report_data['port_scan']['closed_ports_checked'] +=1
            time.sleep(0.01) # Tiny delay for UI update
        except socket.error as e:
            print_status(f"Socket error on port {port}: {str(e)}", "error")
        except Exception as e:
            print_status(f"General error scanning port {port}: {str(e)}", "error")
    
    scan_report_data['port_scan']['open_ports'] = open_ports_found
    if not open_ports_found:
        print_status(f"No common ports open on {ip_address} from the list.", "not_found")
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def discover_paths_and_technologies(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Path & Technology Discovery"
    total_tasks_in_current_stage = len(COMMON_PATHS) + 1 # +1 for robots.txt
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data['path_discovery'] = {'found_paths': [], 'technologies': [], 'robots_txt_status': 'Not Checked'}
    found_paths_list = []

    # Check robots.txt first
    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Checking robots.txt")
    robots_url = urljoin(target_url, '/robots.txt')
    try:
        response = requests.get(robots_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        if response.status_code == 200:
            print_status(f"robots.txt found (Status {response.status_code}). Content length: {len(response.text)}", "found")
            scan_report_data['path_discovery']['robots_txt_status'] = 'Found'
            scan_report_data['path_discovery']['robots_txt_content'] = response.text.splitlines()[:10] # First 10 lines
        else:
            print_status(f"robots.txt not found or access issue (Status {response.status_code})", "not_found")
            scan_report_data['path_discovery']['robots_txt_status'] = f'Not Found (Status {response.status_code})'
    except requests.exceptions.RequestException as e:
        print_status(f"Error checking robots.txt: {str(e)}", "error")
        scan_report_data['path_discovery']['robots_txt_status'] = 'Error'
    time.sleep(0.1)

    for i, path in enumerate(COMMON_PATHS):
        current_task_progress += 1
        full_url = urljoin(target_url, path.lstrip("/"))
        display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Checking {path}")
        try:
            response = requests.get(full_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT-2, allow_redirects=True) # Slightly less timeout for paths
            if response.status_code == 200:
                print_status(f"Path {path} found (Status {response.status_code}) at {full_url}", "found")
                found_paths_list.append({'path': path, 'url': full_url, 'status': response.status_code})
                # Basic tech detection from content or headers (expand later)
                if "wordpress" in response.text.lower() or "wp-content" in response.text.lower():
                    if "WordPress" not in scan_report_data['path_discovery']['technologies']:
                        scan_report_data['path_discovery']['technologies'].append("WordPress")
            elif 300 <= response.status_code < 400:
                 print_status(f"Path {path} redirects (Status {response.status_code}) to {response.headers.get('Location')}", "info")
                 found_paths_list.append({'path': path, 'url': full_url, 'status': response.status_code, 'redirect_to': response.headers.get('Location')})
            # else: print_status(f"Path {path} not found (Status {response.status_code})", "not_found") # Too verbose
        except requests.exceptions.Timeout:
            # print_status(f"Timeout checking path: {path}", "error") # Too verbose
            pass
        except requests.exceptions.RequestException:
            # print_status(f"Error checking path {path}: {str(e)}", "error") # Too verbose
            pass
        time.sleep(0.01)
    scan_report_data['path_discovery']['found_paths'] = found_paths_list
    if scan_report_data['path_discovery']['technologies']:
        print_status(f"Detected technologies: {', '.join(scan_report_data['path_discovery']['technologies'])}", "info")
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def basic_vulnerability_checks(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Security Header & Basic Vulnerability Scan"
    total_tasks_in_current_stage = len(SECURITY_HEADERS_TO_CHECK) + 2 # +2 for server disclosure and http-only/secure cookies (conceptual)
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data['vulnerability_checks'] = {'security_headers': {}, 'other_findings': []}

    try:
        response = requests.get(target_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        headers = response.headers
        
        # Security Headers
        for i, (header_name, config) in enumerate(SECURITY_HEADERS_TO_CHECK.items()):
            current_task_progress += 1
            display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Checking {header_name}")
            header_value = headers.get(header_name)
            finding = {'header': header_name, 'present': bool(header_value), 'value': header_value, 'notes': config['notes']}
            if header_value:
                print_status(f"Header '{header_name}': Present. Value: {header_value[:50]}{'...' if len(header_value)>50 else ''}", "info")
                if 'recommended_value' in config and header_value.lower() != config['recommended_value'].lower():
                    finding['issue'] = f"Not recommended value. Expected '{config['recommended_value']}'."
                    print_status(f"Header '{header_name}': Not optimally configured. Expected '{config['recommended_value']}'.", "not_found") # Using not_found for 'bad config'
            else:
                if config.get('recommended', False):
                    finding['issue'] = "Recommended header is missing."
                    print_status(f"Header '{header_name}': MISSING (Recommended)", "not_found")
                else:
                     print_status(f"Header '{header_name}': Not present.", "info")
            scan_report_data['vulnerability_checks']['security_headers'][header_name] = finding
            time.sleep(0.1)

        # Server Version Disclosure
        current_task_progress += 1
        display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Checking Server Disclosure")
        server_header_val = headers.get('Server')
        if server_header_val:
            print_status(f"Server header: '{server_header_val}'. May disclose version info.", "not_found") # 'not_found' as in 'security best practice not found'
            scan_report_data['vulnerability_checks']['other_findings'].append(f"Server header discloses: {server_header_val}")
        else:
            print_status("Server header: Not disclosed or hidden.", "info")
        time.sleep(0.1)
        
        # Placeholder for cookie checks (to be expanded)
        current_task_progress += 1
        display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Checking Cookie Attributes")
        # TODO: Implement cookie attribute checks (HttpOnly, Secure, SameSite)
        print_status("Cookie attribute checks (HttpOnly, Secure, SameSite) - Placeholder", "info")
        scan_report_data['vulnerability_checks']['other_findings'].append("Cookie attribute checks need further implementation.")
        time.sleep(0.1)

    except requests.exceptions.RequestException as e:
        print_status(f"Could not fetch {target_url} for vulnerability checks: {str(e)}", "error")
        # Mark remaining tasks as complete for progress bar
        while current_task_progress < total_tasks_in_current_stage:
            current_task_progress += 1
            display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Skipping due to error")
            time.sleep(0.01)
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

# --- Report Generation (Step 005) ---
def save_report(target_url):
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_name = urlparse(target_url).hostname.replace('.', '_')
    filename_txt = f"scan_report_{domain_name}_{timestamp_file}.txt"
    filename_json = f"scan_report_{domain_name}_{timestamp_file}.json"

    # TXT Report
    try:
        with open(filename_txt, 'w', encoding='utf-8') as f:
            f.write(f"Web Security Scan Report for: {scan_report_data.get('target_url', 'N/A')}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=====================================================\n\n")
            
            ip_info = scan_report_data.get('ip_info', {})
            f.write("--- IP & Basic Info ---\n")
            f.write(f"  IP Address: {ip_info.get('ip_address', 'N/A')}\n")
            f.write(f"  Server (from HEAD): {ip_info.get('server_type_head', 'N/A')}\n\n")

            port_scan = scan_report_data.get('port_scan', {})
            f.write("--- Port Scan ---\n")
            if port_scan.get('status') == 'Skipped':
                f.write("  Port scan was skipped.\n")
            else:
                f.write(f"  Target IP: {port_scan.get('ip_address', 'N/A')}\n")
                f.write(f"  Open Ports Found ({len(port_scan.get('open_ports', []))}):" + "\n")
                for p in port_scan.get('open_ports', []):
                    f.write(f"    - Port {p['port']} ({p['service']})\n")
                if not port_scan.get('open_ports'): f.write("    None from common list.\n")
            f.write("\n")

            path_disc = scan_report_data.get('path_discovery', {})
            f.write("--- Path & Technology Discovery ---\n")
            f.write(f"  Robots.txt Status: {path_disc.get('robots_txt_status', 'N/A')}\n")
            if path_disc.get('robots_txt_content'):
                 f.write(f"  Robots.txt (first 10 lines):\n")
                 for line in path_disc.get('robots_txt_content',[]):
                     f.write(f"    {line}\n")
                 f.write(f"  Found Paths ({len(path_disc.get('found_paths', []))}):\n")
                 for p in path_disc.get('found_paths', []):
                     f.write(f"    - {p['path']} (Status: {p['status']}) -> {p['url']}\n")
                 if not path_disc.get("found_paths", []):
                     f.write("    None from common list.\n")
            f.write(f"  Detected Technologies: {', '.join(path_disc.get('technologies', ['None']))}\n\n")
            
            vuln_checks = scan_report_data.get('vulnerability_checks', {})
            f.write("--- Security Headers & Basic Vulnerabilities ---\n")
            for header, details in vuln_checks.get('security_headers', {}).items():
                f.write(f"  Header: {header}\n")
                f.write(f"    Present: {details['present']}\n")
                if details['present']: f.write(f"    Value: {str(details['value'])[:100]}{'...' if details['value'] and len(str(details['value'])) > 100 else ''}\n")
                if details.get('issue'): f.write(f"    Issue: {details['issue']}\n")
            for finding in vuln_checks.get('other_findings', []):
                f.write(f"  Other: {finding}\n")
            f.write("\n--- Scan Log ---\n")
            for log_entry in scan_report_data.get('log', []):
                f.write(f"{log_entry}\n")
        print_status(f"Text report saved to {filename_txt}", "info")
    except Exception as e:
        print_status(f"Failed to save text report: {str(e)}", "error")

    # JSON Report
    try:
        with open(filename_json, 'w', encoding='utf-8') as f:
            json.dump(scan_report_data, f, indent=4)
        print_status(f"JSON report saved to {filename_json}", "info")
    except Exception as e:
        print_status(f"Failed to save JSON report: {str(e)}", "error")

# --- Main Scan Orchestration ---
def perform_full_scan(target_url):
    global scan_report_data
    scan_report_data = {'scan_start_time': datetime.now().isoformat()} # Reset report data
    
    print_status(f"Initiating full scan for: {target_url}", "info")
    print("-" * 60)

    retrieve_ip_and_basic_info(target_url)
    print("-" * 60)
    time.sleep(0.5)

    ip_to_scan = scan_report_data.get('ip_info', {}).get('ip_address')
    advanced_port_scan(ip_to_scan)
    print("-" * 60)
    time.sleep(0.5)

    discover_paths_and_technologies(target_url)
    print("-" * 60)
    time.sleep(0.5)

    basic_vulnerability_checks(target_url)
    print("-" * 60)
    time.sleep(0.5)

    scan_report_data['scan_end_time'] = datetime.now().isoformat()
    print_status("Full scan completed.", "stage")
    
    # Save Report
    save_report(target_url)

    input(f"\n{Fore.CYAN}Press Enter to return to the main menu...{Style.RESET_ALL}")

# --- Main Application Loop ---
def main():
    while True:
        clear_screen()
        display_banner()
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Main Menu:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Start New Scan")
        print(f"  {Fore.RED}[2]{Style.RESET_ALL} Exit Scanner")
        
        choice = input(f"\n{Fore.CYAN}{Style.BRIGHT}➤ Select an option [1-2]: {Style.RESET_ALL}").strip()

        if choice == '1':
            clear_screen()
            display_banner() # Show banner again before asking for URL
            target = get_target_url()
            if target:
                perform_full_scan(target)
        elif choice == '2':
            clear_screen()
            print(f"{Fore.BLUE}{Style.BRIGHT}Exiting Advanced Web Security Scanner. Stay Safe!{Style.RESET_ALL}")
            break
        else:
            print_status("Invalid choice. Please select a valid option.", "error")
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

