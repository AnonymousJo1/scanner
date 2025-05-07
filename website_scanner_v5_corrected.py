import socket
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup # Added for form parsing
from colorama import init, Fore, Style
import json
import os
import platform
import time
from datetime import datetime
import concurrent.futures # Added for potential threading

# Initialize colorama
init(autoreset=True)

# --- Configuration ---
# Expanded and categorized common paths
ADMIN_LOGIN_PATHS = [
    # General admin paths
    'admin/', 'administrator/', 'login/', 'admin.php', 'administrator.php', 'login.php',
    'admin/login.php', 'administrator/login.php', 'admin/index.php', 'administrator/index.php',
    'admin/home.php', 'administrator/home.php',
    # CMS specific admin paths
    'wp-admin/', 'wp-login.php',
    'joomla/administrator/',
    'drupal/user/login/', 'drupal/admin/',
    'magento/admin/', 'magento/index.php/admin/',
    'user/login/', 'admin/account/login/', 'signin/', 'auth/login/', 'admin/auth/',
    # Common API login/auth endpoints
    'api/login', 'api/auth', 'api/v1/login', 'api/v1/auth',
    # Backup/config files that might be admin related or contain creds
    'admin.bak', 'admin.old', 'admin/config.php', 'administrator/config.php'
]

HIDDEN_PAGE_PATTERNS = [
    'backup/', 'backups/', 'old/', 'temp/', 'dev/', 'test/', 'staging/',
    '.git/', '.svn/', '.hg/',
    'config.php.bak', 'settings.php.bak', 'wp-config.php.bak', '.env', '.env.bak',
    'debug/', 'logs/', 'log.txt', 'error_log', 'dump.sql', 'database.sql.zip',
    'admin_backup/', 'secret_page.html', 'hidden_info.txt'
]

# Combine with existing COMMON_PATHS, ensuring no duplicates and categorization
EXISTING_COMMON_PATHS = [
    'wp-json/wp/v2/users', '?rest_route=/wp/v2/users', 'wp-json/oembed/1.0/embed',
    'wp-json/', 'wp-admin/admin-ajax.php',
    'feed/', 'rss/', 'sitemap.xml', 'robots.txt',
    'api/', 'v1/', 'v2/', 'json/'
]
# Merge and remove duplicates, keeping a broader list for general discovery
ALL_DISCOVERY_PATHS = sorted(list(set(ADMIN_LOGIN_PATHS + HIDDEN_PAGE_PATTERNS + EXISTING_COMMON_PATHS)))

COMMON_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest"]
# WARNING: Using password lists for brute-forcing is unethical and often illegal without explicit permission.
# This is a tiny list for DEMONSTRATION of form interaction ONLY.
DEMO_PASSWORDS = ["admin", "password", "123456", "admin123", "test"]

COMMON_PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 2082, 2083, 2086, 2087,
    3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8008, 8080, 8081, 8443, 9000, 9090, 27017
]
SECURITY_HEADERS_TO_CHECK = {
    'Strict-Transport-Security': {'recommended': True, 'notes': 'Ensures browser only connects via HTTPS.'},
    'Content-Security-Policy': {'recommended': True, 'notes': 'Helps prevent XSS and data injection attacks.'},
    'X-Frame-Options': {'recommended': True, 'notes': 'Protects against clickjacking attacks.'},
    'X-Content-Type-Options': {'recommended_value': 'nosniff', 'notes': 'Prevents MIME-sniffing attacks.'},
    'Referrer-Policy': {'recommended': True, 'notes': 'Controls how much referrer information is sent.'},
    'Permissions-Policy': {'recommended': True, 'notes': 'Controls which browser features can be used.'},
    'X-XSS-Protection': {'recommended_value': '0', 'notes': 'Modern browsers use CSP. Value 1; mode=block can introduce XSS in older IE.'}
}
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 AdvancedWebScanner/2.0'
REQUEST_TIMEOUT = 7 # Increased slightly for more complex pages
MAX_THREADS = 10 # For concurrent operations

# --- Global state for progress and reporting ---
current_task_progress = 0
total_tasks_in_current_stage = 1
current_stage_name = ""
scan_report_data = {}
progress_animation_chars = ["-", "\\", "|", "/"]

# --- UI and Helper Functions ---
def clear_screen():
    os.system('cls' if platform.system() == "Windows" else 'clear')

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
{Fore.CYAN}                 Advanced Web Security Scanner (v5){Style.RESET_ALL}
{Fore.BLUE}           Scanner Made By: {Style.BRIGHT}Anonymous Jordan Team{Style.RESET_ALL}
{Fore.BLUE}           Telegram: {Style.BRIGHT}https://t.me/AnonymousJordan{Style.RESET_ALL}
    """
    print(banner)

def print_status(message, level="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = f"{Fore.BLUE}[{timestamp}]{Style.RESET_ALL}"
    level_color = {
        "info": Fore.CYAN, "found": Fore.GREEN + Style.BRIGHT, "not_found": Fore.YELLOW,
        "error": Fore.RED + Style.BRIGHT, "stage": Fore.MAGENTA + Style.BRIGHT,
        "attempt": Fore.LIGHTBLUE_EX
    }
    print(f"{prefix} {level_color.get(level, Fore.WHITE)}[{level.upper()}]{Style.RESET_ALL} {message}")
    if 'log' not in scan_report_data: scan_report_data['log'] = []
    scan_report_data['log'].append(f"[{timestamp}] [{level.upper()}] {message}")

def display_progress(current, total, stage_name="Scanning", item_name="", bar_length=40):
    progress = float(current) / total if total > 0 else 0
    arrow = '█' * int(round(progress * bar_length))
    spaces = ' ' * (bar_length - len(arrow))
    percent = int(round(progress * 100))
    anim_char = progress_animation_chars[current % len(progress_animation_chars)] if current < total else Fore.GREEN + Style.BRIGHT + '\u2713' + Style.RESET_ALL
    status_line = f"\r{Fore.YELLOW}{Style.BRIGHT}{stage_name}{Style.RESET_ALL} [{Fore.GREEN}{arrow}{Style.RESET_ALL}{spaces}] {percent}% ({current}/{total}) {anim_char} {item_name[:30]:<30}"
    print(status_line, end="")
    if current == total: print()

def get_target_url():
    while True:
        target_url_input = input(f"{Fore.CYAN}{Style.BRIGHT}➤ Enter target website URL (e.g., http://example.com): {Style.RESET_ALL}").strip()
        if not target_url_input: print_status("No URL provided.", "error"); continue
        if not (target_url_input.startswith('http://') or target_url_input.startswith('https://')):
            target_url_input = 'http://' + target_url_input
            print_status(f"No scheme. Assuming http. Using: {target_url_input}", "info")
        try:
            parsed_check = urlparse(target_url_input)
            if not parsed_check.netloc: print_status("Invalid URL format.", "error"); continue
            return target_url_input
        except Exception: print_status("Invalid URL format.", "error")

# --- Scanning Modules ---
def retrieve_ip_and_basic_info(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Initial Reconnaissance"
    total_tasks_in_current_stage = 2
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data.update({'target_url': target_url, 'ip_info': {}})

    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Resolving IP Address")
    try:
        hostname = urlparse(target_url).hostname
        ip_address = socket.gethostbyname(hostname) if hostname else "Not Resolved"
        print_status(f"IP Address: {ip_address}", "found" if "Resolved" not in ip_address else "not_found")
        scan_report_data['ip_info']['ip_address'] = ip_address
    except socket.gaierror: scan_report_data['ip_info']['ip_address'] = "Resolution Failed"; print_status(f"Failed to resolve IP for {hostname}.", "error")
    except Exception as e: scan_report_data['ip_info']['ip_address'] = "Error"; print_status(f"Error resolving IP: {e}", "error")
    time.sleep(0.2)

    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Fetching initial headers")
    try:
        response = requests.head(target_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        server_type = response.headers.get('Server', 'Not Disclosed')
        print_status(f"Server Type (from HEAD): {server_type}", "info")
        scan_report_data['ip_info']['server_type_head'] = server_type
    except requests.exceptions.RequestException as e: scan_report_data['ip_info']['server_type_head'] = "Error fetching"; print_status(f"Could not fetch initial headers: {e}", "error")
    time.sleep(0.2)
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def scan_single_port(args):
    ip_address, port = args
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3) # Slightly increased for reliability
            if sock.connect_ex((ip_address, port)) == 0:
                service_name = "unknown"
                try: service_name = socket.getservbyport(port)
                except: pass
                return {'port': port, 'service': service_name, 'status': 'open'}
    except socket.error: pass # Silently fail for closed/filtered ports in threads
    except Exception: pass
    return {'port': port, 'status': 'closed'}

def advanced_port_scan(ip_address):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    if not ip_address or "Failed" in ip_address or "Error" in ip_address:
        print_status("Skipping port scan due to IP resolution failure.", "info")
        scan_report_data['port_scan'] = {'status': 'Skipped', 'open_ports': []}
        return

    current_stage_name = "Advanced Port Scanning (Threaded)"
    total_tasks_in_current_stage = len(COMMON_PORTS_TO_SCAN)
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {ip_address}", "stage")
    scan_report_data['port_scan'] = {'ip_address': ip_address, 'open_ports': [], 'checked_ports_count': 0}
    open_ports_found = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_single_port, (ip_address, port)) for port in COMMON_PORTS_TO_SCAN]
        for future in concurrent.futures.as_completed(futures):
            current_task_progress += 1
            result = future.result()
            scan_report_data['port_scan']['checked_ports_count'] += 1
            if result and result['status'] == 'open':
                open_ports_found.append(result)
                print_status(f"Port {result['port']} ({result['service']}) is OPEN", "found")
            display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Port {result['port']}")
    
    scan_report_data['port_scan']['open_ports'] = open_ports_found
    if not open_ports_found: print_status(f"No common ports open on {ip_address} from the list.", "not_found")
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def check_single_path(args):
    target_url, path = args
    full_url = urljoin(target_url, path.lstrip("/"))
    try:
        response = requests.get(full_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT - 2, allow_redirects=False, verify=False) # Added verify=False for self-signed certs
        return {'path': path, 'url': full_url, 'status': response.status_code, 'content_type': response.headers.get('Content-Type', ''), 'content_length': len(response.content), 'response_headers': dict(response.headers), 'is_login_page': any(keyword in path.lower() for keyword in ['login', 'admin', 'auth', 'signin'])}
    except requests.exceptions.Timeout: return {'path': path, 'url': full_url, 'status': 'Timeout'}
    except requests.exceptions.RequestException: return {'path': path, 'url': full_url, 'status': 'Error'}

def discover_paths_and_technologies(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Deep Path & Technology Discovery (Threaded)"
    paths_to_check = ALL_DISCOVERY_PATHS
    total_tasks_in_current_stage = len(paths_to_check) + 1 # +1 for robots.txt
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data['path_discovery'] = {'found_paths': [], 'potential_login_pages': [], 'technologies': [], 'robots_txt_status': 'Not Checked', 'robots_txt_content': []}
    found_items = []

    # Check robots.txt first (not threaded as it's a single quick check)
    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Checking robots.txt")
    robots_url = urljoin(target_url, '/robots.txt')
    try:
        response = requests.get(robots_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
        if response.status_code == 200:
            print_status(f"robots.txt found. Length: {len(response.text)}", "found")
            scan_report_data['path_discovery']['robots_txt_status'] = 'Found'
            scan_report_data['path_discovery']['robots_txt_content'] = response.text.splitlines()
        else:
            scan_report_data['path_discovery']['robots_txt_status'] = f'Not Found (Status {response.status_code})'
    except requests.exceptions.RequestException as e: scan_report_data['path_discovery']['robots_txt_status'] = f'Error: {e}'
    time.sleep(0.1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_single_path, (target_url, path)) for path in paths_to_check]
        for future in concurrent.futures.as_completed(futures):
            current_task_progress += 1
            result = future.result()
            if result and result['status'] != 'Error' and result['status'] != 'Timeout':
                if result['status'] == 200:
                    print_status(f"Path {result['path']} found (200) at {result['url']}", "found")
                    found_items.append(result)
                    if result['is_login_page'] or "login" in result['url'].lower() or "admin" in result['url'].lower():
                         scan_report_data['path_discovery']['potential_login_pages'].append(result['url'])
                    if "wp-json/wp/v2/users" in result['path']:
                        scan_report_data['path_discovery']['technologies'].append("WordPress (User Enum Possible)")
                elif 300 <= result['status'] < 400:
                    print_status(f"Path {result['path']} redirects ({result['status']}) to {result['response_headers'].get('Location')}", "info")
                    found_items.append(result) # Store redirects too
            display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"{result['path']}")
    
    scan_report_data['path_discovery']['found_paths'] = found_items
    # Deduplicate login pages
    scan_report_data['path_discovery']['potential_login_pages'] = sorted(list(set(scan_report_data['path_discovery']['potential_login_pages'])))
    if scan_report_data['path_discovery']['technologies']: print_status(f"Detected technologies: {', '.join(list(set(scan_report_data['path_discovery']['technologies'])))}", "info")
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def attempt_admin_credential_discovery(target_url, login_pages):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Admin Credential Discovery"
    # This is a complex task. For now, focus on WordPress user enumeration and marking login pages.
    # True credential guessing is out of scope for this iteration due to ethical and complexity reasons.
    total_tasks_in_current_stage = 1 + len(login_pages) # 1 for WP user enum, +1 for each login page check (conceptual)
    current_task_progress = 0
    print_status(f"Starting {current_stage_name}", "stage")
    scan_report_data['admin_credentials'] = {'wordpress_users': [], 'potential_login_attempts': [], 'notes': "Credential guessing is highly sensitive and not fully implemented. Focus is on enumeration."}

    # WordPress User Enumeration (if applicable)
    current_task_progress += 1
    display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "WP User Enum")
    wp_user_api_path = 'wp-json/wp/v2/users'
    wp_user_url = urljoin(target_url, wp_user_api_path)
    try:
        response = requests.get(wp_user_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, verify=False)
        if response.status_code == 200:
            users_data = response.json()
            if isinstance(users_data, list) and users_data:
                for user_entry in users_data:
                    if isinstance(user_entry, dict) and 'slug' in user_entry:
                        username = user_entry['slug']
                        scan_report_data['admin_credentials']['wordpress_users'].append(username)
                        print_status(f"WordPress user found via API: {username}", "found")
                if not scan_report_data['admin_credentials']['wordpress_users']:
                    print_status(f"WordPress user API ({wp_user_api_path}) accessible but no user slugs found or unexpected format.", "not_found")        
            elif response.status_code == 401 or response.status_code == 403:
                 print_status(f"WordPress user API ({wp_user_api_path}) requires authentication.", "info") 
            else:
                print_status(f"WordPress user API ({wp_user_api_path}) check returned status {response.status_code}.", "info")
    except requests.exceptions.RequestException as e:
        print_status(f"Error checking WordPress user API ({wp_user_api_path}): {e}", "error")
    except json.JSONDecodeError:
        print_status(f"Error decoding JSON from WordPress user API ({wp_user_api_path}).", "error")
    time.sleep(0.1)

    # Placeholder for login form interaction (very basic for now)
    for login_url in login_pages:
        current_task_progress += 1
        display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Analyzing {login_url.split("/")[-1]}")
        # This would involve parsing forms, trying default creds. Highly complex.
        # For now, just log that we identified it as a login page.
        attempt_info = {'login_url': login_url, 'status': 'Identified as potential login page. Manual review recommended for credential testing.'}
        scan_report_data['admin_credentials']['potential_login_attempts'].append(attempt_info)
        print_status(f"Identified potential login page: {login_url}. Manual review needed.", "info")
        time.sleep(0.1)

    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

def basic_vulnerability_checks(target_url):
    global current_task_progress, total_tasks_in_current_stage, current_stage_name
    current_stage_name = "Security Header & Basic Vulnerability Scan"
    total_tasks_in_current_stage = len(SECURITY_HEADERS_TO_CHECK) + 2
    current_task_progress = 0
    print_status(f"Starting {current_stage_name} for {target_url}", "stage")
    scan_report_data['vulnerability_checks'] = {'security_headers': {}, 'other_findings': []}
    try:
        response = requests.get(target_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
        headers = response.headers
        for i, (header_name, config) in enumerate(SECURITY_HEADERS_TO_CHECK.items()):
            current_task_progress += 1; display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, f"Checking {header_name}")
            header_value = headers.get(header_name)
            finding = {'header': header_name, 'present': bool(header_value), 'value': header_value, 'notes': config['notes']}
            if header_value:
                if 'recommended_value' in config and header_value.lower().strip() != config['recommended_value'].lower().strip():
                    finding['issue'] = f"Value not recommended ('{config['recommended_value']}')"
            elif config.get('recommended'): finding['issue'] = "Header is missing."
            scan_report_data['vulnerability_checks']['security_headers'][header_name] = finding
            if finding.get('issue'): print_status(f"Header \t'{header_name}': {finding['issue']}", "not_found")
            else: print_status(f"Header \t'{header_name}': Present.", "info")
            time.sleep(0.05)
        current_task_progress += 1; display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Server Disclosure")
        for h_name in ['Server', 'X-Powered-By']:
            if h_val := headers.get(h_name): scan_report_data['vulnerability_checks']['other_findings'].append(f"{h_name} Disclosure: {h_val}"); print_status(f"{h_name} discloses: {h_val}", "info")
        time.sleep(0.05)
        current_task_progress += 1; display_progress(current_task_progress, total_tasks_in_current_stage, current_stage_name, "Cookie Security (Basic)")
        # Basic cookie check (conceptual)
        time.sleep(0.05)
    except requests.exceptions.RequestException as e: print_status(f"Could not perform vulnerability checks: {e}", "error")
    display_progress(total_tasks_in_current_stage, total_tasks_in_current_stage, current_stage_name, "Completed")

# --- Reporting ---
def generate_html_report(report_data):
    # This is a placeholder for a more complex HTML generation
    # For now, it will be a very simple pre-formatted text in HTML
    html_content = "<html><head><title>Scan Report</title>"
    html_content += "<style>body { font-family: Arial, sans-serif; margin: 20px; } "
    html_content += "h1, h2, h3 { color: #333; } pre { background-color: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow-x: auto; } "
    html_content += ".found { color: green; font-weight: bold; } .not_found { color: orange; } .error { color: red; font-weight: bold; } </style></head><body>"
    html_content += f"<h1>Scan Report for: {report_data.get('target_url', 'N/A')}</h1>"
    html_content += f"<p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
    
    html_content += "<h2>Summary:</h2><pre>"
    # Simplified summary - more detail can be added
    html_content += f"IP Address: {report_data.get('ip_info', {}).get('ip_address', 'N/A')}\n"
    html_content += f"Open Ports: {len(report_data.get('port_scan', {}).get('open_ports', []))}\n"
    html_content += f"Paths Found: {len(report_data.get('path_discovery', {}).get('found_paths', []))}\n"
    html_content += f"Potential Login Pages: {len(report_data.get('path_discovery', {}).get('potential_login_pages', []))}\n"
    if report_data.get('admin_credentials', {}).get('wordpress_users'):
        html_content += f"WordPress Users Found: {', '.join(report_data['admin_credentials']['wordpress_users'])}\n"
    html_content += "</pre>"

    html_content += "<h2>Full Details (JSON):</h2>"
    html_content += f"<pre>{json.dumps(report_data, indent=2)}</pre>"
    html_content += "</body></html>"
    return html_content

def save_report():
    global scan_report_data
    if not scan_report_data.get('target_url'): print_status("No scan data to save.", "error"); return
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_name = urlparse(scan_report_data['target_url']).netloc.replace('.', '_').replace(':', '_')
    report_dir = "scan_reports"
    if not os.path.exists(report_dir): os.makedirs(report_dir, exist_ok=True)
    filename_base = os.path.join(report_dir, f"scan_{domain_name}_{timestamp_file}")
    filenames = {'txt': f"{filename_base}.txt", 'json': f"{filename_base}.json", 'html': f"{filename_base}.html"}
    print_status(f"Saving reports to {filename_base}.[txt/json/html]...", "info")
    try:
        with open(filenames['txt'], 'w', encoding='utf-8') as f: # Simplified TXT report
            f.write(json.dumps(scan_report_data, indent=2)) # For now, TXT is also JSON pretty print
        print_status(f"Text report saved to {filenames['txt']}", "info")
    except Exception as e: print_status(f"Failed to save text report: {e}", "error")
    try:
        with open(filenames['json'], 'w', encoding='utf-8') as f: json.dump(scan_report_data, f, indent=4)
        print_status(f"JSON report saved to {filenames['json']}", "info")
    except Exception as e: print_status(f"Failed to save JSON report: {e}", "error")
    try:
        html_report_content = generate_html_report(scan_report_data)
        with open(filenames['html'], 'w', encoding='utf-8') as f: f.write(html_report_content)
        print_status(f"HTML report saved to {filenames['html']}", "info")
        # Attempt to open HTML report
        try:
            if platform.system() == "Windows": os.startfile(os.path.abspath(filenames['html']))
            elif platform.system() == "Darwin": os.system(f"open {os.path.abspath(filenames['html'])}")
            else: os.system(f"xdg-open {os.path.abspath(filenames['html'])}")
        except Exception as e:
            print_status(f"Could not automatically open HTML report: {e}. Please open it manually.", "info")
    except Exception as e: print_status(f"Failed to save HTML report: {e}", "error")

# --- Main Scan Process ---
def main_scan_process(target_url):
    global scan_report_data; scan_report_data = {}
    clear_screen(); display_banner()
    print_status(f"Starting comprehensive scan for: {target_url}", "stage")

    retrieve_ip_and_basic_info(target_url)
    ip_address = scan_report_data.get('ip_info', {}).get('ip_address')
    if ip_address and "Failed" not in ip_address and "Error" not in ip_address:
        advanced_port_scan(ip_address)
    else: 
        print_status("Skipping Port Scan.", "info")
        scan_report_data['port_scan'] = {'status': 'Skipped'}
    
    discover_paths_and_technologies(target_url)
    potential_login_pages = scan_report_data.get('path_discovery', {}).get('potential_login_pages', [])
    attempt_admin_credential_discovery(target_url, potential_login_pages)
    basic_vulnerability_checks(target_url)

    print_status("Comprehensive scan finished.", "stage")
    save_report()
    print(f"\n{Fore.YELLOW}Scan complete. Reports saved in '{os.path.join(os.getcwd(), 'scan_reports') if os.path.exists('scan_reports') else '.'}'.{Style.RESET_ALL}")
    input(f"\n{Fore.GREEN}Press Enter to return to the main menu...{Style.RESET_ALL}")

# --- Main Application Loop ---
def main():
    while True:
        clear_screen(); display_banner()
        print("\nMain Menu:")
        print(f"  {Fore.GREEN}[1]{Style.RESET_ALL} Start New Scan")
        print(f"  {Fore.RED}[2]{Style.RESET_ALL} Exit Scanner")
        choice = input(f"\n{Fore.CYAN}{Style.BRIGHT}➤ Select an option [1-2]: {Style.RESET_ALL}").strip()
        if choice == '1':
            target_site = get_target_url()
            if target_site: main_scan_process(target_site)
        elif choice == '2': print_status("Exiting scanner. Goodbye!", "info"); break
        else: print_status("Invalid option.", "error"); time.sleep(1.5)

if __name__ == "__main__":
    # Ensure BeautifulSoup is available
    try:
        import bs4
    except ImportError:
        print("BeautifulSoup4 is not installed. Please install it: pip install beautifulsoup4")
        exit(1)
    main()

