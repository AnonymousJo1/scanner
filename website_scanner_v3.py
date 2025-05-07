import socket
import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style
import json
import os
import platform
import time

# Initialize colorama
init(autoreset=True)

COMMON_PATHS = [
    'wp-json/wp/v2/users',
    '?rest_route=/wp/v2/users',
    'wp-json/oembed/1.0/embed',
    'wp-json/',
    'feed/',
    'author/',
    '?author=1',
    'wp-admin/admin-ajax.php',
    'wp-login.php',
    'xmlrpc.php',
    'admin/',
    'administrator/',
    'login/',
    'wp-admin/',
    'admin.php',
    'administrator.php',
    'login.php'
]
COMMON_PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
VULN_CHECKS_COUNT = 6 # Approximate number of vulnerability checks

def clear_screen():
    """Clears the terminal screen."""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    """Displays the scanner banner."""
    # clear_screen() # Clearing is now handled before banner in main loop
    banner_text = f"""
{Fore.RED}{Style.BRIGHT}
    ███████╗ ██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝ ██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║  ███╗███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║   ██║██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╔╝██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}                        Scanner Made By  : Anonymous Jordan Team{Style.RESET_ALL}
{Fore.CYAN}                        Telegram Link   : https://t.me/AnonymousJordan{Style.RESET_ALL}
    """
    print(banner_text)

def print_progress_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█', print_end="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        print_end   - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{:0." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{Fore.YELLOW}{prefix} |{bar}| {percent}% {suffix}{Style.RESET_ALL}', end=print_end)
    if iteration == total:
        print() # New line on complete

current_scan_step = 0
total_scan_steps = 1 # Initialize with 1 to avoid division by zero if not calculated properly

def update_global_progress():
    global current_scan_step
    current_scan_step += 1
    print_progress_bar(current_scan_step, total_scan_steps, prefix='Overall Progress:', suffix='Complete', length=50)

def get_ip_address(url):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Stage: Retrieving IP Address{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scanning: {url} for IP Address...{Style.RESET_ALL}")
    ip_address = None
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}[+] Found: IP Address is {ip_address}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Not Found: Could not determine hostname from URL: {url}{Style.RESET_ALL}")
    except socket.gaierror:
        print(f"{Fore.RED}[-] Not Found: Failed to get IP for {url}. Hostname could not be resolved.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: An error occurred while getting IP address: {e}{Style.RESET_ALL}")
    update_global_progress()
    return ip_address

def scan_ports(ip_address, ports_to_scan):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Stage: Scanning Ports{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scanning: Common ports for {ip_address}...{Style.RESET_ALL}")
    open_ports_found = []
    for i, port in enumerate(ports_to_scan):
        print(f"{Fore.CYAN}  Checking port: {port}...{Style.RESET_ALL}", end=' ')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1) # Even shorter timeout
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"{Fore.GREEN}Found: Port {port} is open{Style.RESET_ALL}")
                open_ports_found.append(port)
            else:
                print(f"{Fore.YELLOW}Not Found: Port {port} is closed or filtered{Style.RESET_ALL}")
            sock.close()
        except socket.error:
            print(f"{Fore.RED}Error: Could not connect to port {port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: An error occurred while scanning port {port}: {e}{Style.RESET_ALL}")
        update_global_progress()
        time.sleep(0.05) # Small delay to make progress visible

    if not open_ports_found:
        print(f"{Fore.YELLOW}[-] Summary: No common open ports found on {ip_address} from the scanned list.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Summary: Open ports found: {open_ports_found}{Style.RESET_ALL}")
    return open_ports_found

def find_admin_and_user_info(url):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Stage: Searching for Admin Pages & User Info{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scanning: {url} for common admin/user paths...{Style.RESET_ALL}")
    
    original_url = url
    if not (url.startswith('http://') or url.startswith('https://')):
        schemes_to_try = ['https://', 'http://']
    elif url.startswith('http://'):
        schemes_to_try = ['http://', 'https://']
    else: 
        schemes_to_try = ['https://', 'http://']

    found_anything_globally = False
    paths_found_details = []

    for scheme_idx, scheme in enumerate(schemes_to_try):
        base_url_netloc = urlparse(original_url).netloc
        base_url_path_orig = urlparse(original_url).path
        base_url_query = urlparse(original_url).query

        current_base_url = scheme + base_url_netloc
        if base_url_path_orig:
            current_base_url += base_url_path_orig.rstrip('/')
        if not base_url_path_orig and not current_base_url.endswith('/'):
             current_base_url += '/' 
        if base_url_query:
             current_base_url += "?" + base_url_query
        if not base_url_path_orig and not current_base_url.endswith('/') and not base_url_query:
            current_base_url += '/'

        print(f"{Fore.BLUE}  Trying with {scheme} (Base: {current_base_url.split('?')[0]}){Style.RESET_ALL}")
        try:
            requests.get(current_base_url.split('?')[0], timeout=3, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException:
            print(f"{Fore.YELLOW}  Could not connect to {current_base_url.split('?')[0]}. Skipping this protocol.{Style.RESET_ALL}")
            # Decrement total steps if a scheme is skipped early, or adjust initial calculation
            # For simplicity, we'll update progress for each path attempt regardless of scheme success here
            # but a more accurate progress would account for this.
            if scheme_idx == 0: # If first scheme fails, all its paths are skipped
                for _ in COMMON_PATHS:
                    update_global_progress()
            continue 

        found_pages_for_this_scheme = False
        for path_idx, path in enumerate(COMMON_PATHS):
            print(f"{Fore.CYAN}    Checking path: {path}...{Style.RESET_ALL}", end=' ')
            if path.startswith('?'):
                full_url = current_base_url.rstrip('/') + path
            else:
                full_url = current_base_url.rstrip('/') + '/' + path.lstrip('/')
            
            try:
                response = requests.get(full_url, timeout=3, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    status_msg = f"{Fore.GREEN}Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}"
                    print(status_msg)
                    paths_found_details.append(full_url + " (200)")
                    found_pages_for_this_scheme = True
                    found_anything_globally = True
                    if 'wp-json/wp/v2/users' in path or '?rest_route=/wp/v2/users' in path:
                        try:
                            users_data = response.json()
                            if isinstance(users_data, list) and len(users_data) > 0:
                                print(f"{Fore.MAGENTA}      [*] Potential user data at {full_url}:{Style.RESET_ALL}")
                                for user_entry in users_data:
                                    if isinstance(user_entry, dict):
                                        user_slug = user_entry.get('slug', 'N/A')
                                        user_name = user_entry.get('name', 'N/A')
                                        print(f"{Fore.MAGENTA}        - User Slug: {user_slug}, User Name: {user_name}{Style.RESET_ALL}")
                        except json.JSONDecodeError:
                            print(f"{Fore.YELLOW}      [!] Content at {full_url} is not valid JSON, but page exists.{Style.RESET_ALL}")
                        except Exception as e_json:
                            print(f"{Fore.RED}      [!] Error processing JSON from {full_url}: {e_json}{Style.RESET_ALL}")
                elif 300 <= response.status_code < 400:
                    status_msg = f"{Fore.YELLOW}Found (Redirect): {full_url} (Status: {response.status_code}) -> {response.headers.get('Location')}{Style.RESET_ALL}"
                    print(status_msg)
                    paths_found_details.append(f"{full_url} ({response.status_code} -> {response.headers.get('Location')})")
                    found_anything_globally = True
                else:
                    print(f"{Fore.YELLOW}Not Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
            except requests.exceptions.Timeout:
                print(f"{Fore.RED}Timeout: for {full_url}{Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}Error: accessing {full_url}: {type(e).__name__}{Style.RESET_ALL}")
            except Exception as e_general:
                print(f"{Fore.RED}Error: Unexpected error with {full_url}: {e_general}{Style.RESET_ALL}")
            update_global_progress()
            time.sleep(0.05)
        
        if found_pages_for_this_scheme:
            # If found with one scheme, skip other schemes for these paths
            # Adjust remaining progress steps if we break early
            remaining_paths_in_other_schemes = len(COMMON_PATHS) * (len(schemes_to_try) - 1 - scheme_idx)
            for _ in range(remaining_paths_in_other_schemes):
                update_global_progress()
            break 

    if not found_anything_globally:
        print(f"{Fore.YELLOW}[-] Summary: No common admin/user paths found for {original_url}.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Summary: Found potential admin/user paths:{Style.RESET_ALL}")
        for pfd in paths_found_details:
            print(f"{Fore.GREEN}    - {pfd}{Style.RESET_ALL}")
    return found_anything_globally

def check_vulnerabilities(url):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Stage: Basic Vulnerability Checks{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scanning: {url} for basic security headers and misconfigurations...{Style.RESET_ALL}")
    
    test_url = url
    response = None
    if not (test_url.startswith('http://') or test_url.startswith('https://')):
        test_url_https = 'https://' + test_url.lstrip('/')
        test_url_http = 'http://' + test_url.lstrip('/') 
        try:
            print(f"{Fore.CYAN}  Checking connectivity with HTTPS: {test_url_https}...{Style.RESET_ALL}", end=' ')
            response = requests.get(test_url_https, timeout=3, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            test_url = test_url_https
            print(f"{Fore.GREEN}Connected.{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            print(f"{Fore.YELLOW}Failed. Trying HTTP...{Style.RESET_ALL}")
            try:
                print(f"{Fore.CYAN}  Checking connectivity with HTTP: {test_url_http}...{Style.RESET_ALL}", end=' ')
                response = requests.get(test_url_http, timeout=3, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
                test_url = test_url_http
                print(f"{Fore.GREEN}Connected.{Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}Error: Could not connect to {url} for vulnerability checks: {e}{Style.RESET_ALL}")
                for _ in range(VULN_CHECKS_COUNT): update_global_progress() # Mark all vuln checks as 'done'
                return
    else:
        try:
            print(f"{Fore.CYAN}  Checking connectivity: {test_url}...{Style.RESET_ALL}", end=' ')
            response = requests.get(test_url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            print(f"{Fore.GREEN}Connected.{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error: Could not connect to {url} for vulnerability checks: {e}{Style.RESET_ALL}")
            for _ in range(VULN_CHECKS_COUNT): update_global_progress()
            return

    if not response:
        print(f"{Fore.RED}[-] Could not get a response from {url}. Skipping vulnerability checks.{Style.RESET_ALL}")
        for _ in range(VULN_CHECKS_COUNT): update_global_progress()
        return

    headers = response.headers
    print(f"{Fore.BLUE}  Server Headers Analysis:{Style.RESET_ALL}")
    # X-Frame-Options
    print(f"{Fore.CYAN}    Checking X-Frame-Options header...{Style.RESET_ALL}", end=' ')
    if 'X-Frame-Options' not in headers:
        print(f"{Fore.YELLOW}Not Found: X-Frame-Options header missing (Potential Clickjacking).{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Found: X-Frame-Options header present: {headers['X-Frame-Options']}{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    # X-Content-Type-Options
    print(f"{Fore.CYAN}    Checking X-Content-Type-Options header...{Style.RESET_ALL}", end=' ')
    if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
        print(f"{Fore.YELLOW}Not Optimal: X-Content-Type-Options header not 'nosniff' (Potential MIME sniffing). Value: {headers.get('X-Content-Type-Options', 'Not Set')}{Style.RESET_ALL}" )
    else:
        print(f"{Fore.GREEN}Found: X-Content-Type-Options header is 'nosniff'.{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    # Content-Security-Policy
    print(f"{Fore.CYAN}    Checking Content-Security-Policy header...{Style.RESET_ALL}", end=' ')
    if 'Content-Security-Policy' not in headers:
        print(f"{Fore.YELLOW}Not Found: Content-Security-Policy header missing.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Found: Content-Security-Policy header present: {headers['Content-Security-Policy'][:60]}...{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    # Strict-Transport-Security (HSTS)
    print(f"{Fore.CYAN}    Checking Strict-Transport-Security (HSTS) header (for HTTPS)...{Style.RESET_ALL}", end=' ')
    if test_url.startswith("https://"):
        if 'Strict-Transport-Security' not in headers:
            print(f"{Fore.YELLOW}Not Found: Strict-Transport-Security (HSTS) header missing for HTTPS site.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Found: Strict-Transport-Security (HSTS) header present.{Style.RESET_ALL}")
    else:
        print(f"{Fore.BLUE}Skipped: Site is not HTTPS.{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    # Server Header
    print(f"{Fore.CYAN}    Checking Server header...{Style.RESET_ALL}", end=' ')
    server_header = headers.get('Server')
    if server_header:
        print(f"{Fore.YELLOW}Found: Server header: {server_header}. Version info might be exposed.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Not Found or Hidden: Server header not present or well-hidden.{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    # robots.txt
    print(f"{Fore.CYAN}    Checking for robots.txt...{Style.RESET_ALL}", end=' ')
    robots_url = test_url.rstrip('/') + '/robots.txt'
    try:
        robots_response = requests.get(robots_url, timeout=2, headers={'User-Agent': 'Mozilla/5.0'})
        if robots_response.status_code == 200:
            print(f"{Fore.GREEN}Found: robots.txt at {robots_url}. Review its content.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Not Found: robots.txt not found or not accessible (Status: {robots_response.status_code}).{Style.RESET_ALL}")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Error: accessing robots.txt at {robots_url}.{Style.RESET_ALL}")
    update_global_progress()
    time.sleep(0.05)

    print(f"{Fore.YELLOW}\n[!] Note: Vulnerability scanning is complex. This tool performs very basic checks.{Style.RESET_ALL}")

def perform_scan():
    global current_scan_step, total_scan_steps
    current_scan_step = 0
    # Calculate total steps for progress bar
    # Number of schemes to try for admin paths (approx 1 or 2)
    # For simplicity, let's assume 1 successful scheme for admin paths for calculation
    total_scan_steps = 1 + len(COMMON_PORTS_TO_SCAN) + len(COMMON_PATHS) + VULN_CHECKS_COUNT

    target_url_input = input(f"{Fore.CYAN}➤ Enter the target website URL (e.g., example.com): {Style.RESET_ALL}").strip()

    if not target_url_input:
        print(f"{Fore.RED}[-] No URL provided. Returning to main menu.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- Starting Scan for: {target_url_input} ---{Style.RESET_ALL}")
    print_progress_bar(current_scan_step, total_scan_steps, prefix='Overall Progress:', suffix='Complete', length=50)

    # Section 1: IP Information
    url_for_ip = target_url_input
    if not (url_for_ip.startswith('http://') or url_for_ip.startswith('https://')):
        url_for_ip = 'http://' + url_for_ip # Default to http for IP lookup if no scheme
    ip_address = get_ip_address(url_for_ip)

    # Section 2: Port Scanning
    if ip_address:
        scan_ports(ip_address, COMMON_PORTS_TO_SCAN)
    else:
        print(f"{Fore.YELLOW}[-] Skipping port scan as IP address was not found.{Style.RESET_ALL}")
        # Account for skipped port scan steps in progress
        for _ in range(len(COMMON_PORTS_TO_SCAN)):
            update_global_progress()

    # Section 3: Admin & User Path Finder
    find_admin_and_user_info(target_url_input) # Pass original input

    # Section 4: Basic Vulnerability Checks
    check_vulnerabilities(target_url_input) # Pass original input
    
    # Ensure progress bar reaches 100% if steps were miscounted or skipped
    if current_scan_step < total_scan_steps:
        print_progress_bar(total_scan_steps, total_scan_steps, prefix='Overall Progress:', suffix='Complete', length=50)

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}=============================================")
    print(f"   Scan completed for {target_url_input}   ")
    print(f"============================================={Style.RESET_ALL}\n")
    input(f"{Fore.CYAN}Press Enter to return to the main menu...{Style.RESET_ALL}")

def main():
    while True:
        clear_screen()
        display_banner()
        print(f"{Fore.YELLOW}{Style.BRIGHT}Choose an option:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  [1] Start Scan{Style.RESET_ALL}")
        print(f"{Fore.RED}  [2] Exit{Style.RESET_ALL}")
        choice = input(f"\n{Fore.CYAN}{Style.BRIGHT}➤ Enter your choice [1-2]: {Style.RESET_ALL}").strip()

        if choice == '1':
            perform_scan()
        elif choice == '2':
            clear_screen()
            print(f"{Fore.BLUE}{Style.BRIGHT}Exiting scanner. Goodbye!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}[-] Invalid choice. Please enter 1 or 2.{Style.RESET_ALL}")
            input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

