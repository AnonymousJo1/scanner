import socket
import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style
import json
import os
import platform

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

def clear_screen():
    """Clears the terminal screen."""
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def display_banner():
    """Displays the scanner banner."""
    clear_screen()
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

def get_ip_address(url):
    """
    Retrieves the IP address of a given URL.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}[+] {Style.BRIGHT}IP Address:{Style.RESET_ALL} {ip_address}")
            return ip_address
        else:
            print(f"{Fore.RED}[-] Could not determine hostname from URL: {url}")
            return None
    except socket.gaierror:
        print(f"{Fore.RED}[-] Failed to get IP for {url}. Hostname could not be resolved.")
        return None
    except Exception as e:
        print(f"{Fore.RED}[-] An error occurred while getting IP address: {e}")
        return None

def scan_ports(ip_address, ports_to_scan):
    """
    Scans a list of common ports on a given IP address.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}Scanning common ports for {ip_address}...{Style.RESET_ALL}")
    open_ports = []
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.2) # Short timeout for faster scanning
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} is open")
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            pass # Avoid too much noise for closed/filtered ports
        except Exception as e:
            print(f"{Fore.RED}[-] An error occurred while scanning port {port}: {e}")
    if not open_ports:
        print(f"{Fore.YELLOW}[-] No common open ports found on {ip_address} from the scanned list.")
    return open_ports

def find_admin_and_user_info(url):
    """
    Attempts to find admin pages and user/password related endpoints.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}Searching for admin pages and user info for {url}...{Style.RESET_ALL}")
    
    original_url = url
    if not (url.startswith('http://') or url.startswith('https://')):
        schemes_to_try = ['https://', 'http://']
    elif url.startswith('http://'):
        schemes_to_try = ['http://', 'https://']
    else: 
        schemes_to_try = ['https://', 'http://']

    found_anything_globally = False

    for scheme in schemes_to_try:
        base_url_netloc = urlparse(original_url).netloc
        base_url_path = urlparse(original_url).path
        base_url_query = urlparse(original_url).query

        # Construct base_url carefully to avoid issues with paths like example.com/path
        current_base_url = scheme + base_url_netloc
        if base_url_path:
            current_base_url += base_url_path.rstrip('/')
        if not base_url_path and not current_base_url.endswith('/'):
             current_base_url += '/' # Ensure trailing slash for domain root or if path is empty
        if base_url_query:
             current_base_url += "?" + base_url_query
        
        # If the original URL was just a domain (e.g., example.com), ensure base_url ends with /
        if not base_url_path and not current_base_url.endswith('/') and not base_url_query:
            current_base_url += '/'

        print(f"{Fore.BLUE}  [*] Trying with {scheme} ... Base: {current_base_url}{Style.RESET_ALL}")
        found_pages_for_scheme = False
        try:
            requests.get(current_base_url.split('?')[0], timeout=3, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException:
            print(f"{Fore.YELLOW}  [-] Could not connect to {current_base_url.split('?')[0]}. Skipping this protocol.{Style.RESET_ALL}")
            continue 

        for path in COMMON_PATHS:
            if path.startswith('?'):
                full_url = current_base_url.rstrip('/') + path
            else:
                full_url = current_base_url.rstrip('/') + '/' + path.lstrip('/')
            
            try:
                response = requests.get(full_url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    print(f"{Fore.GREEN}  [+] Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
                    found_pages_for_scheme = True
                    found_anything_globally = True
                    if 'wp-json/wp/v2/users' in path or '?rest_route=/wp/v2/users' in path:
                        try:
                            users_data = response.json()
                            if isinstance(users_data, list) and len(users_data) > 0:
                                print(f"{Fore.MAGENTA}    [*] Potential user data at {full_url}:{Style.RESET_ALL}")
                                for user_entry in users_data:
                                    if isinstance(user_entry, dict):
                                        user_slug = user_entry.get('slug', 'N/A')
                                        user_name = user_entry.get('name', 'N/A')
                                        print(f"{Fore.MAGENTA}      - User Slug: {user_slug}, User Name: {user_name}{Style.RESET_ALL}")
                        except json.JSONDecodeError:
                            print(f"{Fore.YELLOW}    [!] Content at {full_url} is not valid JSON, but page exists.{Style.RESET_ALL}")
                        except Exception as e_json:
                            print(f"{Fore.RED}    [!] Error processing JSON from {full_url}: {e_json}{Style.RESET_ALL}")
                elif 300 <= response.status_code < 400:
                    print(f"{Fore.YELLOW}  [?] Found (Redirect): {full_url} (Status: {response.status_code}) -> {response.headers.get('Location')}{Style.RESET_ALL}")
                    found_anything_globally = True 
            except requests.exceptions.Timeout:
                print(f"{Fore.RED}  [-] Timeout for {full_url}{Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}  [-] Error accessing {full_url}: {type(e).__name__}{Style.RESET_ALL}")
            except Exception as e_general:
                print(f"{Fore.RED}  [-] Unexpected error with {full_url}: {e_general}{Style.RESET_ALL}")
        
        if found_pages_for_scheme:
            break 
        elif scheme == schemes_to_try[0] and not found_anything_globally:
            print(f"{Fore.YELLOW}  [-] No common paths found using {scheme}. Trying next protocol if available.{Style.RESET_ALL}")

    if not found_anything_globally:
        print(f"{Fore.YELLOW}[-] No common admin/user paths found for {original_url} after trying available protocols.{Style.RESET_ALL}")
    return found_anything_globally

def check_vulnerabilities(url):
    """
    Performs basic vulnerability checks.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}Checking basic security headers for {url}...{Style.RESET_ALL}")
    
    test_url = url
    if not (test_url.startswith('http://') or test_url.startswith('https://')):
        test_url_https = 'https://' + test_url.lstrip('/')
        test_url_http = 'http://' + test_url.lstrip('/') 
        try:
            response = requests.get(test_url_https, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
            test_url = test_url_https
        except requests.exceptions.RequestException:
            try:
                response = requests.get(test_url_http, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
                test_url = test_url_http
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[-] Could not connect to {url} for vulnerability checks: {e}{Style.RESET_ALL}")
                return
    else:
        try:
            response = requests.get(test_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] Could not connect to {url} for vulnerability checks: {e}{Style.RESET_ALL}")
            return

    headers = response.headers
    print(f"{Fore.BLUE}  [*] Server Headers:{Style.RESET_ALL}")
    for key, value in headers.items():
        print(f"{Fore.BLUE}    {key}: {value}{Style.RESET_ALL}")

    if 'X-Frame-Options' not in headers:
        print(f"{Fore.YELLOW}  [!] X-Frame-Options header missing (Potential Clickjacking).{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}  [+] X-Frame-Options header present: {headers['X-Frame-Options']}{Style.RESET_ALL}")

    if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
        print(f"{Fore.YELLOW}  [!] X-Content-Type-Options header not 'nosniff' (Potential MIME sniffing).{Style.RESET_ALL}" )
    else:
        print(f"{Fore.GREEN}  [+] X-Content-Type-Options header is 'nosniff'.{Style.RESET_ALL}")

    if 'Content-Security-Policy' not in headers:
        print(f"{Fore.YELLOW}  [!] Content-Security-Policy header missing.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}  [+] Content-Security-Policy header present: {headers['Content-Security-Policy'][:100]}...{Style.RESET_ALL}")

    if test_url.startswith("https://") and 'Strict-Transport-Security' not in headers:
        print(f"{Fore.YELLOW}  [!] Strict-Transport-Security (HSTS) header missing for HTTPS site.{Style.RESET_ALL}")
    elif test_url.startswith("https://") and 'Strict-Transport-Security' in headers:
        print(f"{Fore.GREEN}  [+] Strict-Transport-Security (HSTS) header present.{Style.RESET_ALL}")

    server_header = headers.get('Server')
    if server_header:
        print(f"{Fore.BLUE}  [*] Server header: {server_header}{Style.RESET_ALL}")
        if any(ver in server_header.lower() for ver in ['apache/', 'nginx/', 'iis/', 'litespeed']):
             print(f"{Fore.YELLOW}    [!] Server version information might be exposed. This could help attackers.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}  [+] Server header not present or well-hidden.{Style.RESET_ALL}")

    robots_url = test_url.rstrip('/') + '/robots.txt'
    try:
        robots_response = requests.get(robots_url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        if robots_response.status_code == 200:
            print(f"{Fore.GREEN}  [+] robots.txt found at {robots_url}. Review its content for sensitive disclosures.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}  [-] robots.txt not found or not accessible (Status: {robots_response.status_code}).{Style.RESET_ALL}")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}  [-] Error accessing robots.txt at {robots_url}.{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}\n[!] Note: Vulnerability scanning is complex. This tool performs very basic checks.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}    For comprehensive scanning, consider dedicated tools like Nikto, Nmap scripts, OWASP ZAP, etc.{Style.RESET_ALL}")


def perform_scan():
    target_url_input = input(f"{Fore.YELLOW}Enter the target website URL (e.g., example.com or http://example.com): {Style.RESET_ALL}").strip()

    if not target_url_input:
        print(f"{Fore.RED}[-] No URL provided. Exiting scan.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.BLUE}--- Section: IP Information ---{Style.RESET_ALL}")
    url_for_ip = target_url_input
    if not (url_for_ip.startswith('http://') or url_for_ip.startswith('https://')):
        url_for_ip = 'http://' + url_for_ip
    ip_address = get_ip_address(url_for_ip)

    if ip_address:
        print(f"\n{Fore.BLUE}--- Section: Port Scanning ---{Style.RESET_ALL}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
        scan_ports(ip_address, common_ports)

    print(f"\n{Fore.BLUE}--- Section: Admin & User Path Finder ---{Style.RESET_ALL}")
    find_admin_and_user_info(target_url_input)

    print(f"\n{Fore.BLUE}--- Section: Basic Vulnerability Checks ---{Style.RESET_ALL}")
    check_vulnerabilities(target_url_input)

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}======================================")
    print(f"   Scan completed for {target_url_input}   ")
    print(f"======================================{Style.RESET_ALL}\n")
    input(f"{Fore.CYAN}Press Enter to return to the main menu...{Style.RESET_ALL}")

def main():
    while True:
        display_banner()
        print(f"{Fore.YELLOW}{Style.BRIGHT}Choose an option:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}1. Start Scan{Style.RESET_ALL}")
        print(f"{Fore.RED}2. Exit{Style.RESET_ALL}")
        choice = input(f"{Fore.CYAN}Enter your choice (1-2): {Style.RESET_ALL}").strip()

        if choice == '1':
            clear_screen() # Clear screen before starting scan section
            display_banner() # Display banner again for context
            print(f"{Fore.MAGENTA}{Style.BRIGHT}======================================")
            print(f"         Website Scan Tool        ")
            print(f"======================================{Style.RESET_ALL}\n")
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

