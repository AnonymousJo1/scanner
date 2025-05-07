import socket
import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style
import json

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

def get_ip_address(url):
    """
    Retrieves the IP address of a given URL.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            ip_address = socket.gethostbyname(hostname)
            print(f"{Fore.GREEN}[+] {Style.BRIGHT}عنوان IP:{Style.RESET_ALL} {ip_address}")
            return ip_address
        else:
            print(f"{Fore.RED}[-] تعذر تحديد اسم المضيف من الرابط: {url}")
            return None
    except socket.gaierror:
        print(f"{Fore.RED}[-] فشل في الحصول على عنوان IP لـ {url}. تعذر تحديد اسم المضيف.")
        return None
    except Exception as e:
        print(f"{Fore.RED}[-] حدث خطأ أثناء الحصول على عنوان IP: {e}")
        return None

def scan_ports(ip_address, ports_to_scan):
    """
    Scans a list of common ports on a given IP address.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}يتم فحص المنافذ الشائعة لـ {ip_address}...{Style.RESET_ALL}")
    open_ports = []
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.2) # مهلة قصيرة لفحص أسرع
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] المنفذ {port} مفتوح")
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            # Redundant if timeout is very short, but good for other errors
            # print(f"{Fore.RED}[-] تعذر الاتصال بالمنفذ {port}: {e}")
            pass # Avoid too much noise for closed/filtered ports
        except Exception as e:
            print(f"{Fore.RED}[-] حدث خطأ أثناء فحص المنفذ {port}: {e}")
    if not open_ports:
        print(f"{Fore.YELLOW}[-] لم يتم العثور على منافذ شائعة مفتوحة على {ip_address} من القائمة المفحوصة.")
    return open_ports

def find_admin_and_user_info(url):
    """
    Attempts to find admin pages and user/password related endpoints.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}يتم البحث عن صفحات المسؤول ومعلومات المستخدم لـ {url}...{Style.RESET_ALL}")
    
    original_url = url
    # Ensure URL has a scheme, try https first then http
    if not (url.startswith('http://') or url.startswith('https://')):
        schemes_to_try = ['https://', 'http://']
    elif url.startswith('http://'):
        schemes_to_try = ['http://', 'https://'] # If http, also try https
    else: # url starts with https://
        schemes_to_try = ['https://', 'http://'] # If https, also try http

    found_anything_globally = False

    for scheme in schemes_to_try:
        base_url = scheme + urlparse(original_url).netloc + urlparse(original_url).path.rstrip('/')
        if urlparse(original_url).query: # Append query if exists
            base_url += "?" + urlparse(original_url).query
        if not urlparse(original_url).path and not base_url.endswith('/'): # Ensure trailing slash for domain root
             base_url += '/' 

        print(f"{Fore.BLUE}  [*] يتم المحاولة باستخدام {scheme} ...")
        found_pages_for_scheme = []
        try:
            # Test base URL connectivity for this scheme
            requests.get(base_url, timeout=3, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException:
            print(f"{Fore.YELLOW}  [-] تعذر الاتصال بـ {base_url}. يتم تخطي هذا البروتوكول.")
            continue # Try next scheme

        for path in COMMON_PATHS:
            # Construct full_url carefully
            # If path starts with '?', it's a query for the base_url
            if path.startswith('?'):
                full_url = base_url.rstrip('/') + path
            else:
                full_url = base_url.rstrip('/') + '/' + path.lstrip('/')
            
            try:
                response = requests.get(full_url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
                if response.status_code == 200:
                    print(f"{Fore.GREEN}  [+] تم العثور على: {full_url} (الحالة: {response.status_code})")
                    found_pages_for_scheme.append(full_url)
                    found_anything_globally = True
                    if 'wp-json/wp/v2/users' in path or '?rest_route=/wp/v2/users' in path:
                        try:
                            users_data = response.json()
                            if isinstance(users_data, list) and len(users_data) > 0:
                                print(f"{Fore.MAGENTA}    [*] بيانات مستخدمين محتملة في {full_url}:")
                                for user_entry in users_data:
                                    if isinstance(user_entry, dict):
                                        user_slug = user_entry.get('slug', 'N/A')
                                        user_name = user_entry.get('name', 'N/A')
                                        print(f"{Fore.MAGENTA}      - Slug المستخدم: {user_slug}, اسم المستخدم: {user_name}")
                        except json.JSONDecodeError:
                            print(f"{Fore.YELLOW}    [!] المحتوى في {full_url} ليس بتنسيق JSON صالح، ولكن الصفحة موجودة.")
                        except Exception as e_json:
                            print(f"{Fore.RED}    [!] خطأ في معالجة JSON من {full_url}: {e_json}")
                elif 300 <= response.status_code < 400:
                    print(f"{Fore.YELLOW}  [?] تم العثور على (إعادة توجيه): {full_url} (الحالة: {response.status_code}) -> {response.headers.get('Location')}")
                    found_anything_globally = True # Count redirects as a find
            except requests.exceptions.Timeout:
                print(f"{Fore.RED}  [-] انتهت مهلة الاتصال لـ {full_url}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}  [-] خطأ في الوصول إلى {full_url}: {type(e).__name__}")
            except Exception as e_general:
                print(f"{Fore.RED}  [-] حدث خطأ غير متوقع مع {full_url}: {e_general}")
        
        if found_pages_for_scheme: # If we found something with this scheme, likely it's the correct one
            break # Stop trying other schemes if one works and finds paths
        elif scheme == schemes_to_try[0] and not found_anything_globally: # If first scheme failed and found nothing
            print(f"{Fore.YELLOW}  [-] لم يتم العثور على مسارات شائعة باستخدام {scheme}. يتم محاولة البروتوكول التالي إذا متاح.")

    if not found_anything_globally:
        print(f"{Fore.YELLOW}[-] لم يتم العثور على أي من مسارات المسؤول/المستخدم الشائعة لـ {original_url} بعد تجربة البروتوكولات المتاحة.")
    return found_anything_globally # Return true if anything was found across schemes

def check_vulnerabilities(url):
    """
    Performs basic vulnerability checks.
    """
    print(f"\n{Fore.CYAN}[*] {Style.BRIGHT}يتم التحقق من الثغرات الأمنية الأساسية لـ {url}...{Style.RESET_ALL}")
    
    # Ensure URL has a scheme, prefer https
    if not (url.startswith('http://') or url.startswith('https://')):
        test_url_https = 'https://' + url.lstrip('/')
        test_url_http = 'http://' + url.lstrip('/') 
        try:
            response = requests.get(test_url_https, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            url = test_url_https
        except requests.exceptions.RequestException:
            try:
                response = requests.get(test_url_http, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                url = test_url_http
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[-] تعذر الاتصال بـ {url} لفحص الثغرات: {e}")
                return
    else:
        try:
            response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[-] تعذر الاتصال بـ {url} لفحص الثغرات: {e}")
            return

    headers = response.headers
    print(f"{Fore.BLUE}  [*] رؤوس الخادم:")
    for key, value in headers.items():
        print(f"{Fore.BLUE}    {key}: {value}")

    if 'X-Frame-Options' not in headers:
        print(f"{Fore.YELLOW}  [!] ترويسة X-Frame-Options مفقودة (احتمالية ثغرة Clickjacking).")
    else:
        print(f"{Fore.GREEN}  [+] ترويسة X-Frame-Options موجودة: {headers['X-Frame-Options']}")

    if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
        print(f"{Fore.YELLOW}  [!] ترويسة X-Content-Type-Options ليست 'nosniff' (احتمالية ثغرة MIME sniffing)." )
    else:
        print(f"{Fore.GREEN}  [+] ترويسة X-Content-Type-Options هي 'nosniff'.")

    if 'Content-Security-Policy' not in headers:
        print(f"{Fore.YELLOW}  [!] ترويسة Content-Security-Policy مفقودة.")
    else:
        print(f"{Fore.GREEN}  [+] ترويسة Content-Security-Policy موجودة: {headers['Content-Security-Policy'][:100]}...")

    if url.startswith("https://") and 'Strict-Transport-Security' not in headers:
        print(f"{Fore.YELLOW}  [!] ترويسة Strict-Transport-Security (HSTS) مفقودة لموقع HTTPS.")
    elif url.startswith("https://") and 'Strict-Transport-Security' in headers:
        print(f"{Fore.GREEN}  [+] ترويسة Strict-Transport-Security (HSTS) موجودة.")

    server_header = headers.get('Server')
    if server_header:
        print(f"{Fore.BLUE}  [*] ترويسة الخادم: {server_header}")
        if any(ver in server_header.lower() for ver in ['apache/', 'nginx/', 'iis/', 'litespeed']):
             print(f"{Fore.YELLOW}    [!] تم الكشف عن معلومات إصدار الخادم المحتملة. قد يساعد هذا المهاجمين.")
    else:
        print(f"{Fore.GREEN}  [+] ترويسة الخادم غير موجودة أو مخفية بشكل جيد.")

    robots_url = url.rstrip('/') + '/robots.txt'
    try:
        robots_response = requests.get(robots_url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        if robots_response.status_code == 200:
            print(f"{Fore.GREEN}  [+] تم العثور على robots.txt في {robots_url}. راجع محتواه بحثًا عن كشوفات حساسة.")
        else:
            print(f"{Fore.YELLOW}  [-] لم يتم العثور على robots.txt أو لا يمكن الوصول إليه (الحالة: {robots_response.status_code}).")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}  [-] خطأ في الوصول إلى robots.txt في {robots_url}.")

    print(f"{Fore.YELLOW}\n[!] ملاحظة: فحص الثغرات موضوع معقد. هذه الأداة تقوم بفحوصات أساسية جداً.")
    print(f"{Fore.YELLOW}    للفحص الشامل، ضع في اعتبارك أدوات مخصصة مثل Nikto، Nmap scripts، OWASP ZAP، إلخ.")

def main():
    print(f"{Fore.MAGENTA}{Style.BRIGHT}======================================")
    print(f"   أداة فحص معلومات الموقع   ")
    print(f"======================================{Style.RESET_ALL}\n")

    target_url_input = input(f"{Fore.YELLOW}أدخل رابط الموقع المستهدف (مثال: example.com أو http://example.com): {Style.RESET_ALL}").strip()

    if not target_url_input:
        print(f"{Fore.RED}[-] لم يتم تقديم رابط. يتم الخروج.")
        return

    # Section 1: Get IP Address
    print(f"\n{Fore.BLUE}--- القسم: معلومات IP ---{Style.RESET_ALL}")
    # Add http:// if no scheme is present for get_ip_address, as it expects a full URL for parsing hostname
    url_for_ip = target_url_input
    if not (url_for_ip.startswith('http://') or url_for_ip.startswith('https://')):
        url_for_ip = 'http://' + url_for_ip
    ip_address = get_ip_address(url_for_ip)

    # Section 2: Port Scanning
    if ip_address:
        print(f"\n{Fore.BLUE}--- القسم: فحص المنافذ ---{Style.RESET_ALL}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
        scan_ports(ip_address, common_ports)

    # Section 3: Admin Page and User/Password Path Finder
    # This function will handle scheme internally
    print(f"\n{Fore.BLUE}--- القسم: البحث عن مسارات المسؤول والمستخدمين ---{Style.RESET_ALL}")
    find_admin_and_user_info(target_url_input) # Pass original input

    # Section 4: Vulnerability Checks (Basic)
    # This function will handle scheme internally
    print(f"\n{Fore.BLUE}--- القسم: فحوصات الثغرات الأساسية ---{Style.RESET_ALL}")
    check_vulnerabilities(target_url_input) # Pass original input

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}======================================")
    print(f"   اكتمل الفحص لـ {target_url_input}   ")
    print(f"======================================{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()

