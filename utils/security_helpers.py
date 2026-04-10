"""
Security testing utilities — headers, SSL, and vulnerability helpers.
"""
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_response(url: str, verify_ssl: bool = True, timeout: int = 10):
    """Fetch a URL and return the response."""
    try:
        return requests.get(url, verify=verify_ssl, timeout=timeout,
                          allow_redirects=True)
    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.ConnectionError:
        return None


def get_headers(url: str) -> dict:
    """Return response headers for a URL."""
    response = get_response(url)
    if response:
        return dict(response.headers)
    return {}


def check_security_header(headers: dict, header_name: str) -> bool:
    """Return True if security header is present (case-insensitive)."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    return header_name.lower() in headers_lower


def get_header_value(headers: dict, header_name: str) -> str:
    """Return header value or empty string if not found."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    return headers_lower.get(header_name.lower(), "")


def check_https_redirect(url: str) -> bool:
    """Return True if HTTP redirects to HTTPS."""
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        return response.url.startswith("https://")
    except Exception:
        return False


def check_cookie_security(cookies) -> dict:
    """Analyze cookies for security flags."""
    results = {}
    for cookie in cookies:
        results[cookie.name] = {
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly") or
                       "httponly" in str(cookie).lower(),
            "samesite": cookie.get_nonstandard_attr("SameSite", "Not Set"),
        }
    return results


def check_sql_injection_basic(url: str, param: str) -> bool:
    """
    Test basic SQL injection — returns True if response seems safe.
    Tests that common SQL injection payloads do not cause errors.
    """
    payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]
    safe = True
    for payload in payloads:
        try:
            response = requests.get(url, params={param: payload}, timeout=10)
            error_keywords = [
                "sql", "mysql", "sqlite", "postgresql", "oracle",
                "syntax error", "unclosed quotation", "odbc", "jdbc"
            ]
            body_lower = response.text.lower()
            if any(kw in body_lower for kw in error_keywords):
                safe = False
                break
        except Exception:
            pass
    return safe


def check_xss_basic(url: str, param: str) -> bool:
    """
    Test basic XSS — returns True if response seems safe.
    Tests that script payloads are not reflected unescaped.
    """
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    safe = True
    for payload in payloads:
        try:
            response = requests.get(url, params={param: payload}, timeout=10)
            if payload in response.text:
                safe = False
                break
        except Exception:
            pass
    return safe


def check_sensitive_data_exposure(url: str) -> dict:
    """Check response for common sensitive data patterns."""
    import re
    response = get_response(url)
    if not response:
        return {"error": "Could not fetch URL"}

    body = response.text
    findings = {
        "api_keys": bool(re.search(r'api[_-]?key["\s:=]+["\']?\w{20,}', body, re.I)),
        "passwords": bool(re.search(r'password["\s:=]+["\'][^"\']{3,}', body, re.I)),
        "emails": bool(re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)),
        "private_keys": bool(re.search(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', body)),
        "aws_keys": bool(re.search(r'AKIA[0-9A-Z]{16}', body)),
    }
    return findings
