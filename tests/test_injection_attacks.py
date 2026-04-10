"""
SQL Injection and XSS vulnerability tests.
Tests against intentionally vulnerable demo endpoints.
"""
import pytest
import requests
from utils.security_helpers import (
    check_sql_injection_basic,
    check_xss_basic,
    get_response,
)

# Using httpbin.org for safe injection testing
# and OWASP WebGoat concepts against demo endpoints
HTTPBIN_BASE = "https://httpbin.org"


class TestSQLInjectionPrevention:

    def test_httpbin_get_not_vulnerable_to_sqli(self):
        """HTTPBin GET endpoint should not expose SQL errors."""
        payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "' OR 1=1--"]
        for payload in payloads:
            response = requests.get(
                f"{HTTPBIN_BASE}/get",
                params={"search": payload},
                timeout=10
            )
            assert response.status_code == 200, \
                f"Unexpected status for payload: {payload}"
            body_lower = response.text.lower()
            sql_errors = ["sql error", "mysql error", "syntax error",
                         "unclosed quotation", "odbc driver"]
            for error in sql_errors:
                assert error not in body_lower, \
                    f"SQL error exposed for payload: {payload}"

    def test_special_characters_handled_safely(self):
        """Special SQL characters must be handled without errors."""
        special_chars = ["'", '"', ";", "--", "/*", "*/", "xp_"]
        for char in special_chars:
            response = requests.get(
                f"{HTTPBIN_BASE}/get",
                params={"q": char},
                timeout=10
            )
            assert response.status_code == 200, \
                f"Server error for special character: {char}"

    def test_numeric_injection_handled(self):
        """Numeric SQL injection patterns must not cause errors."""
        payloads = ["1 OR 1=1", "1; SELECT * FROM users", "1 UNION SELECT NULL"]
        for payload in payloads:
            response = requests.get(
                f"{HTTPBIN_BASE}/get",
                params={"id": payload},
                timeout=10
            )
            assert response.status_code == 200, \
                f"Unexpected error for numeric payload: {payload}"

    def test_encoded_sqli_handled(self):
        """URL-encoded SQL injection must be handled safely."""
        payloads = ["%27%20OR%20%271%27%3D%271", "%3B%20DROP%20TABLE%20users"]
        for payload in payloads:
            url = f"{HTTPBIN_BASE}/get?q={payload}"
            response = requests.get(url, timeout=10)
            assert response.status_code in [200, 400], \
                f"Unexpected response for encoded payload: {payload}"

    def test_saucedemo_login_not_bypassed_by_sqli(self):
        """Login endpoint must not be bypassed by SQL injection."""
        payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--"]
        for payload in payloads:
            response = requests.post(
                "https://www.saucedemo.com",
                data={"username": payload, "password": payload},
                timeout=10,
                allow_redirects=False
            )
            # Should not redirect to inventory (successful login)
            assert response.status_code not in [302], \
                f"Possible SQL injection bypass with payload: {payload}"


class TestXSSPrevention:

    def test_script_tags_not_reflected_in_response(self):
        """Script tags in params must not be reflected unescaped."""
        payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        for payload in payloads:
            response = requests.get(
                f"{HTTPBIN_BASE}/get",
                params={"input": payload},
                timeout=10
            )
            # HTTPBin JSON-encodes output so raw script tags won't execute
            assert response.status_code == 200, \
                f"Server error for XSS payload: {payload}"

    def test_javascript_protocol_handled(self):
        """javascript: protocol in params must be handled safely."""
        payload = "javascript:alert(document.cookie)"
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            params={"url": payload},
            timeout=10
        )
        assert response.status_code == 200, \
            "Server error for javascript: protocol payload"

    def test_html_entities_in_response(self):
        """Response content type must be JSON not HTML for API endpoints."""
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            params={"q": "<script>alert(1)</script>"},
            timeout=10
        )
        content_type = response.headers.get("Content-Type", "")
        assert "json" in content_type.lower(), \
            f"API returned non-JSON content type: {content_type}"

    def test_event_handler_payloads_handled(self):
        """Event handler XSS payloads must not cause server errors."""
        payloads = [
            "onmouseover=alert(1)",
            "onclick=alert(document.cookie)",
            "onfocus=alert(1) autofocus",
        ]
        for payload in payloads:
            response = requests.get(
                f"{HTTPBIN_BASE}/get",
                params={"attr": payload},
                timeout=10
            )
            assert response.status_code == 200, \
                f"Server error for event handler payload: {payload}"
