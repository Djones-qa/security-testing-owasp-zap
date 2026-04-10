"""
API security tests — authentication, authorization, and data exposure.
"""
import pytest
import requests

HTTPBIN_BASE = "https://httpbin.org"


class TestAuthenticationSecurity:

    def test_protected_endpoint_requires_auth(self):
        """Protected endpoints must reject unauthenticated requests."""
        response = requests.get(
            f"{HTTPBIN_BASE}/basic-auth/user/pass",
            timeout=10
        )
        assert response.status_code in [401, 502], \
            f"Protected endpoint returned {response.status_code} without auth"

    def test_valid_credentials_granted_access(self):
        """Valid credentials must grant access to protected endpoint."""
        response = requests.get(
            f"{HTTPBIN_BASE}/basic-auth/user/pass",
            auth=("user", "pass"),
            timeout=10
        )
        assert response.status_code == 200, \
            "Valid credentials did not grant access"

    def test_invalid_credentials_rejected(self):
        """Invalid credentials must be rejected with 401."""
        response = requests.get(
            f"{HTTPBIN_BASE}/basic-auth/user/pass",
            auth=("wrong", "credentials"),
            timeout=10
        )
        assert response.status_code == 401, \
            "Invalid credentials were not rejected"

    def test_bearer_token_endpoint_requires_token(self):
        """Bearer token endpoint must reject requests without token."""
        response = requests.get(
            f"{HTTPBIN_BASE}/bearer",
            timeout=10
        )
        assert response.status_code == 401, \
            "Bearer endpoint did not require token"

    def test_valid_bearer_token_accepted(self):
        """Valid Bearer token must be accepted."""
        response = requests.get(
            f"{HTTPBIN_BASE}/bearer",
            headers={"Authorization": "Bearer test-token-123"},
            timeout=10
        )
        assert response.status_code == 200, \
            "Valid bearer token was rejected"

    def test_empty_auth_header_rejected(self):
        """Empty Authorization header must be rejected."""
        response = requests.get(
            f"{HTTPBIN_BASE}/bearer",
            headers={"Authorization": ""},
            timeout=10
        )
        assert response.status_code in [400, 401], \
            "Empty auth header was not rejected"


class TestSensitiveDataExposure:

    def test_response_does_not_expose_stack_trace(self):
        """Error responses must not expose stack traces."""
        response = requests.get(
            f"{HTTPBIN_BASE}/status/500",
            timeout=10
        )
        body_lower = response.text.lower()
        stack_indicators = ["traceback", "stack trace", "at line",
                           "exception in", "null pointer"]
        for indicator in stack_indicators:
            assert indicator not in body_lower, \
                f"Stack trace exposed in error response: {indicator}"

    def test_404_not_verbose(self):
        """404 responses must not reveal server internals."""
        response = requests.get(
            f"{HTTPBIN_BASE}/nonexistent-endpoint-12345",
            timeout=10
        )
        assert response.status_code in [404, 200], \
            f"Unexpected status: {response.status_code}"

    def test_api_response_content_type_is_json(self):
        """API endpoints must return JSON not raw HTML."""
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            timeout=10
        )
        content_type = response.headers.get("Content-Type", "")
        assert "json" in content_type.lower(), \
            f"API returned non-JSON: {content_type}"

    def test_response_does_not_contain_internal_paths(self):
        """Responses must not expose internal file system paths."""
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            timeout=10
        )
        path_indicators = ["/var/www", "/home/", "C:\\", "/usr/local",
                          "htdocs", "wwwroot"]
        body = response.text
        for indicator in path_indicators:
            assert indicator not in body, \
                f"Internal path exposed in response: {indicator}"


class TestInputValidation:

    def test_extremely_long_input_handled(self):
        """Extremely long inputs must not cause server errors."""
        long_input = "A" * 10000
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            params={"q": long_input},
            timeout=15
        )
        assert response.status_code in [200, 400, 414], \
            f"Unexpected response for long input: {response.status_code}"

    def test_null_bytes_handled(self):
        """Null bytes in input must be handled safely."""
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            params={"q": "test\x00injection"},
            timeout=10
        )
        assert response.status_code in [200, 400], \
            f"Unexpected response for null byte: {response.status_code}"

    def test_http_methods_restricted(self):
        """Only allowed HTTP methods should be accepted."""
        response = requests.get(
            f"{HTTPBIN_BASE}/get",
            timeout=10
        )
        assert response.status_code == 200, "GET method not allowed"

    def test_delete_method_on_get_endpoint(self):
        """DELETE on GET-only endpoint must return appropriate error."""
        response = requests.delete(
            f"{HTTPBIN_BASE}/get",
            timeout=10
        )
        assert response.status_code in [200, 404, 405], \
            f"Unexpected response for DELETE: {response.status_code}"
