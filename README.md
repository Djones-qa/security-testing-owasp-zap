# Security Testing Suite

[![Security Tests](https://github.com/Djones-qa/security-testing-owasp-zap/actions/workflows/security-tests.yml/badge.svg?branch=master)](https://github.com/Djones-qa/security-testing-owasp-zap/actions/workflows/security-tests.yml)

A Python-based security test suite validating OWASP-aligned security controls against real web targets. Tests cover security headers, injection prevention, authentication, CORS policy, and information disclosure.

## Test Coverage

| Module | What it tests |
|---|---|
| `test_security_headers.py` | HTTPS, SSL, X-Content-Type-Options, Server header verbosity |
| `test_injection_attacks.py` | SQL injection and XSS payload handling |
| `test_api_security.py` | Auth (Basic + Bearer), sensitive data exposure, input validation |
| `test_cors_and_disclosure.py` | CORS policy, admin path exposure, file disclosure, rate limiting |

## Targets

- [https://www.saucedemo.com](https://www.saucedemo.com)
- [https://httpbin.org](https://httpbin.org)
- [https://demoqa.com](https://demoqa.com)

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
python -m pytest
```

## Project Structure

```
├── tests/
│   ├── test_security_headers.py
│   ├── test_injection_attacks.py
│   ├── test_api_security.py
│   └── test_cors_and_disclosure.py
├── utils/
│   └── security_helpers.py
├── .github/workflows/
│   └── security-tests.yml
└── pytest.ini
```
