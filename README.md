# SentinelScan

A lightweight command-line web vulnerability scanner that detects common **OWASP Top 10** security misconfigurations and generates actionable security reports.

Built with Python as a practical security assessment tool for developers, students, and security professionals.

---

# Features

SentinelScan performs the following security checks:

| Check | Description | OWASP Category |
|--------|-------------|----------------|
| **Security Headers** | Detects missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and information disclosure through `Server` or `X-Powered-By` headers. | A05:2021 – Security Misconfiguration |
| **Cookie Security** | Identifies cookies missing `Secure`, `HttpOnly`, or `SameSite` attributes. | A05:2021 – Security Misconfiguration |
| **TLS Configuration** | Detects plaintext HTTP usage, outdated TLS versions, and expired or expiring certificates. | A02:2021 – Cryptographic Failures |
| **Exposed Files** | Checks for publicly accessible `.env`, `.git`, backup files, `phpinfo.php`, `server-status`, and other sensitive resources. | A01:2021 – Broken Access Control |
| **Port Scan** | Detects commonly exposed services such as Redis, MongoDB, Telnet, FTP, SSH, SMB, RDP, and more using pure Python sockets. | A05:2021 – Security Misconfiguration |

Every finding includes:

- Severity level
- Plain-language explanation
- Recommended remediation
- Associated OWASP category

The goal is to generate reports that developers and security teams can immediately act upon.

---

# Installation

```bash
git clone https://github.com/mohakchaudhary203/sentinelscan.git
cd sentinelscan
pip install -e .
```

## Requirements

- Python 3.9+
- No external binaries
- No Nmap dependency
- No OpenSSL CLI dependency

SentinelScan relies only on Python's standard library and the `requests` package.

---

# Usage

### Run a complete scan

```bash
sentinelscan https://example.com
```

### Run selected checks

```bash
sentinelscan https://example.com --checks security_headers cookie_security
```

### Export reports

```bash
sentinelscan https://example.com --json report.json --markdown report.md
```

### CI/CD Integration

Exit with a non-zero status if HIGH or CRITICAL findings are detected.

```bash
sentinelscan https://example.com --quiet --json report.json
```

---

# Example Output

```text
SentinelScan Report

Target: https://example.com
Scanned: 2026-01-15 10:32:00 UTC

Risk Score: 27/100
Grade: C

[HIGH]
Missing Strict-Transport-Security

HSTS header is missing, allowing browsers to access the site over HTTP.

Recommendation:
Add:

Strict-Transport-Security:
max-age=31536000;
includeSubDomains

OWASP:
A05:2021 – Security Misconfiguration

-------------------------------------------------

[MEDIUM]
Cookie "session" missing HttpOnly

The cookie is accessible via JavaScript, increasing the impact of Cross-Site Scripting (XSS).

Recommendation:
Enable the HttpOnly attribute.

OWASP:
A05:2021 – Security Misconfiguration
```

---

# Project Structure

```text
sentinelscan/
├── sentinelscan/
│   ├── cli.py
│   ├── scanner.py
│   ├── models.py
│   ├── severity.py
│   ├── report.py
│   └── checks/
│       ├── headers.py
│       ├── cookies.py
│       ├── tls.py
│       ├── exposed_files.py
│       └── ports.py
├── tests/
├── README.md
├── LICENSE
├── pyproject.toml
└── .gitignore
```

Each security check is implemented as an independent module exposing:

```python
run(session, base_url) -> list[Finding]
```

New checks can be added with minimal changes by registering them in the scanner.

---

# Running Tests

Install development dependencies:

```bash
pip install -e ".[dev]"
```

Run the test suite:

```bash
pytest tests/ -v
```

The tests use mocked HTTP responses, allowing the suite to execute completely offline without requiring a live target.

---

# Responsible Use

SentinelScan is intended **only for authorized security testing**.

Only scan systems that:

- You own
- You manage
- You have explicit written permission to assess

Unauthorized security scanning may violate applicable laws and regulations.

---

# License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.