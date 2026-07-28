"""Security headers check — flags missing or weak HTTP security headers (OWASP A05:2021)."""

from ..models import Finding
from ..severity import Severity

OWASP_CAT = "A05:2021 - Security Misconfiguration"

# header_name -> (severity, description, remediation)
REQUIRED_HEADERS = {
    "strict-transport-security": (
        Severity.HIGH,
        "HSTS header is missing, so browsers won't enforce HTTPS on repeat visits.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS.",
    ),
    "x-content-type-options": (
        Severity.MEDIUM,
        "Missing X-Content-Type-Options allows MIME-sniffing attacks in older browsers.",
        "Add `X-Content-Type-Options: nosniff`.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Missing X-Frame-Options / frame-ancestors CSP directive leaves the site open to clickjacking.",
        "Add `X-Frame-Options: SAMEORIGIN` or a CSP `frame-ancestors` directive.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy header — reduces defense-in-depth against XSS.",
        "Define a CSP appropriate to your app (start with `default-src 'self'` and tighten from there).",
    ),
    "referrer-policy": (
        Severity.LOW,
        "No Referrer-Policy set — full URLs (potentially with sensitive query params) may leak to third parties.",
        "Add `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "No Permissions-Policy header — browser features (camera, mic, geolocation) aren't explicitly restricted.",
        "Add a `Permissions-Policy` header disabling features you don't use, e.g. `camera=(), microphone=()`.",
    ),
}

SERVER_HEADER_LEAK = (
    Severity.LOW,
    "Server/X-Powered-By header discloses backend technology and version.",
    "Suppress or genericize the `Server` / `X-Powered-By` response headers.",
)


def run(session, base_url: str) -> list:
    findings = []
    resp = session.get(base_url, timeout=10, allow_redirects=True)
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, (severity, desc, fix) in REQUIRED_HEADERS.items():
        if header not in headers_lower:
            findings.append(
                Finding(
                    check="security_headers",
                    title=f"Missing {header}",
                    severity=severity,
                    description=desc,
                    remediation=fix,
                    owasp_category=OWASP_CAT,
                )
            )

    for leaky in ("server", "x-powered-by"):
        if leaky in headers_lower:
            severity, desc, fix = SERVER_HEADER_LEAK
            findings.append(
                Finding(
                    check="security_headers",
                    title=f"Information disclosure via {leaky}",
                    severity=severity,
                    description=desc,
                    remediation=fix,
                    evidence=f"{leaky}: {headers_lower[leaky]}",
                    owasp_category=OWASP_CAT,
                )
            )

    return findings
