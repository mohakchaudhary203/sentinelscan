"""Cookie security check — flags cookies missing Secure/HttpOnly/SameSite flags (OWASP A05:2021)."""

from ..models import Finding
from ..severity import Severity

OWASP_CAT = "A05:2021 - Security Misconfiguration"


def run(session, base_url: str) -> list:
    findings = []
    resp = session.get(base_url, timeout=10, allow_redirects=True)

    set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else None
    if not set_cookie_headers:
        # Fall back to requests' parsed cookie jar (loses some flag detail but still useful)
        set_cookie_headers = [f"{c.name}=..." for c in resp.cookies]

    for raw_cookie in set_cookie_headers or []:
        cookie_name = raw_cookie.split("=")[0].strip()
        lower = raw_cookie.lower()

        if "secure" not in lower and base_url.startswith("https"):
            findings.append(
                Finding(
                    check="cookie_security",
                    title=f"Cookie '{cookie_name}' missing Secure flag",
                    severity=Severity.MEDIUM,
                    description="Cookie can be transmitted over unencrypted HTTP connections.",
                    remediation="Set the `Secure` attribute on all cookies served over HTTPS.",
                    evidence=raw_cookie[:120],
                    owasp_category=OWASP_CAT,
                )
            )

        if "httponly" not in lower:
            findings.append(
                Finding(
                    check="cookie_security",
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    description="Cookie is accessible via JavaScript, increasing XSS impact if present.",
                    remediation="Set the `HttpOnly` attribute so client-side scripts cannot read the cookie.",
                    evidence=raw_cookie[:120],
                    owasp_category=OWASP_CAT,
                )
            )

        if "samesite" not in lower:
            findings.append(
                Finding(
                    check="cookie_security",
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    description="Cookie may be sent on cross-site requests, increasing CSRF exposure.",
                    remediation="Set `SameSite=Lax` (or `Strict` where feasible).",
                    evidence=raw_cookie[:120],
                    owasp_category=OWASP_CAT,
                )
            )

    return findings
