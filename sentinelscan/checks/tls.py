"""TLS/SSL check — flags plaintext HTTP and inspects certificate validity (OWASP A02:2021)."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import Finding
from ..severity import Severity

OWASP_CAT = "A02:2021 - Cryptographic Failures"


def run(session, base_url: str) -> list:
    findings = []
    parsed = urlparse(base_url)

    if parsed.scheme != "https":
        findings.append(
            Finding(
                check="tls",
                title="Site served over plaintext HTTP",
                severity=Severity.CRITICAL,
                description="All traffic (including credentials, cookies, and form data) is transmitted unencrypted.",
                remediation="Serve the site exclusively over HTTPS and redirect all HTTP traffic to HTTPS.",
                owasp_category=OWASP_CAT,
            )
        )
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                Finding(
                    check="tls",
                    title=f"Outdated TLS protocol in use: {protocol}",
                    severity=Severity.HIGH,
                    description=f"Server negotiated {protocol}, which has known cryptographic weaknesses.",
                    remediation="Disable TLS < 1.2 on the server and require TLS 1.2 or 1.3 only.",
                    evidence=protocol,
                    owasp_category=OWASP_CAT,
                )
            )

        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    Finding(
                        check="tls",
                        title="TLS certificate has expired",
                        severity=Severity.CRITICAL,
                        description=f"Certificate expired {abs(days_left)} day(s) ago.",
                        remediation="Renew the TLS certificate immediately.",
                        evidence=not_after,
                        owasp_category=OWASP_CAT,
                    )
                )
            elif days_left < 14:
                findings.append(
                    Finding(
                        check="tls",
                        title="TLS certificate expiring soon",
                        severity=Severity.MEDIUM,
                        description=f"Certificate expires in {days_left} day(s).",
                        remediation="Renew the certificate before expiry; consider automated renewal (e.g. Let's Encrypt + certbot).",
                        evidence=not_after,
                        owasp_category=OWASP_CAT,
                    )
                )

    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        findings.append(
            Finding(
                check="tls",
                title="Could not fully verify TLS configuration",
                severity=Severity.INFO,
                description=f"TLS handshake/inspection failed: {exc}",
                remediation="Manually verify certificate chain and TLS configuration.",
                owasp_category=OWASP_CAT,
            )
        )

    return findings
