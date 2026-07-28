"""Lightweight TCP port scan for commonly-exposed sensitive services (OWASP A05:2021).

Uses raw sockets rather than shelling out to nmap, so this has zero external
binary dependencies and works anywhere Python runs.
"""

import socket
from urllib.parse import urlparse

from ..models import Finding
from ..severity import Severity

OWASP_CAT = "A05:2021 - Security Misconfiguration"

# port -> (service name, severity if found open on a public-facing host)
INTERESTING_PORTS = {
    21: ("FTP", Severity.HIGH),
    22: ("SSH", Severity.INFO),          # expected on many servers; informational only
    23: ("Telnet", Severity.CRITICAL),   # unencrypted remote admin — should never be exposed
    25: ("SMTP", Severity.LOW),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    6379: ("Redis", Severity.CRITICAL),  # frequently misconfigured with no auth
    9200: ("Elasticsearch", Severity.CRITICAL),
    27017: ("MongoDB", Severity.CRITICAL),
    445: ("SMB", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
}


def run(session, base_url: str) -> list:
    findings = []
    host = urlparse(base_url).hostname
    if not host:
        return findings

    for port, (service, severity) in INTERESTING_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    findings.append(
                        Finding(
                            check="port_scan",
                            title=f"Port {port} ({service}) is open",
                            severity=severity,
                            description=f"{service} appears reachable directly from the internet on port {port}.",
                            remediation=(
                                f"Restrict {service} to internal networks / a VPN, or place it behind a firewall "
                                "so it isn't reachable from the public internet."
                            ),
                            evidence=f"{host}:{port}",
                            owasp_category=OWASP_CAT,
                        )
                    )
        except (socket.gaierror, socket.timeout, OSError):
            continue

    return findings
