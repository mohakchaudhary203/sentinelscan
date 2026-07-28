"""Exposed sensitive files/paths check (OWASP A01:2021 / A05:2021)."""

from urllib.parse import urljoin

from ..models import Finding
from ..severity import Severity

OWASP_CAT = "A01:2021 - Broken Access Control"

# path -> (severity, description)
SENSITIVE_PATHS = {
    ".env": (Severity.CRITICAL, "Environment file exposed — may contain secrets, DB credentials, or API keys."),
    ".git/config": (Severity.CRITICAL, "Exposed .git directory can leak full source history."),
    ".git/HEAD": (Severity.CRITICAL, "Exposed .git directory can leak full source history."),
    "wp-config.php.bak": (Severity.HIGH, "Backup config file may expose database credentials."),
    "config.php.bak": (Severity.HIGH, "Backup config file may expose credentials."),
    ".DS_Store": (Severity.LOW, "Can reveal directory structure/filenames not meant to be public."),
    "server-status": (Severity.MEDIUM, "Apache server-status page may leak internal request/traffic info."),
    "phpinfo.php": (Severity.HIGH, "Exposes detailed server configuration, aiding further attacks."),
    "admin/": (Severity.INFO, "Admin panel path is reachable — ensure it's authenticated and rate-limited."),
    "backup.zip": (Severity.HIGH, "Publicly accessible backup archive may contain source code or data."),
    ".well-known/security.txt": (Severity.INFO, "security.txt found — good practice, not a vulnerability (informational only)."),
}


def run(session, base_url: str) -> list:
    findings = []

    for path, (severity, desc) in SENSITIVE_PATHS.items():
        url = urljoin(base_url.rstrip("/") + "/", path)
        try:
            resp = session.get(url, timeout=6, allow_redirects=False)
        except Exception:
            continue

        # Treat 2xx (and 3xx pointing away from a generic 404 page) as "present"
        if 200 <= resp.status_code < 300 and len(resp.content) > 0:
            # security.txt existing is a positive signal, not a vuln — downgrade noise
            if path == ".well-known/security.txt":
                findings.append(
                    Finding(
                        check="exposed_files",
                        title="security.txt present",
                        severity=Severity.INFO,
                        description=desc,
                        remediation="No action needed — this is a good security practice.",
                        evidence=f"{resp.status_code} {url}",
                        owasp_category=OWASP_CAT,
                    )
                )
                continue

            findings.append(
                Finding(
                    check="exposed_files",
                    title=f"Sensitive path exposed: /{path}",
                    severity=severity,
                    description=desc,
                    remediation=f"Remove public access to `/{path}` or block it at the web server / reverse proxy level.",
                    evidence=f"{resp.status_code} {url}",
                    owasp_category=OWASP_CAT,
                )
            )

    return findings
