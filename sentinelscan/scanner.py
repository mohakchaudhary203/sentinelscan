"""Scan orchestrator — runs all registered checks against a target and aggregates results."""

from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .models import ScanResult
from .checks import headers, cookies, tls, exposed_files, ports

# Order matters slightly for readability of console output, not for correctness.
CHECK_MODULES = {
    "tls": tls,
    "security_headers": headers,
    "cookie_security": cookies,
    "exposed_files": exposed_files,
    "port_scan": ports,
}


class Scanner:
    def __init__(self, target: str, timeout: int = 10, user_agent: str = "SentinelScan/1.0"):
        if not urlparse(target).scheme:
            target = f"https://{target}"
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def run(self, only: list | None = None) -> ScanResult:
        """
        Run all checks (or a subset via `only`, e.g. ["tls", "security_headers"]).
        Individual check failures are captured as non-fatal errors so one broken
        check doesn't abort the whole scan.
        """
        result = ScanResult(target=self.target)

        checks_to_run = only or list(CHECK_MODULES.keys())

        for name in checks_to_run:
            module = CHECK_MODULES.get(name)
            if module is None:
                result.add_error(name, "Unknown check name")
                continue
            try:
                findings = module.run(self.session, self.target)
                for f in findings:
                    result.add(f)
            except requests.RequestException as exc:
                result.add_error(name, f"Request failed: {exc}")
            except Exception as exc:  # defensive: never let one check crash the scan
                result.add_error(name, f"Unexpected error: {exc}")

        result.finished_at = datetime.now(timezone.utc)
        return result
