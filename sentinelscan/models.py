"""Shared data models for scan findings and results."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from .severity import Severity


@dataclass
class Finding:
    """A single vulnerability/misconfiguration detected during a scan."""

    check: str                 # Which check produced this (e.g. "security_headers")
    title: str                 # Short human-readable title
    severity: Severity
    description: str           # What was found
    remediation: str           # How to fix it
    evidence: str = ""         # Raw evidence (header value, path found, etc.)
    owasp_category: str = ""   # e.g. "A05:2021 - Security Misconfiguration"

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "owasp_category": self.owasp_category,
        }


@dataclass
class ScanResult:
    """Aggregate result of a full scan run against a target."""

    target: str
    findings: list = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    errors: list = field(default_factory=list)  # non-fatal check errors (e.g. timeouts)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, check: str, message: str) -> None:
        self.errors.append({"check": check, "message": message})

    def findings_by_severity(self, severity: Severity) -> list:
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
