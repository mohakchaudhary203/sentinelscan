"""Severity levels and scoring for scan findings."""

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def weight(self) -> int:
        """Points contributed to the overall risk score."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 10,
            Severity.CRITICAL: 20,
        }[self]


def compute_risk_score(findings: list) -> int:
    """
    Aggregate a 0-100 risk score from a list of Finding objects.
    Higher = worse. Capped at 100 so one scan with many low findings
    doesn't outrank a scan with a single critical one.
    """
    if not findings:
        return 0
    raw = sum(f.severity.weight for f in findings)
    return min(100, raw)


def grade_for_score(score: int) -> str:
    if score == 0:
        return "A+ (No issues detected)"
    if score <= 10:
        return "A (Minor issues)"
    if score <= 25:
        return "B (Some hardening needed)"
    if score <= 50:
        return "C (Multiple weaknesses)"
    if score <= 75:
        return "D (Significant exposure)"
    return "F (Critical exposure — remediate immediately)"
