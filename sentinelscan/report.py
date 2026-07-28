"""Report generation — console (colored), JSON, and Markdown output formats."""

import json
from colorama import Fore, Style, init as colorama_init

from .models import ScanResult
from .severity import Severity, compute_risk_score, grade_for_score

colorama_init(autoreset=True)

SEVERITY_COLORS = {
    Severity.INFO: Fore.CYAN,
    Severity.LOW: Fore.BLUE,
    Severity.MEDIUM: Fore.YELLOW,
    Severity.HIGH: Fore.RED,
    Severity.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
}


def print_console_report(result: ScanResult) -> None:
    score = compute_risk_score(result.findings)
    grade = grade_for_score(score)

    print(f"\n{Style.BRIGHT}SentinelScan Report{Style.RESET_ALL}")
    print(f"Target: {result.target}")
    print(f"Scanned: {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Risk Score: {score}/100  —  Grade: {grade}\n")

    if not result.findings:
        print(f"{Fore.GREEN}No issues detected across all checks.{Style.RESET_ALL}\n")
    else:
        # Sort worst-first so the report leads with what matters most
        ordered = sorted(result.findings, key=lambda f: f.severity, reverse=True)
        for f in ordered:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"{color}[{f.severity.label}]{Style.RESET_ALL} {f.title}")
            print(f"   {f.description}")
            if f.evidence:
                print(f"   Evidence: {f.evidence}")
            print(f"   Fix: {f.remediation}")
            if f.owasp_category:
                print(f"   OWASP: {f.owasp_category}")
            print()

    if result.errors:
        print(f"{Fore.YELLOW}Non-fatal check errors:{Style.RESET_ALL}")
        for err in result.errors:
            print(f"  - [{err['check']}] {err['message']}")
        print()


def write_json_report(result: ScanResult, path: str) -> None:
    payload = result.to_dict()
    payload["risk_score"] = compute_risk_score(result.findings)
    payload["grade"] = grade_for_score(payload["risk_score"])
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_markdown_report(result: ScanResult, path: str) -> None:
    score = compute_risk_score(result.findings)
    grade = grade_for_score(score)
    lines = [
        f"# SentinelScan Report",
        "",
        f"**Target:** {result.target}  ",
        f"**Scanned:** {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Risk Score:** {score}/100 — **Grade:** {grade}",
        "",
    ]

    if not result.findings:
        lines.append("No issues detected across all checks.")
    else:
        ordered = sorted(result.findings, key=lambda f: f.severity, reverse=True)
        lines.append("| Severity | Finding | OWASP Category |")
        lines.append("|---|---|---|")
        for f in ordered:
            lines.append(f"| {f.severity.label} | {f.title} | {f.owasp_category or '-'} |")
        lines.append("")
        lines.append("## Details")
        lines.append("")
        for f in ordered:
            lines.append(f"### [{f.severity.label}] {f.title}")
            lines.append(f"{f.description}")
            if f.evidence:
                lines.append(f"\n**Evidence:** `{f.evidence}`")
            lines.append(f"\n**Remediation:** {f.remediation}")
            lines.append("")

    if result.errors:
        lines.append("## Check Errors (non-fatal)")
        for err in result.errors:
            lines.append(f"- **{err['check']}:** {err['message']}")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
