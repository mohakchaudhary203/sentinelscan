"""Command-line interface for SentinelScan."""

import argparse
import sys

from . import __version__
from .scanner import Scanner, CHECK_MODULES
from .report import print_console_report, write_json_report, write_markdown_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="Automated vulnerability scanner for common OWASP Top 10 web misconfigurations.",
    )
    parser.add_argument("target", help="Target URL or hostname to scan (e.g. https://example.com)")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=list(CHECK_MODULES.keys()),
        help="Run only specific checks (default: run all checks).",
    )
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report to PATH.")
    parser.add_argument("--markdown", metavar="PATH", help="Write a Markdown report to PATH.")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10).")
    parser.add_argument("--quiet", action="store_true", help="Suppress console report (useful with --json/--markdown).")
    parser.add_argument("--version", action="version", version=f"SentinelScan {__version__}")
    return parser


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(
        "\nSentinelScan — only scan systems you own or have explicit permission to test.\n"
        "Unauthorized scanning may be illegal in your jurisdiction.\n"
    )

    scanner = Scanner(args.target, timeout=args.timeout)

    try:
        result = scanner.run(only=args.checks)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130

    if not args.quiet:
        print_console_report(result)

    if args.json:
        write_json_report(result, args.json)
        print(f"JSON report written to {args.json}")

    if args.markdown:
        write_markdown_report(result, args.markdown)
        print(f"Markdown report written to {args.markdown}")

    # Non-zero exit code if any HIGH/CRITICAL findings — useful for CI pipelines
    from .severity import Severity
    has_serious = any(f.severity >= Severity.HIGH for f in result.findings)
    return 1 if has_serious else 0


if __name__ == "__main__":
    sys.exit(main())
