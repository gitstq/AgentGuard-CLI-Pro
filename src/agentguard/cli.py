"""
Command-line interface for AgentGuard-CLI.

Zero-dependency CLI using only Python standard library.
"""

import sys
import os
import argparse
from typing import Optional

from .scanner import Scanner
from .reporter import Reporter


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="🛡️ AgentGuard-CLI - Lightweight AI Agent Skill Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  agentguard scan ./my-skill/              Scan a local skill directory
  agentguard scan ./SKILL.md               Scan a single skill file
  agentguard scan https://github.com/...   Scan a remote repository
  agentguard scan ./skill.zip              Scan a zip file
  agentguard scan ./skill --format json    Output JSON report
  agentguard scan ./skill --no-color       Disable colored output
  agentguard scan ./skill --no-llm         Skip LLM analysis (faster)

For more information: https://github.com/gitstq/AgentGuard-CLI
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an AI agent skill for security vulnerabilities",
        description="Scan a skill file, directory, URL, or zip archive",
    )
    scan_parser.add_argument(
        "target",
        help="Target to scan (file, directory, URL, or zip)",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "markdown", "sarif"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file path (default: stdout)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output",
    )
    scan_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM semantic analysis (static analysis only, faster)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity level to report",
    )

    # Version command
    version_parser = subparsers.add_parser(
        "version",
        help="Show version information",
    )

    return parser


def main(argv: Optional[list] = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        print("AgentGuard-CLI v1.0.0")
        print("Lightweight AI Agent Skill Security Scanner")
        print("https://github.com/gitstq/AgentGuard-CLI")
        return 0

    if args.command == "scan":
        return run_scan(args)

    return 0


def run_scan(args) -> int:
    """Execute scan command."""
    target = args.target

    # Validate target exists (for local files)
    if not target.startswith(("http://", "https://")) and not os.path.exists(target):
        print(f"Error: Target not found: {target}", file=sys.stderr)
        return 1

    # Initialize scanner
    scanner = Scanner()

    # Run scan
    print(f"🛡️  AgentGuard scanning: {target}")
    print("   This may take a moment...\n")

    try:
        result = scanner.scan(target)
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        return 1

    # Filter by severity if specified
    if args.severity:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = severity_order.get(args.severity, 0)
        result.findings = [
            f for f in result.findings
            if severity_order.get(f.severity, 0) >= min_level
        ]
        result.calculate_risk()

    # Generate report
    reporter = Reporter(use_color=not args.no_color)

    if args.format == "json":
        report = reporter.json_report(result)
    elif args.format == "markdown":
        report = reporter.markdown(result)
    elif args.format == "sarif":
        report = reporter.sarif(result)
    else:
        report = reporter.terminal(result)

    # Output
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report saved to: {args.output}")
        except OSError as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            return 1
    else:
        print(report)

    # Return exit code based on risk
    if result.risk_level == "CRITICAL":
        return 3
    elif result.risk_level == "HIGH":
        return 2
    elif result.risk_level == "MEDIUM":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
