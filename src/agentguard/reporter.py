"""
Report generators for AgentGuard-CLI.

Supports multiple output formats: terminal, JSON, Markdown, SARIF.
All using pure Python standard library.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

from .scanner import ScanResult, Finding


class Reporter:
    """Generate scan reports in various formats."""

    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "bg_red": "\033[41m",
        "bg_yellow": "\033[43m",
        "bg_green": "\033[42m",
    }

    # Severity colors
    SEVERITY_COLORS = {
        "CRITICAL": "bg_red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    # Risk level colors
    RISK_COLORS = {
        "CRITICAL": "bg_red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "SAFE": "green",
    }

    def __init__(self, use_color: bool = True):
        self.use_color = use_color

    def _color(self, color_name: str, text: str) -> str:
        """Apply color to text if enabled."""
        if not self.use_color:
            return text
        color_code = self.COLORS.get(color_name, "")
        reset = self.COLORS["reset"]
        return f"{color_code}{text}{reset}"

    def terminal(self, result: ScanResult) -> str:
        """Generate terminal-formatted report."""
        lines = []
        c = self._color

        # Header
        lines.append("")
        lines.append(c("bold", "=" * 70))
        lines.append(c("cyan", "  🛡️  AgentGuard Security Report v1.0.0"))
        lines.append(c("bold", "=" * 70))
        lines.append("")

        # Target info
        lines.append(f"  {c('bold', 'Target:')} {result.target}")
        lines.append(f"  {c('bold', 'Scan Time:')} {result.scan_time}")
        lines.append(f"  {c('bold', 'Files Scanned:')} {result.total_files}")
        lines.append("")

        # Risk score box
        risk_color = self.RISK_COLORS.get(result.risk_level, "white")
        lines.append(c("bold", "  " + "-" * 40))
        lines.append(f"  {c('bold', 'Risk Score:')} {c(risk_color, f' {result.risk_score}/100 ')} {c(risk_color, f' [{result.risk_level}] ')}")
        lines.append(c("bold", "  " + "-" * 40))
        lines.append("")

        # Summary
        if result.summary:
            lines.append(c("bold", "  📊 Summary:"))
            lines.append(f"    Total Findings: {result.summary.get('total_findings', 0)}")
            sev = result.summary.get('severity_breakdown', {})
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = sev.get(level, 0)
                if count > 0:
                    color = self.SEVERITY_COLORS.get(level, "white")
                    lines.append(f"    {c(color, f'{level}:')} {count}")
            lines.append("")

        # Findings detail
        if result.findings:
            lines.append(c("bold", "  🔍 Detailed Findings:"))
            lines.append("")

            # Group by category
            by_category: Dict[str, List[Finding]] = {}
            for finding in result.findings:
                by_category.setdefault(finding.category, []).append(finding)

            for category, findings in by_category.items():
                lines.append(c("bold", f"  [{category}] ({len(findings)} findings)"))
                lines.append("")
                for finding in findings:
                    sev_color = self.SEVERITY_COLORS.get(finding.severity, "white")
                    lines.append(f"    {c(sev_color, f'[{finding.severity}]')} {c('bold', finding.rule_id)} - {finding.name}")
                    lines.append(f"    📁 {finding.file_path}:{finding.line_number}")
                    if finding.line_content:
                        lines.append(f"    📝 {finding.line_content[:100]}")
                    lines.append(f"    💡 {finding.recommendation}")
                    lines.append("")
        else:
            lines.append(c("green", "  ✅ No security issues detected!"))
            lines.append("")

        # Recommendation
        lines.append(c("bold", "  📋 Recommendation:"))
        if result.risk_level == "CRITICAL":
            lines.append(c("red", "    🚫 DO NOT INSTALL - Critical security risks detected"))
        elif result.risk_level == "HIGH":
            lines.append(c("red", "    ⚠️  DO NOT INSTALL - High security risks detected"))
        elif result.risk_level == "MEDIUM":
            lines.append(c("yellow", "    ⚡ CAUTION - Review findings before installing"))
        else:
            lines.append(c("green", "    ✅ SAFE - No significant risks detected"))

        lines.append("")
        lines.append(c("bold", "=" * 70))
        lines.append("")

        return "\n".join(lines)

    def json_report(self, result: ScanResult) -> str:
        """Generate JSON report."""
        data = {
            "tool": "AgentGuard-CLI",
            "version": "1.0.0",
            "scan": {
                "target": result.target,
                "scan_time": result.scan_time,
                "total_files": result.total_files,
            },
            "risk": {
                "score": result.risk_score,
                "level": result.risk_level,
            },
            "summary": result.summary,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "name": f.name,
                    "severity": f.severity,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "line_content": f.line_content,
                    "recommendation": f.recommendation,
                    "score": f.score,
                }
                for f in result.findings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def markdown(self, result: ScanResult) -> str:
        """Generate Markdown report."""
        lines = []
        lines.append("# 🛡️ AgentGuard Security Report")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **Tool** | AgentGuard-CLI v1.0.0 |")
        lines.append(f"| **Target** | `{result.target}` |")
        lines.append(f"| **Scan Time** | {result.scan_time} |")
        lines.append(f"| **Files Scanned** | {result.total_files} |")
        lines.append(f"| **Risk Score** | **{result.risk_score}/100** |")
        lines.append(f"| **Risk Level** | **{result.risk_level}** |")
        lines.append("")

        # Risk badge
        if result.risk_level == "CRITICAL":
            lines.append("> 🚫 **CRITICAL: DO NOT INSTALL**")
        elif result.risk_level == "HIGH":
            lines.append("> ⚠️ **HIGH: DO NOT INSTALL**")
        elif result.risk_level == "MEDIUM":
            lines.append("> ⚡ **MEDIUM: CAUTION**")
        else:
            lines.append("> ✅ **LOW: SAFE**")
        lines.append("")

        # Summary
        lines.append("## 📊 Summary")
        lines.append("")
        if result.summary:
            lines.append(f"- **Total Findings:** {result.summary.get('total_findings', 0)}")
            sev = result.summary.get('severity_breakdown', {})
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = sev.get(level, 0)
                if count > 0:
                    lines.append(f"- **{level}:** {count}")
        lines.append("")

        # Findings
        lines.append("## 🔍 Detailed Findings")
        lines.append("")

        if result.findings:
            by_category: Dict[str, List[Finding]] = {}
            for finding in result.findings:
                by_category.setdefault(finding.category, []).append(finding)

            for category, findings in by_category.items():
                lines.append(f"### {category}")
                lines.append("")
                for f in findings:
                    lines.append(f"#### {f.rule_id} - {f.name}")
                    lines.append("")
                    lines.append(f"- **Severity:** `{f.severity}`")
                    lines.append(f"- **Score:** {f.score}")
                    lines.append(f"- **Location:** `{f.file_path}:{f.line_number}`")
                    lines.append(f"- **Description:** {f.description}")
                    if f.line_content:
                        lines.append(f"- **Code:** `{f.line_content[:100]}`")
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                    lines.append("")
        else:
            lines.append("✅ No security issues detected!")
            lines.append("")

        return "\n".join(lines)

    def sarif(self, result: ScanResult) -> str:
        """Generate SARIF report for CI/CD integration."""
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgentGuard-CLI",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/gitstq/AgentGuard-CLI",
                            "rules": [
                                {
                                    "id": f.rule_id,
                                    "name": f.name,
                                    "shortDescription": {"text": f.description},
                                    "fullDescription": {"text": f.description},
                                    "defaultConfiguration": {
                                        "level": f.severity.lower(),
                                    },
                                }
                                for f in result.findings
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": f.severity.lower(),
                            "message": {"text": f.description},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file_path},
                                        "region": {
                                            "startLine": f.line_number,
                                            "snippet": {"text": f.line_content},
                                        },
                                    }
                                }
                            ],
                        }
                        for f in result.findings
                    ],
                }
            ],
        }
        return json.dumps(sarif_data, indent=2, ensure_ascii=False)
