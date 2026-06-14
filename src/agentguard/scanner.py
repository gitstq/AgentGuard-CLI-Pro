"""
Core scanner engine for AgentGuard-CLI.

Performs static analysis on AI agent skill files and directories.
Uses only Python standard library - zero external dependencies.
"""

import os
import re
import json
import ast
import zipfile
import urllib.request
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .rules import compile_all_rules, Rule, SEVERITY_SCORES


@dataclass
class Finding:
    """A single security finding."""
    rule_id: str
    category: str
    name: str
    severity: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    recommendation: str
    score: int


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target: str
    scan_time: str
    total_files: int
    findings: List[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "SAFE"
    summary: Dict[str, Any] = field(default_factory=dict)

    def calculate_risk(self) -> None:
        """Calculate overall risk score and level."""
        score = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts: Dict[str, int] = {}

        for finding in self.findings:
            score += finding.score
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

        # Cap at 100
        self.risk_score = min(score, 100)

        if self.risk_score >= 81:
            self.risk_level = "CRITICAL"
        elif self.risk_score >= 51:
            self.risk_level = "HIGH"
        elif self.risk_score >= 21:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"

        self.summary = {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


class Scanner:
    """Main security scanner."""

    # File extensions to scan
    SCAN_EXTENSIONS = {
        '.py', '.js', '.ts', '.json', '.yaml', '.yml',
        '.md', '.txt', '.sh', '.bash', '.zsh',
        '.toml', '.cfg', '.ini', '.env', '.skill',
    }

    # Files to always scan regardless of extension
    ALWAYS_SCAN = {
        'skill.md', 'skill.json', 'mcp.json', 'claude.json',
        'requirements.txt', 'package.json', 'dockerfile',
        'makefile', '.env', '.env.example',
    }

    # Max file size (1MB)
    MAX_FILE_SIZE = 1024 * 1024

    def __init__(self):
        self.rules = compile_all_rules()

    def scan(self, target: str) -> ScanResult:
        """Scan a target (file, directory, URL, or zip)."""
        scan_time = datetime.now().isoformat()
        result = ScanResult(
            target=target,
            scan_time=scan_time,
            total_files=0,
        )

        # Determine target type and collect files
        files_to_scan: List[Tuple[str, str]] = []  # (path, content)

        if target.startswith(('http://', 'https://')):
            files_to_scan = self._fetch_url(target)
        elif target.endswith('.zip'):
            files_to_scan = self._extract_zip(target)
        elif os.path.isfile(target):
            content = self._read_file(target)
            if content is not None:
                files_to_scan = [(target, content)]
        elif os.path.isdir(target):
            files_to_scan = self._scan_directory(target)
        else:
            # Try as single file content
            files_to_scan = [(target, target)]

        result.total_files = len(files_to_scan)

        # Scan each file
        for file_path, content in files_to_scan:
            findings = self._scan_content(file_path, content)
            result.findings.extend(findings)

        # Calculate risk
        result.calculate_risk()
        return result

    def _read_file(self, path: str) -> Optional[str]:
        """Read file content with safety checks."""
        try:
            size = os.path.getsize(path)
            if size > self.MAX_FILE_SIZE:
                return None
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (OSError, UnicodeDecodeError):
            return None

    def _scan_directory(self, directory: str) -> List[Tuple[str, str]]:
        """Recursively scan directory for files."""
        files = []
        try:
            for root, _, filenames in os.walk(directory):
                # Skip common non-source directories
                if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']):
                    continue
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    if self._should_scan(filename):
                        content = self._read_file(filepath)
                        if content is not None:
                            files.append((filepath, content))
        except OSError:
            pass
        return files

    def _should_scan(self, filename: str) -> bool:
        """Check if file should be scanned."""
        lower_name = filename.lower()
        if lower_name in self.ALWAYS_SCAN:
            return True
        _, ext = os.path.splitext(lower_name)
        return ext in self.SCAN_EXTENSIONS

    def _fetch_url(self, url: str) -> List[Tuple[str, str]]:
        """Fetch content from URL."""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'AgentGuard-CLI/1.0 Security Scanner',
                    'Accept': 'text/plain, application/json, text/html',
                }
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                return [(url, content)]
        except Exception:
            return []

    def _extract_zip(self, zip_path: str) -> List[Tuple[str, str]]:
        """Extract and scan zip file contents."""
        files = []
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for info in zf.infolist():
                    if info.file_size > self.MAX_FILE_SIZE:
                        continue
                    if self._should_scan(info.filename):
                        try:
                            content = zf.read(info.filename).decode('utf-8', errors='ignore')
                            files.append((info.filename, content))
                        except (UnicodeDecodeError, zipfile.BadZipFile):
                            continue
        except (zipfile.BadZipFile, OSError):
            pass
        return files

    def _scan_content(self, file_path: str, content: str) -> List[Finding]:
        """Scan file content against all rules."""
        findings = []
        lines = content.split('\n')

        for rule in self.rules:
            for pattern in rule.regex_patterns:
                for match in pattern.finditer(content):
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    finding = Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        name=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_content[:200],
                        recommendation=rule.recommendation,
                        score=rule.score,
                    )
                    findings.append(finding)

        return findings

    def scan_with_ast(self, file_path: str, content: str) -> List[Finding]:
        """Additional AST-based analysis for Python files."""
        findings = []
        if not file_path.endswith('.py'):
            return findings

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Check for exec() calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'exec':
                    findings.append(Finding(
                        rule_id="AST1-AST",
                        category="Dangerous Code",
                        name="exec() Call (AST)",
                        severity="CRITICAL",
                        description="Direct exec() enabling arbitrary code execution",
                        file_path=file_path,
                        line_number=getattr(node, 'lineno', 0),
                        line_content="exec() call detected via AST analysis",
                        recommendation="AVOID exec() completely; use safer alternatives",
                        score=50,
                    ))
                elif isinstance(node.func, ast.Name) and node.func.id == 'eval':
                    findings.append(Finding(
                        rule_id="AST2-AST",
                        category="Dangerous Code",
                        name="eval() Call (AST)",
                        severity="HIGH",
                        description="Direct eval() evaluating arbitrary expressions",
                        file_path=file_path,
                        line_number=getattr(node, 'lineno', 0),
                        line_content="eval() call detected via AST analysis",
                        recommendation="Replace eval() with ast.literal_eval for literals",
                        score=25,
                    ))
                elif isinstance(node.func, ast.Attribute) and node.func.attr == 'system':
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                        findings.append(Finding(
                            rule_id="AST5-AST",
                            category="Dangerous Code",
                            name="os.system() Call (AST)",
                            severity="HIGH",
                            description="Shell commands via os.system()",
                            file_path=file_path,
                            line_number=getattr(node, 'lineno', 0),
                            line_content="os.system() call detected via AST analysis",
                            recommendation="Use subprocess with argument lists instead",
                            score=25,
                        ))

        return findings
