"""
Security rule definitions for AgentGuard-CLI.

Contains vulnerability patterns across multiple categories.
All patterns use pure Python standard library only.
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import re


@dataclass
class Rule:
    """Security detection rule."""
    id: str
    category: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    patterns: List[str]
    regex_patterns: List[re.Pattern]
    recommendation: str
    score: int


# Severity score mapping
SEVERITY_SCORES = {
    "CRITICAL": 50,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5,
}


def compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    """Compile regex patterns with case-insensitive flag."""
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE | re.MULTILINE))
        except re.error:
            continue
    return compiled


# =============================================================================
# RULE DEFINITIONS
# =============================================================================

RULES: List[Rule] = [
    # === Prompt Injection (5 rules) ===
    Rule(
        id="P1",
        category="Prompt Injection",
        name="Instruction Override",
        severity="HIGH",
        description="Commands to ignore safety constraints or system instructions",
        patterns=[
            r"ignore\s+(previous|prior|above)\s+(instructions?|commands?|prompts?)",
            r"disregard\s+(all\s+)?(safety|security|system)\s+(instructions?|rules?|constraints?)",
            r"override\s+(system|safety)\s+(prompt|instruction|setting)",
            r"bypass\s+(safety|security)\s+(check|filter|guardrail)",
            r"forget\s+(your|all)\s+(instructions?|training|constraints?)",
        ],
        regex_patterns=[],
        recommendation="Review skill for attempts to override AI safety instructions",
        score=25,
    ),
    Rule(
        id="P2",
        category="Prompt Injection",
        name="Hidden Instructions",
        severity="HIGH",
        description="Malicious directives hidden in comments or invisible text",
        patterns=[
            r"<!--\s*.*?(ignore|override|bypass|disregard).*?-->",
            r"/\*\s*.*?(ignore|override|bypass|disregard).*?\*/",
            r"#\s*.*?(ignore|override|bypass|disregard).*",
            r"[\u200B-\u200F\uFEFF].*?(command|instruction|override)",
        ],
        regex_patterns=[],
        recommendation="Check for hidden Unicode characters or comment-based injection",
        score=25,
    ),
    Rule(
        id="P3",
        category="Prompt Injection",
        name="Exfiltration Commands",
        severity="HIGH",
        description="Instructions to transmit data to external endpoints",
        patterns=[
            r"send\s+.*\s+to\s+https?://",
            r"send\s+.*data\s+to\s+.*\.",
            r"exfiltrate\s+(data|information|context)",
            r"transmit\s+(conversation|chat|message|context)\s+to",
            r"forward\s+(all\s+)?(data|messages?|conversation)\s+to",
            r"send\s+(all\s+)?(conversation|context|data)\s+(to|out|externally)",
        ],
        regex_patterns=[],
        recommendation="Verify skill does not attempt to leak conversation data externally",
        score=25,
    ),
    Rule(
        id="P4",
        category="Prompt Injection",
        name="Behavior Manipulation",
        severity="MEDIUM",
        description="Subtle instructions altering agent decisions",
        patterns=[
            r"always\s+(respond|reply|answer)\s+(with|using|by)",
            r"never\s+(refuse|decline|deny|reject)",
            r"pretend\s+(to\s+be|you\s+are|you're)",
            r"act\s+as\s+(if\s+)?(you\s+)?(have|possess|own)",
        ],
        regex_patterns=[],
        recommendation="Review for attempts to manipulate AI behavior patterns",
        score=10,
    ),
    Rule(
        id="P5",
        category="Prompt Injection",
        name="Harmful Content",
        severity="CRITICAL",
        description="Instructions that could cause physical or digital harm",
        patterns=[
            r"(create|generate|write|produce)\s+(malware|virus|trojan|ransomware|worm)",
            r"(steal|exfiltrate|harvest)\s+(password|credential|token|secret|key)",
            r"(attack|exploit|compromise)\s+(system|server|network|database)",
            r"(delete|destroy|wipe|corrupt)\s+(data|file|system|database)",
        ],
        regex_patterns=[],
        recommendation="IMMEDIATE REVIEW: Potential malicious intent detected",
        score=50,
    ),

    # === Data Exfiltration (4 rules) ===
    Rule(
        id="E1",
        category="Data Exfiltration",
        name="External Transmission",
        severity="MEDIUM",
        description="Sending data to external URLs without consent",
        patterns=[
            r"requests\.(get|post|put|patch)\s*\([^)]*https?://",
            r"urllib\.(request\.urlopen|urlretrieve)",
            r"http\.client\.HTTPConnection",
            r"\.sendall\s*\([^)]*http",
        ],
        regex_patterns=[],
        recommendation="Verify all external network requests are documented and necessary",
        score=10,
    ),
    Rule(
        id="E2",
        category="Data Exfiltration",
        name="Env Variable Harvesting",
        severity="HIGH",
        description="Collecting API keys, secrets, and environment variables",
        patterns=[
            r"os\.environ\[.*?(KEY|SECRET|TOKEN|PWD|PASS|AUTH)",
            r"os\.environ\.get\s*\([^)]*(key|secret|token|pwd|pass|auth)",
            r"os\.environ\.items\s*\(\)",
            r"dict\(os\.environ\)",
        ],
        regex_patterns=[],
        recommendation="Ensure environment variable access is scoped and documented",
        score=25,
    ),
    Rule(
        id="E3",
        category="Data Exfiltration",
        name="File System Enumeration",
        severity="MEDIUM",
        description="Scanning directories for sensitive files",
        patterns=[
            r"os\.walk\s*\([^)]*\.(ssh|aws|config|secret|key)",
            r"glob\.(glob|iglob)\s*\([^)]*\.(key|pem|secret|env|config)",
            r"pathlib\.Path\s*\([^)]*\.(ssh|aws|config|secret)",
        ],
        regex_patterns=[],
        recommendation="Verify file system access is limited to necessary paths",
        score=10,
    ),
    Rule(
        id="E4",
        category="Data Exfiltration",
        name="Context Leakage",
        severity="HIGH",
        description="Transmitting conversation context externally",
        patterns=[
            r"(conversation|context|chat|messages?)\s*.*?(send|transmit|upload|post)",
            r"(user|assistant)\s*(message|input|query)\s*.*?(external|outside|third.party)",
        ],
        regex_patterns=[],
        recommendation="Ensure conversation context is not leaked to external services",
        score=25,
    ),

    # === Privilege Escalation (3 rules) ===
    Rule(
        id="PE1",
        category="Privilege Escalation",
        name="Excessive Permissions",
        severity="LOW",
        description="Requesting access beyond stated functionality",
        patterns=[
            r"(full|complete|total|unrestricted)\s+(access|permission|control)",
            r"(all|every)\s+(file|directory|folder|system)\s+access",
        ],
        regex_patterns=[],
        recommendation="Minimize requested permissions to only what's necessary",
        score=5,
    ),
    Rule(
        id="PE2",
        category="Privilege Escalation",
        name="Sudo/Root Execution",
        severity="MEDIUM",
        description="Invoking elevated system privileges",
        patterns=[
            r"sudo\s+",
            r"os\.setuid\s*\(",
            r"os\.setgid\s*\(",
            r"subprocess\..*?shell\s*=\s*True.*?sudo",
        ],
        regex_patterns=[],
        recommendation="Avoid requiring elevated privileges; use least privilege principle",
        score=10,
    ),
    Rule(
        id="PE3",
        category="Privilege Escalation",
        name="Credential Access",
        severity="HIGH",
        description="Reading SSH keys, tokens, passwords",
        patterns=[
            r"open\s*\([^)]*id_rsa|id_dsa|id_ecdsa|id_ed25519",
            r"open\s*\([^)]*\.ssh",
            r"Path\s*\([^)]*\.aws[\\/]credentials",
            r"open\s*\([^)]*\.netrc",
        ],
        regex_patterns=[],
        recommendation="Never access credential files directly; use secure credential stores",
        score=25,
    ),

    # === Supply Chain (6 rules) ===
    Rule(
        id="SC1",
        category="Supply Chain",
        name="Unpinned Dependencies",
        severity="LOW",
        description="No version constraints on packages",
        patterns=[
            r"pip\s+install\s+\w+\s*(?!.*==)",
            r"requirements\.txt.*\w+\s*(?!.*==|.*>=|.*<=|.*~=)",
        ],
        regex_patterns=[],
        recommendation="Pin all dependencies to specific versions",
        score=5,
    ),
    Rule(
        id="SC2",
        category="Supply Chain",
        name="External Script Fetching",
        severity="HIGH",
        description="curl | bash and remote code execution patterns",
        patterns=[
            r"curl\s+.*\|\s*(bash|sh|zsh|python)",
            r"wget\s+.*\|\s*(bash|sh|zsh|python)",
            r"fetch\s*\([^)]*\)\s*.*?(eval|exec)",
            r"urllib\.request\.urlretrieve\s*\([^)]*\)\s*.*?(exec|eval)",
        ],
        regex_patterns=[],
        recommendation="Never execute remotely fetched scripts without verification",
        score=25,
    ),
    Rule(
        id="SC3",
        category="Supply Chain",
        name="Obfuscated Code",
        severity="HIGH",
        description="Base64/hex encoded execution",
        patterns=[
            r"base64\.(b64decode|decode)\s*\([^)]*\)\s*.*?(exec|eval)",
            r"bytes\.fromhex\s*\([^)]*\)\s*.*?(exec|eval)",
            r"decode\s*\([^)]*base64[^)]*\)\s*.*?(exec|eval)",
            r"eval\s*\(\s*compile\s*\(",
        ],
        regex_patterns=[],
        recommendation="Decode and review any encoded code before execution",
        score=25,
    ),
    Rule(
        id="SC4",
        category="Supply Chain",
        name="Known Vulnerable Dependencies",
        severity="HIGH",
        description="Dependencies with known CVEs",
        patterns=[
            r"(requests|urllib3|certifi|idna|charset.normalizer)==\s*0\.",
            r"(flask|django|fastapi)==\s*0\.",
        ],
        regex_patterns=[],
        recommendation="Check dependencies against vulnerability databases (OSV, NVD)",
        score=25,
    ),
    Rule(
        id="SC5",
        category="Supply Chain",
        name="Abandoned Dependencies",
        severity="MEDIUM",
        description="Unmaintained packages without security updates",
        patterns=[],
        regex_patterns=[],
        recommendation="Verify all dependencies are actively maintained",
        score=10,
    ),
    Rule(
        id="SC6",
        category="Supply Chain",
        name="Typosquatting",
        severity="HIGH",
        description="Package names similar to popular packages",
        patterns=[
            r"(reqeusts|urlib3|certifii|djnago|flaskk|numpyy|pandasss)",
        ],
        regex_patterns=[],
        recommendation="Verify package names carefully before installation",
        score=25,
    ),

    # === Dangerous Code Execution (8 rules) ===
    Rule(
        id="AST1",
        category="Dangerous Code",
        name="exec() Call",
        severity="CRITICAL",
        description="Direct exec() enabling arbitrary code execution",
        patterns=[
            r"\bexec\s*\(",
            r"\bexec\s+\'",
            r"\bexec\s+\"",
        ],
        regex_patterns=[],
        recommendation="AVOID exec() completely; use safer alternatives like ast.literal_eval",
        score=50,
    ),
    Rule(
        id="AST2",
        category="Dangerous Code",
        name="eval() Call",
        severity="HIGH",
        description="Direct eval() evaluating arbitrary expressions",
        patterns=[
            r"\beval\s*\(",
            r"\beval\s+\'",
            r"\beval\s+\"",
        ],
        regex_patterns=[],
        recommendation="Replace eval() with ast.literal_eval for literals, or proper parsers",
        score=25,
    ),
    Rule(
        id="AST3",
        category="Dangerous Code",
        name="Dynamic Import",
        severity="HIGH",
        description="__import__() loading arbitrary modules at runtime",
        patterns=[
            r"__import__\s*\(",
            r"importlib\.import_module\s*\([^)]*\+",
            r"importlib\.import_module\s*\([^)]*f\"",
            r"importlib\.import_module\s*\([^)]*f\'",
        ],
        regex_patterns=[],
        recommendation="Use static imports; validate dynamic imports against allowlist",
        score=25,
    ),
    Rule(
        id="AST4",
        category="Dangerous Code",
        name="subprocess Call",
        severity="HIGH",
        description="External command execution via subprocess",
        patterns=[
            r"subprocess\.(call|run|Popen|check_output|check_call)\s*\(",
            r"subprocess\..*shell\s*=\s*True",
        ],
        regex_patterns=[],
        recommendation="Avoid shell=True; use argument lists and validate inputs",
        score=25,
    ),
    Rule(
        id="AST5",
        category="Dangerous Code",
        name="os.system / exec-family",
        severity="HIGH",
        description="Shell commands via os module",
        patterns=[
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"os\.execl\s*\(",
            r"os\.execv\s*\(",
            r"os\.spawnl\s*\(",
            r"subprocess\..*shell\s*=\s*True",
        ],
        regex_patterns=[],
        recommendation="Use subprocess with argument lists instead of os.system",
        score=25,
    ),
    Rule(
        id="AST6",
        category="Dangerous Code",
        name="compile() Call",
        severity="MEDIUM",
        description="Code object creation from strings",
        patterns=[
            r"compile\s*\([^)]*\'",
            r"compile\s*\([^)]*\"",
            r"compile\s*\([^)]*\+",
        ],
        regex_patterns=[],
        recommendation="Avoid compile() with dynamic strings; use static code only",
        score=10,
    ),
    Rule(
        id="AST7",
        category="Dangerous Code",
        name="Dynamic getattr()",
        severity="MEDIUM",
        description="Arbitrary attribute access with non-literal names",
        patterns=[
            r"getattr\s*\([^)]*,\s*[^\'\"]",
            r"getattr\s*\([^)]*\+",
            r"getattr\s*\([^)]*f\"",
            r"getattr\s*\([^)]*f\'",
        ],
        regex_patterns=[],
        recommendation="Validate attribute names against allowlist before getattr",
        score=10,
    ),
    Rule(
        id="AST8",
        category="Dangerous Code",
        name="Dangerous Execution Chain",
        severity="CRITICAL",
        description="exec/eval combined with dynamic source (network, encoded data)",
        patterns=[
            r"(exec|eval)\s*\([^)]*(base64|decode|urllib|requests|socket)",
            r"(exec|eval)\s*\([^)]*(download|fetch|get|read)\s*\(",
        ],
        regex_patterns=[],
        recommendation="CRITICAL: Never execute dynamically fetched or decoded code",
        score=50,
    ),

    # === MCP Specific (8 rules) ===
    Rule(
        id="MCP1",
        category="MCP Security",
        name="Wildcard Permission",
        severity="MEDIUM",
        description="Permission list contains wildcards",
        patterns=[
            r"\"permissions\"\s*:\s*\[\s*[^\]]*(\*|all|full|any)",
            r"\"scopes\"\s*:\s*\[\s*[^\]]*(\*|all|full|any)",
        ],
        regex_patterns=[],
        recommendation="Use explicit, minimal permissions instead of wildcards",
        score=10,
    ),
    Rule(
        id="MCP2",
        category="MCP Security",
        name="Missing Permission Declaration",
        severity="MEDIUM",
        description="No permissions field but code has detectable capabilities",
        patterns=[
            r"(?<!permissions.*)(?<!scopes.*)(os\.path|subprocess|urllib|requests|socket)",
        ],
        regex_patterns=[],
        recommendation="Declare all required permissions explicitly in skill manifest",
        score=10,
    ),
    Rule(
        id="MCP3",
        category="MCP Security",
        name="Hidden Instructions in Metadata",
        severity="HIGH",
        description="Hidden directives in tool metadata",
        patterns=[
            r"\"description\"\s*:\s*\"[^\"]*?(ignore|override|bypass|disregard)[^\"]*\"",
            r"\"name\"\s*:\s*\"[^\"]*?(admin|root|sudo|system)[^\"]*\"",
        ],
        regex_patterns=[],
        recommendation="Review all tool metadata for hidden malicious instructions",
        score=25,
    ),
    Rule(
        id="MCP4",
        category="MCP Security",
        name="Unicode Deception",
        severity="HIGH",
        description="Homoglyphs, RTL overrides in tool metadata",
        patterns=[
            r"[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F].*?[a-zA-Z]",
            r"[\u0430-\u044F].*?[a-zA-Z]",
        ],
        regex_patterns=[],
        recommendation="Check for Unicode homoglyph attacks in identifiers",
        score=25,
    ),
    Rule(
        id="MCP5",
        category="MCP Security",
        name="Parameter Description Injection",
        severity="MEDIUM",
        description="Injection patterns in parameter definitions",
        patterns=[
            r"\"parameters\".*?(override|ignore|bypass|system|admin)",
            r"\"properties\".*?(command|exec|eval|shell|system)",
        ],
        regex_patterns=[],
        recommendation="Validate parameter descriptions for injection attempts",
        score=10,
    ),
    Rule(
        id="MCP6",
        category="MCP Security",
        name="Tool Parameter Abuse",
        severity="HIGH",
        description="Crafted parameters for unintended behavior",
        patterns=[
            r"shell\s*=\s*True",
            r"--force",
            r"force\s*=\s*True",
            r"unsafe\s*=\s*True",
        ],
        regex_patterns=[],
        recommendation="Avoid unsafe parameter defaults; validate all inputs",
        score=25,
    ),
    Rule(
        id="MCP7",
        category="MCP Security",
        name="Self-Modification",
        severity="CRITICAL",
        description="Modifying own code or configuration at runtime",
        patterns=[
            r"open\s*\(__file__",
            r"open\s*\([^)]*__name__",
            r"Path\s*\([^)]*__file__",
            r"os\.chmod\s*\([^)]*__file__",
        ],
        regex_patterns=[],
        recommendation="NEVER allow self-modifying code in agent skills",
        score=50,
    ),
    Rule(
        id="MCP8",
        category="MCP Security",
        name="Session Persistence",
        severity="HIGH",
        description="Unauthorized persistence via cron jobs or startup scripts",
        patterns=[
            r"cron\.(tab|job)",
            r"crontab",
            r"startup\s*script",
            r"registry\s*key",
            r"plist\s*file",
        ],
        regex_patterns=[],
        recommendation="Avoid persistent mechanisms; skills should be stateless",
        score=25,
    ),
]


def compile_all_rules() -> List[Rule]:
    """Compile regex patterns for all rules."""
    compiled_rules = []
    for rule in RULES:
        compiled = compile_patterns(rule.patterns)
        if compiled:
            compiled_rules.append(Rule(
                id=rule.id,
                category=rule.category,
                name=rule.name,
                severity=rule.severity,
                description=rule.description,
                patterns=rule.patterns,
                regex_patterns=compiled,
                recommendation=rule.recommendation,
                score=rule.score,
            ))
    return compiled_rules
