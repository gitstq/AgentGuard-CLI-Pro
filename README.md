# 🛡️ AgentGuard-CLI

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)]()

> **Lightweight AI Agent Skill Security Scanner** | 轻量级AI Agent技能安全扫描器
>
> Zero dependencies, cross-platform CLI tool for detecting vulnerabilities in AI agent skills (MCP, Claude Code, Codex CLI, etc.)

---

## 🎉 Project Introduction

AgentGuard-CLI is a lightweight, zero-dependency security scanner designed specifically for AI agent skills. As AI agents become more prevalent, the skills they use pose potential security risks. AgentGuard helps you answer:

**"Is this skill safe to install?"**

Inspired by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector), AgentGuard-CLI focuses on being:
- **Lightweight**: Pure Python standard library, no external dependencies
- **Fast**: Static analysis without requiring API keys
- **Portable**: Works on any platform with Python 3.9+
- **Comprehensive**: 40+ vulnerability patterns across 10 categories

---

## ✨ Core Features

- 🔍 **Multi-format Input**: Scan directories, single files, URLs, or zip archives
- 🛡️ **40+ Vulnerability Patterns**: Across 10 security categories
- 📊 **Risk Scoring**: 0-100 score with clear severity levels
- 🖥️ **Beautiful Terminal Output**: Color-coded, easy to read
- 📄 **Multiple Report Formats**: Terminal, JSON, Markdown, SARIF
- 🐳 **Docker Support**: Run without installing Python
- 🌐 **Cross-Platform**: Windows, macOS, Linux

### Security Categories

| Category | Patterns | Description |
|----------|----------|-------------|
| Prompt Injection | 5 | Override, hidden, exfiltration commands |
| Data Exfiltration | 4 | External transmission, env harvesting |
| Privilege Escalation | 3 | Excessive permissions, credential access |
| Supply Chain | 6 | Unpinned deps, obfuscated code, typosquatting |
| Dangerous Code | 8 | exec(), eval(), subprocess, dynamic imports |
| MCP Security | 8 | Wildcard permissions, hidden metadata, self-modification |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/gitstq/AgentGuard-CLI.git
cd AgentGuard-CLI

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
make install
# Or: pip install -e .
```

### Docker (No Python Required)

```bash
# Build image
make docker-build
# Or: docker build -t agentguard-cli .

# Scan a directory
docker run --rm -v "$PWD:/scan" agentguard-cli scan ./my-skill/
```

### Basic Usage

```bash
# Scan a local skill directory
agentguard scan ./my-skill/

# Scan a single file
agentguard scan ./SKILL.md

# Scan a Git repository
agentguard scan https://github.com/user/my-skill

# Scan a zip file
agentguard scan ./my-skill.zip

# Output JSON report
agentguard scan ./my-skill/ --format json --output report.json

# SARIF output for CI/CD
agentguard scan ./my-skill/ --format sarif --output report.sarif

# Disable colors
agentguard scan ./my-skill/ --no-color

# Filter by severity
agentguard scan ./my-skill/ --severity HIGH
```

---

## 📖 Detailed Usage Guide

### Risk Scoring

| Score | Level | Recommendation |
|-------|-------|----------------|
| 0-20 | LOW | ✅ SAFE |
| 21-50 | MEDIUM | ⚡ CAUTION |
| 51-80 | HIGH | ⚠️ DO NOT INSTALL |
| 81-100 | CRITICAL | 🚫 DO NOT INSTALL |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Safe - No significant risks |
| 1 | Medium risks detected |
| 2 | High risks detected |
| 3 | Critical risks detected |

---

## 💡 Design Philosophy

AgentGuard-CLI was designed with these principles:

1. **Zero Dependencies**: Uses only Python standard library for maximum portability
2. **Fast Static Analysis**: No API keys or network calls required for basic scanning
3. **Clear Output**: Color-coded terminal output with actionable recommendations
4. **CI/CD Ready**: SARIF output for integration with GitHub Advanced Security, etc.

### Comparison with SkillSpector

| Feature | AgentGuard-CLI | SkillSpector |
|---------|---------------|--------------|
| Dependencies | Zero | Multiple (requests, etc.) |
| LLM Analysis | Optional (planned) | Built-in |
| AST Analysis | Basic | Advanced |
| YARA Signatures | No | Yes |
| CVE Lookup | No | Yes (OSV) |
| Size | ~50KB | ~5MB+ |
| Startup Time | Instant | ~2s |

AgentGuard-CLI is ideal for quick, lightweight scans and CI/CD pipelines where minimal dependencies are preferred.

---

## 📦 Packaging & Deployment

### Build Wheel

```bash
make build
```

### Run Tests

```bash
make test
```

### Lint & Format

```bash
make lint
make format
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- Inspired by [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
- Built for the AI agent security community

---

<p align="center">
  Made with ❤️ for safer AI agents
</p>
