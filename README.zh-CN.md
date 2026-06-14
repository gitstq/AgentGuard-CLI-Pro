# 🛡️ AgentGuard-CLI

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)]()

> **轻量级AI Agent技能安全扫描器** | Lightweight AI Agent Skill Security Scanner
>
> 零依赖、跨平台CLI工具，用于检测AI Agent技能（MCP、Claude Code等）中的安全漏洞

---

## 🎉 项目介绍

AgentGuard-CLI 是一款专为AI Agent技能设计的轻量级、零依赖安全扫描器。随着AI Agent的普及，它们使用的技能可能存在潜在的安全风险。AgentGuard 帮助您回答：

**"这个技能可以安全安装吗？"**

灵感来源于 [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)，AgentGuard-CLI 专注于：
- **轻量级**：纯Python标准库，无外部依赖
- **快速**：静态分析，无需API密钥
- **可移植**：任何支持Python 3.9+的平台均可运行
- **全面**：覆盖10个安全类别的40+漏洞模式

---

## ✨ 核心特性

- 🔍 **多格式输入**：扫描目录、单文件、URL或zip压缩包
- 🛡️ **40+漏洞模式**：覆盖10个安全类别
- 📊 **风险评分**：0-100分，风险等级清晰
- 🖥️ **精美终端输出**：彩色编码，易于阅读
- 📄 **多种报告格式**：终端、JSON、Markdown、SARIF
- 🐳 **Docker支持**：无需安装Python即可运行
- 🌐 **跨平台**：Windows、macOS、Linux

### 安全类别

| 类别 | 模式数 | 描述 |
|------|--------|------|
| 提示注入 | 5 | 覆盖、隐藏、数据外泄命令 |
| 数据外泄 | 4 | 外部传输、环境变量收集 |
| 权限提升 | 3 | 过度权限、凭证访问 |
| 供应链 | 6 | 未固定依赖、混淆代码、域名抢注 |
| 危险代码 | 8 | exec()、eval()、subprocess、动态导入 |
| MCP安全 | 8 | 通配符权限、隐藏元数据、自我修改 |

---

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/gitstq/AgentGuard-CLI-Pro.git
cd AgentGuard-CLI-Pro

# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 安装
make install
# 或: pip install -e .
```

### Docker（无需Python）

```bash
# 构建镜像
make docker-build
# 或: docker build -t agentguard-cli .

# 扫描目录
docker run --rm -v "$PWD:/scan" agentguard-cli scan ./my-skill/
```

### 基本用法

```bash
# 扫描本地技能目录
agentguard scan ./my-skill/

# 扫描单个文件
agentguard scan ./SKILL.md

# 扫描Git仓库
agentguard scan https://github.com/user/my-skill

# 扫描zip文件
agentguard scan ./my-skill.zip

# 输出JSON报告
agentguard scan ./my-skill/ --format json --output report.json

# SARIF输出用于CI/CD
agentguard scan ./my-skill/ --format sarif --output report.sarif

# 禁用颜色
agentguard scan ./my-skill/ --no-color

# 按严重级别过滤
agentguard scan ./my-skill/ --severity HIGH
```

---

## 📖 详细使用指南

### 风险评分

| 分数 | 等级 | 建议 |
|------|------|------|
| 0-20 | 低 | ✅ 安全 |
| 21-50 | 中 | ⚡ 谨慎 |
| 51-80 | 高 | ⚠️ 不要安装 |
| 81-100 | 严重 | 🚫 不要安装 |

### 退出代码

| 代码 | 含义 |
|------|------|
| 0 | 安全 - 无重大风险 |
| 1 | 检测到中等风险 |
| 2 | 检测到高风险 |
| 3 | 检测到严重风险 |

---

## 💡 设计思路

AgentGuard-CLI 遵循以下设计原则：

1. **零依赖**：仅使用Python标准库，最大化可移植性
2. **快速静态分析**：基本扫描无需API密钥或网络调用
3. **清晰输出**：彩色终端输出，提供可操作建议
4. **CI/CD就绪**：SARIF输出可与GitHub Advanced Security等集成

### 与SkillSpector对比

| 特性 | AgentGuard-CLI | SkillSpector |
|------|---------------|--------------|
| 依赖 | 零 | 多个（requests等） |
| LLM分析 | 可选（计划中） | 内置 |
| AST分析 | 基础 | 高级 |
| YARA签名 | 否 | 是 |
| CVE查询 | 否 | 是（OSV） |
| 大小 | ~50KB | ~5MB+ |
| 启动时间 | 即时 | ~2秒 |

AgentGuard-CLI 适合需要快速、轻量级扫描和CI/CD流水线的场景。

---

## 📦 打包与部署

### 构建Wheel

```bash
make build
```

### 运行测试

```bash
make test
```

### 代码检查与格式化

```bash
make lint
make format
```

---

## 🤝 贡献指南

欢迎贡献！请：

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/ amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

请遵循 [Conventional Commits](https://www.conventionalcommits.org/) 提交规范。

---

## 📄 开源协议

本项目采用 MIT 协议 - 详见 [LICENSE](LICENSE) 文件。

---

## 🙏 致谢

- 灵感来源于 [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
- 为AI Agent安全社区而建

---

<p align="center">
  Made with ❤️ for safer AI agents
</p>
