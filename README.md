# B-XSSRF v7 🛡️

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Types: MyPy](https://img.shields.io/badge/types-mypy-0078d4.svg)](https://github.com/microsoft/mypy)

```
⠀⠀⠀⠀⠀⣠⣴⣶⣿⣿⠿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣷⠿⣿⣿⣶⣦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣶⣦⣬⡉⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⢉⣥⣴⣾⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⡾⠿⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⠿⠿⠛⠛⠛⠛⠿⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣤⠶⠶⠶⠰⠦⣤⣀⠀⠙⣷⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠋⢀⣀⣤⢴⠆⠲⠶⠶⣤⣄⠀⠀⠀⠀⠀⠀
⠀⠘⣆⠀⠀⢠⣾⣫⣶⣾⣿⣿⣿⣿⣷⣯⣿⣦⠈⠃⡇⠀⠀⠀⠀⠀⢸⠘⢁⣶⣿⣵⣾⣿⣿⣿⣿⣷⣦⣝⣷⡄⠀⠀⡰⠂⠀
⠀⠀⣨⣷⣶⣿⣧⣛⣛⠿⠿⣿⢿⣿⣿⣛⣿⡿⠀⠀⡇⠀⠀⠀⠀⠀⢸⠀⠈⢿⣟⣛⠿⢿⡿⢿⢿⣛⣫⣼⡿⣶⣾⣅⡀⠀
⢀⡼⠋⠁⠀⠀⠀⠈⠉⠛⠛⠻⠟⠸⠛⠋⠉⠁⠀⠀⢸⡇⠀⠀⠄⠀⢸⡄⠀⠀⠈⠉⠙⠛⠃⠻⠛⠛⠛⠉⠁⠀⠀⠈⠙⢧⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⢠⠀⠀⠀⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⣿⠇⠀⠀⠀⠀⢸⡇⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠰⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠖⡾⠁⠀⠀⣿⠀⠀⠀⠀⠀⠘⣿⠀⠀⠙⡇⢸⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠄⠀
⠀⠀⢻⣷⡦⣤⣤⣤⡴⠶⠿⠛⠉⠁⠀⢳⠀⢠⡀⢿⣀⠀⠀⠀⠀⣠⡟⢀⣀⢠⠇⠀⠈⠙⠛⠷⠶⢦⣤⣤⣤⢴⣾⡏⠀⠀
⠀⠀⠈⣿⣧⠙⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⢊⣙⠛⠒⠒⢛⣋⡚⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⡿⠁⣾⡿⠀⠀⠀
⠀⠀⠀⠘⣿⣇⠈⢿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⢿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⡟⠁⣼⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠘⣿⣦⠀⠻⣿⣷⣦⣤⣤⣶⣶⣶⣿⣿⣿⣿⠏⠀⠀⠻⣿⣿⣿⣿⣶⣶⣶⣦⣤⣴⣿⣿⠏⢀⣼⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢿⣷⣄⠙⠻⠿⠿⠿⠿⠿⢿⣿⣿⣿⣁⣀⣀⣀⣀⣙⣿⣿⣿⠿⠿⠿⠿⠿⠿⠟⠁⣠⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠻⣯⠙⢦⣀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⣠⠴⢋⣾⠟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠙⢧⡀⠈⠉⠒⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠐⠒⠉⠁⢀⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

![B-XSSRF v7 Main Menu](Screenshot%202026-11-17%20154950.png)

**B-XSSRF v7** is an advanced **End-to-End Automated Penetration Testing & Security Auditing Framework** engineered for mobile applications (Android) and backend infrastructure. The framework completely automates the security assessment lifecycle—from static analysis and deep decompilation to custom payload generation, live exploitation verification, and highly structured security reporting.

---

## 📌 Features

### 🔍 Static Analysis
- **Comprehensive Manifest Analysis**: 10+ security checks (debuggable, allowBackup, cleartext traffic, exported components, network security config, dangerous permissions, WebView settings, custom TrustManager, backup agent, native libs extraction)
- **Sensitive Data Extraction**: URLs, emails, API keys (Google, AWS, generic), JWT tokens, auth tokens from APK resources and code
- **Deep Source Scan**: Decompile APK with apktool, scan smali/XML/JS for secrets, endpoints, SQL/path traversal/XXE/deserialization patterns
- **Configurable Patterns**: Extend detection via YAML config with custom regex

### 🎯 Dynamic Analysis (Frida)
- **Modular Hook System**: Network (OkHttp, URL, SSL pinning), Storage (SharedPreferences, KeyStore, SQLCipher), IPC (Binder, AIDL, Messenger), Auth (Biometric, KeyStore), Anti-tamper (Root, Emulator, Debugger detection)
- **Structured Event Collection**: JSONL output with stack traces, timestamps, correlation IDs
- **Spawn/Attach Modes**: Flexible instrumentation

### ⚔️ Exploitation Engine
- **Attack Orchestration**: Automatic attack chain decision from static findings
- **Deep Link Injection**: SSRF, path traversal, open redirect, XXE, deserialization, WebView abuse, Intent abuse
- **Content Provider Testing**: SQL injection, path traversal, grantUriPermission abuse
- **JDWP Exploitation**: Code execution via debug port (jdwp-shellifier integration)
- **Backup Extraction**: Automated `adb backup` + `abe.jar` unpacking + analysis
- **Intent Injection**: Exported activity/service/receiver testing

### 🌐 Infrastructure Scanning
- **Full Port Scanning**: Nmap with service detection, OS fingerprinting
- **Vulnerability Testing**: SSRF (metadata services, cloud endpoints), RCE (command injection variants)
- **SSL/TLS Analysis**: Certificate validation, weak cipher/protocol detection, expiry monitoring
- **Nuclei Integration**: Template-based vulnerability scanning (CVEs, misconfigurations, exposures)
- **Subdomain Enumeration**: Passive DNS, certificate transparency logs

### 📊 Professional Reporting
- **Multi-format Output**: Console (Rich tables), Text, JSON, SARIF 2.1.0, HTML
- **Dynamic Recommendations**: Context-aware remediation based on actual findings
- **CI/CD Integration**: SARIF upload to GitHub Security tab, GitLab, Azure DevOps
- **Evidence Management**: Structured findings with severity, payload, evidence, timestamps

---

## 🚀 Quick Start

### Prerequisites

```bash
# System dependencies (Ubuntu/Debian/Kali)
sudo apt update && sudo apt install -y \
    python3.11 python3.11-venv \
    openjdk-17-jre-headless \
    apktool \
    nmap \
    aapt \
    adb

# Frida (optional, for dynamic analysis)
pip install frida-tools

# Nuclei (optional, for infrastructure vuln scanning)
# https://github.com/projectdiscovery/nuclei/releases
```

### Installation

```bash
# Clone repository
git clone https://github.com/mazen-elgammal10/b-xssrf-framework.git
cd b-xssrf-framework

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# Or for development
pip install -e ".[dev]"
```

### Run

```bash
# Interactive CLI
python main.py

# Or if installed as package
b-xssrf
```

---

## 🎮 Usage

### Interactive Menu

The framework features a modern terminal interface with a hacker aesthetic:

```
┌─[ MODULES ]─

  [1] MOBILE AUDIT       → Static manifest analysis + secret extraction
  [2] INFRASTRUCTURE     → Network recon, port scanning, vuln assessment
  [3] ATTACK CHAIN       → Build & execute exploit chains from findings
  [4] AUTO EXPLOIT       → Full automation: static → dynamic → exploit → report
  [5] DECOMPILE APK      → Decompile APK with apktool for manual analysis
  [6] GENERATE PAYLOADS  → Create custom exploitation payloads for endpoints
  [0] EXIT               → Terminate framework

└─[ SELECT OPTION ]─

┌─[b-xssrf]
└──► Enter APK Path:
```

### Full Automation Chain (Option 4)

```bash
# Select option 4, then provide APK path
[+] Enter APK Path: /path/to/app.apk
```

**Execution Lifecycle:**
1. **Static Analysis** → Manifest risks + sensitive data extraction
2. **Deep Scan** → Decompile APK, scan for secrets/endpoints/injection patterns
3. **Payload Generation** → Context-aware exploitation vectors
4. **Live Exploitation** → ADB-based verification (if device connected)
5. **Final Report** → Multi-format security report with recommendations

### Command Line Options (Planned)

```bash
# Direct scanning
b-xssrf scan --apk app.apk --format sarif --output report.sarif

# Payload generation
b-xssrf payloads --url https://api.example.com --categories ssrf,xxe

# Infrastructure scan
b-xssrf infra --target example.com --full-scan

# Decompile only
b-xssrf decompile --apk app.apk --output ./extracted
```

---

## ⚙️ Configuration

Copy `config.yaml` to `config.local.yaml` for local overrides (gitignored):

```yaml
# config.local.yaml
general:
  log_level: "DEBUG"
  output_dir: "./my_reports"

static_analysis:
  deep_scan:
    max_results_per_category: 100

payloads:
  ssrf:
    - "http://custom.internal/metadata"

exploitation:
  deeplink:
    max_payloads_per_endpoint: 50

reporting:
  formats: ["console", "json", "sarif", "html"]
  auto_save: true
```

### Environment Variables

All config options can be overridden via `BXSSRF_` prefix:

```bash
BXSSRF_GENERAL__LOG_LEVEL=DEBUG
BXSSRF_STATIC_ANALYSIS__DEEP_SCAN__MAX_RESULTS_PER_CATEGORY=200
BXSSRF_REPORTING__FORMATS='["console", "sarif"]'
python main.py
```

---

## 📁 Project Structure

```
b-xssrf-framework/
├── main.py                    # CLI entry point
├── config.yaml                # Default configuration
├── config_loader.py           # Configuration management (Pydantic)
├── logging_setup.py           # Structured logging (structlog)
├── pyproject.toml             # Package metadata & tool config
├── requirements.txt           # Dependencies
├── Makefile                   # Development commands
├── CONTRIBUTING.md            # Contribution guidelines
│
├── core_engine.py             # Pipeline orchestration
├── manifest_parser.py         # Android Manifest analysis
├── scraper.py                 # Deep source code scanner
├── payload_factory.py         # Exploitation payload generation
├── executor.py                # ADB device communication
├── attack_orchestrator.py     # Attack chain decision & execution
├── reporter.py                # Multi-format report generation
├── server_scanner.py          # Infrastructure vulnerability scanner
├── frida_runner.py            # Frida dynamic analysis manager
├── frida_hook.js              # Main Frida hook script
├── logcat_monitor.py          # Logcat collection & streaming
├── result_analyzer.py         # Logcat analysis for exploitation evidence
├── unpacker.py                # APK decompilation (apktool wrapper)
├── logger_silencer.py         # Legacy logger suppression
├── ai_bridge.py               # AI payload generation (experimental)
│
├── tests/                     # Unit tests
│   ├── test_payload_factory.py
│   ├── test_scraper.py
│   ├── test_attack_orchestrator.py
│   ├── test_result_analyzer.py
│   └── test_config_loader.py
│
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI/CD
│
├── pre-commit-config.yaml     # Pre-commit hooks (rename to .pre-commit-config.yaml)
├── gitignore.txt              # Git ignore patterns (rename to .gitignore)
│
└── output/                    # Generated reports (gitignored)
```

---

## 🔧 Development

### Common Commands

```bash
# Install dev dependencies
make install-dev

# Run all quality checks
make lint
make typecheck
make test
make security

# Format code
make format

# Build package
make build

# Run tests with coverage
make test

# Update dependencies
make deps-update
```

### Pre-commit Hooks

```bash
# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Adding New Features

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Adding payload categories
- Creating Frida hooks
- Building exploit modules
- Adding manifest checks
- Writing tests

---

## 📋 Requirements

| Tool | Purpose | Required |
|------|---------|----------|
| Python 3.10+ | Core runtime | ✅ |
| apktool | APK decompilation | ✅ |
| ADB | Device communication | ✅ |
| aapt | APK metadata extraction | ✅ |
| Nmap | Port scanning | ✅ |
| Frida | Dynamic analysis | Optional |
| Nuclei | Vulnerability templates | Optional |
| Subfinder | Subdomain enumeration | Optional |

### Python Dependencies

```
androguard>=3.4.0      # APK parsing
rich>=13.7.0           # Terminal UI
python-nmap>=0.7.1     # Nmap wrapper
requests>=2.31.0       # HTTP client
frida-tools>=12.0.0    # Frida CLI
pyyaml>=6.0.1          # Config parsing
structlog>=24.1.0      # Structured logging
pydantic>=2.5.0        # Config validation
pydantic-settings>=2.1.0  # Env var config
```

---

## 🛡️ Security

**Disclaimer**: This framework is built strictly for authorized penetration testing, industrial security auditing, and academic research. Operating this utility against unauthorized environments without proper written approval is explicitly prohibited. The author holds no liability for downstream infrastructure damages or alignment issues caused by inappropriate usage.

### Responsible Disclosure

If you discover a security vulnerability in B-XSSRF itself, please report it privately via GitHub Security Advisories or email the maintainer.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Code style and standards
- Testing requirements
- Pull request process
- Adding new features

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Mazen El-Gammal** — Cybersecurity Researcher & Core Developer

- GitHub: [@mazen-elgammal10](https://github.com/mazen-elgammal10)
- LinkedIn: [Mazen El-Gammal](https://www.linkedin.com/in/mazen-el-gammal-1934a1291/)

---

## 🙏 Acknowledgments

- [Androguard](https://github.com/androguard/androguard) — APK analysis
- [Frida](https://frida.re/) — Dynamic instrumentation
- [Nmap](https://nmap.org/) — Network exploration
- [Nuclei](https://github.com/projectdiscovery/nuclei) — Vulnerability templates
- [Rich](https://github.com/Textualize/rich) — Terminal formatting
- [Ruff](https://github.com/astral-sh/ruff) — Fast Python linting

---

⭐ **Star this repo if you find it useful!** ⭐