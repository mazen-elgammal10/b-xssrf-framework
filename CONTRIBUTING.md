# Contributing to B-XSSRF

Thank you for your interest in contributing to B-XSSRF! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Git
- ADB (Android Debug Bridge)
- apktool
- Frida (optional, for dynamic analysis)
- Nmap (optional, for infrastructure scanning)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/mazen-elgammal10/b-xssrf-framework.git
cd b-xssrf-framework

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
make install-dev

# Install pre-commit hooks
make pre-commit

# Run tests to verify setup
make test
```

## 📋 Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Follow the existing code style (enforced by Ruff)
- Add type hints to all new functions
- Write tests for new functionality
- Update documentation as needed

### 3. Run Quality Checks

```bash
# Run all checks
make lint
make typecheck
make test
make security
```

### 4. Commit Changes

```bash
git add .
git commit -m "feat: add new feature description"
# or
git commit -m "fix: resolve issue description"
```

Pre-commit hooks will automatically run checks on commit.

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## 🎯 Contribution Areas

### High Priority

- **New Frida Hooks**: Add hooks for WebView, SSL pinning, crypto, IPC, auth bypass
- **Payload Modules**: XXE, deserialization, GraphQL, SSTI, NoSQLi, LDAPi
- **Exploit Modules**: Content Provider SQLi, JDWP shell, Backup extraction, Intent injection
- **Infrastructure**: Nuclei integration, subdomain enumeration, SSL analysis

### Medium Priority

- **Static Analysis**: Taint tracking integration (Quark/FlowDroid), native library analysis
- **Reporting**: HTML report templates, SARIF enhancements, evidence management
- **Plugin System**: Plugin architecture, plugin registry, example plugins

### Good First Issues

- Add new SSRF bypass payloads
- Improve regex patterns for secret detection
- Add more dangerous permissions to manifest checks
- Improve error messages and logging
- Add unit tests for uncovered code

## 📝 Code Style Guidelines

### Python Style

- Follow PEP 8 (enforced by Ruff)
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use double quotes for strings
- Use `snake_case` for functions/variables, `PascalCase` for classes

### Type Hints

```python
# Good
def generate_payloads(base_url: str, categories: list[str] | None = None) -> list[str]:
    ...

# Avoid
def generate_payloads(base_url, categories=None):
    ...
```

### Logging

Use structured logging via `logging_setup`:

```python
from logging_setup import get_logger, log_operation

logger = get_logger(__name__)

with log_operation("my_operation", param=value):
    logger.info("operation_started", extra_param=value)
    # ...
    logger.warning("something_suspicious", detail=detail)
```

### Error Handling

- Don't use bare `except:` - catch specific exceptions
- Log errors with context using structured logging
- Return meaningful error information

```python
# Good
try:
    result = risky_operation()
except SpecificException as e:
    logger.error("operation_failed", error=str(e), exc_info=True)
    return False, str(e)

# Avoid
try:
    result = risky_operation()
except:
    pass
```

## 🧪 Testing Guidelines

### Test Structure

```python
# tests/test_module.py
import pytest
from module import function

class TestFunction:
    """Tests for function."""

    def test_normal_case(self):
        """Test normal operation."""
        result = function("input")
        assert result == "expected"

    def test_edge_case(self):
        """Test edge case."""
        with pytest.raises(ValueError):
            function("")

    @pytest.mark.parametrize("input,expected", [
        ("a", "A"),
        ("b", "B"),
    ])
    def test_parametrized(self, input, expected):
        """Parametrized test."""
        assert function(input) == expected
```

### Test Categories

- **Unit tests** (`tests/test_*.py`): Fast, isolated tests
- **Integration tests** (`tests/test_*_integration.py`): Tests requiring external tools (mark with `@pytest.mark.integration`)

### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# With coverage report
pytest tests/ --cov=. --cov-report=html
```

## 📦 Adding New Features

### 1. Payload Category

To add a new payload category:

1. Add patterns to `config.yaml` under `payloads:`
2. Add generation function in `payload_factory.py`
3. Update `generate_payloads()` to include new category
4. Add tests in `tests/test_payload_factory.py`

### 2. Frida Hook

To add a Frida hook:

1. Create new hook file in `frida_hooks/` (e.g., `frida_hooks/crypto.js`)
2. Add hook category to `config.yaml` under `dynamic_analysis.hook_categories`
3. Update `frida_runner.py` to load new hook
4. Document the hook in `docs/frida-hooks.md`

### 3. Exploit Module

To add a new exploit module:

1. Create module in `exploits/` (e.g., `exploits/content_provider.py`)
2. Add attack type to `attack_orchestrator.decide_attacks()`
3. Implement execution in `attack_orchestrator.run_attacks()`
4. Add tests

### 4. Manifest Check

To add a new manifest check:

1. Add check method to `BxssrfMobileParser` in `manifest_parser.py`
2. Add config option in `config.yaml` under `static_analysis.manifest_checks`
3. Add risk level in `config.yaml` under `risk_scoring.manifest_risks`
4. Update `get_attack_surface()` to call new check

## 🔒 Security Considerations

- **Never commit secrets**: API keys, tokens, passwords
- **Validate all inputs**: Especially user-provided APK paths, URLs
- **Use subprocess safely**: Avoid `shell=True`, validate commands
- **Handle errors gracefully**: Don't leak stack traces to users
- **Report vulnerabilities privately**: See SECURITY.md

## 📚 Documentation

- Update `README.md` for user-facing changes
- Update docstrings for API changes
- Add examples for new features
- Keep `CHANGELOG.md` updated

## 🏷️ Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(payloads): add GraphQL introspection payloads
fix(scraper): handle encoding errors in smali files
docs: update Frida hooks documentation
test(analyzer): add ANR detection tests
```

## 🤝 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- No harassment or discrimination

## 📞 Getting Help

- Open an issue for bugs/features
- Start a discussion for questions
- Check existing issues/PRs before creating new ones

---

Thank you for contributing to B-XSSRF! 🛡️