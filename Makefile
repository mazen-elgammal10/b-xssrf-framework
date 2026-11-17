# B-XSSRF v7 - Makefile
# Common development tasks

.PHONY: help install test lint format typecheck security build clean run

# Default target
help:
	@echo "B-XSSRF v7 - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  install        Install dependencies"
	@echo "  install-dev    Install development dependencies"
	@echo "  pre-commit     Install pre-commit hooks"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint           Run Ruff linter"
	@echo "  format         Format code with Ruff"
	@echo "  typecheck      Run MyPy type checker"
	@echo "  security       Run security scans (bandit, safety)"
	@echo ""
	@echo "Testing:"
	@echo "  test           Run all tests with coverage"
	@echo "  test-unit      Run unit tests only"
	@echo "  test-watch     Run tests in watch mode"
	@echo ""
	@echo "Building:"
	@echo "  build          Build package (sdist + wheel)"
	@echo "  build-docker   Build Docker image"
	@echo ""
	@echo "Running:"
	@echo "  run            Run B-XSSRF CLI"
	@echo "  run-mobile     Run mobile audit on APK (usage: make run-mobile APK=path/to/app.apk)"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean          Clean build artifacts"
	@echo "  deps-update    Update dependencies"
	@echo "  deps-check     Check for outdated dependencies"

# ============================
# Setup
# ============================

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -e ".[dev]"

pre-commit:
	pip install pre-commit
	pre-commit install

# ============================
# Code Quality
# ============================

lint:
	ruff check .

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy .

security:
	bandit -r . -f json -o bandit-report.json || true
	safety check --json --output safety-report.json || true

# ============================
# Testing
# ============================

test:
	pytest tests/ -v --tb=short --cov=. --cov-report=term-missing --cov-report=html

test-unit:
	pytest tests/ -v --tb=short -m "unit"

test-integration:
	pytest tests/ -v --tb=short -m "integration"

test-watch:
	pytest tests/ -v --tb=short --watch

# ============================
# Building
# ============================

build:
	python -m build

build-docker:
	docker build -t b-xssrf:latest .

# ============================
# Running
# ============================

run:
	python main.py

run-mobile:
	@if [ -z "$(APK)" ]; then echo "Usage: make run-mobile APK=path/to/app.apk"; exit 1; fi
	python -c "from core_engine import run_full_pipeline; results, sensitive = run_full_pipeline('$(APK)'); print('Results:', results); print('Sensitive:', sensitive)"

# ============================
# Maintenance
# ============================

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ htmlcov/ bandit-report.json safety-report.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

deps-update:
	pip install --upgrade pip
	pip install --upgrade -r requirements.txt
	pip list --outdated

deps-check:
	pip list --outdated

# ============================
# Release
# ============================

release-check:
	@echo "Checking release readiness..."
	@make lint
	@make typecheck
	@make test
	@make security
	@make build
	@twine check dist/*
	@echo "All checks passed!"

version-patch:
	@python -c "import toml; data=toml.load('pyproject.toml'); v=data['project']['version']; parts=v.split('.'); parts[2]=str(int(parts[2])+1); data['project']['version']='.'.join(parts); toml.dump(data, open('pyproject.toml','w')); print('New version:', data['project']['version'])"

version-minor:
	@python -c "import toml; data=toml.load('pyproject.toml'); v=data['project']['version']; parts=v.split('.'); parts[1]=str(int(parts[1])+1); parts[2]='0'; data['project']['version']='.'.join(parts); toml.dump(data, open('pyproject.toml','w')); print('New version:', data['project']['version'])"

version-major:
	@python -c "import toml; data=toml.load('pyproject.toml'); v=data['project']['version']; parts=v.split('.'); parts[0]=str(int(parts[0])+1); parts[1]='0'; parts[2]='0'; data['project']['version']='.'.join(parts); toml.dump(data, open('pyproject.toml','w')); print('New version:', data['project']['version'])"