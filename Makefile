.PHONY: install install-dev test lint format clean build docker-build help

PYTHON := python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

help:
	@echo "AgentGuard-CLI - Available commands:"
	@echo ""
	@echo "  make install      - Install package for production"
	@echo "  make install-dev  - Install package with dev dependencies"
	@echo "  make test         - Run test suite"
	@echo "  make lint         - Run linter (ruff)"
	@echo "  make format       - Format code (ruff)"
	@echo "  make build        - Build wheel distribution"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make docker-build - Build Docker image"
	@echo ""

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(VENV_PIP) install --upgrade pip

install: $(VENV)
	$(VENV_PIP) install -e .

install-dev: $(VENV)
	$(VENV_PIP) install -e ".[dev]"

test: install-dev
	$(VENV_PYTHON) -m pytest tests/ -v

lint: install-dev
	$(VENV_PYTHON) -m ruff check src/ tests/
	$(VENV_PYTHON) -m mypy src/

format: install-dev
	$(VENV_PYTHON) -m ruff format src/ tests/

build: clean
	$(VENV_PIP) install build
	$(VENV_PYTHON) -m build

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

docker-build:
	docker build -t agentguard-cli:latest .
