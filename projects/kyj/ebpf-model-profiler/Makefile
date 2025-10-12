# Makefile - Build and installation automation for eBPF Model Profiler

.PHONY: install install-bcc test clean dev-install check-kernel help

help:
	@echo "eBPF Model Profiler - Available targets:"
	@echo "  install       - Install the package"
	@echo "  install-bcc   - Install BCC dependencies"
	@echo "  dev-install   - Install in development mode"
	@echo "  check-kernel  - Check kernel eBPF support"
	@echo "  test          - Run tests"
	@echo "  clean         - Remove build artifacts"

install:
	pip install -e .
	chmod +x scripts/*.sh

install-bcc:
	./scripts/setup_bcc.sh

dev-install:
	pip install -e ".[dev]"
	chmod +x scripts/*.sh

check-kernel:
	python scripts/check_kernel.py

test:
	pytest tests/ -v --cov=src

clean:
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
