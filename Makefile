# Velora developer Makefile
VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.PHONY: help venv install dev test lint format typecheck run docker-build docker-up clean

help:
	@echo "Velora — make targets"
	@echo "  venv        Create the virtualenv"
	@echo "  install     Install the package"
	@echo "  dev         Install with dev + reference-stack extras"
	@echo "  test        Run the test suite (pytest, or unittest fallback)"
	@echo "  lint        ruff check"
	@echo "  format      black + ruff --fix"
	@echo "  typecheck   mypy"
	@echo "  run         Launch the dashboard"
	@echo "  docker-build / docker-up"

venv:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip wheel

install: venv
	$(PIP) install .

dev: venv
	$(PIP) install -e ".[dev,pdf,reference-stack]"

test:
	@if $(VENV)/bin/pytest --version >/dev/null 2>&1; then \
		$(VENV)/bin/pytest -q; \
	else \
		echo "pytest not installed; using unittest"; \
		PYTHONPATH=.:tests/fixtures $(PY) -m unittest discover -s tests -t . -p "test_*.py"; \
	fi

lint:
	@if $(VENV)/bin/ruff --version >/dev/null 2>&1; then \
		$(VENV)/bin/ruff check .; \
	else \
		echo "ruff not installed; using scripts/lintcheck.py"; \
		$(PY) scripts/lintcheck.py; \
	fi
format:
	$(VENV)/bin/black velora tests
	$(VENV)/bin/ruff check --fix velora tests

typecheck:
	$(VENV)/bin/mypy velora

run:
	$(VENV)/bin/velora dashboard

docker-build:
	docker build -f docker/Dockerfile -t velora:2.0.0 .

docker-up:
	docker compose -f docker/docker-compose.yml up --build

clean:
	rm -rf build dist *.egg-info **/__pycache__ .pytest_cache .mypy_cache .ruff_cache
