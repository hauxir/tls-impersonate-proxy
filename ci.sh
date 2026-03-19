#!/bin/bash
set -e

echo "Running basedpyright type checks..."
basedpyright tls_impersonate_proxy/

echo ""
echo "Running ruff linting..."
ruff check tls_impersonate_proxy/

echo ""
echo "Running tests..."
python -m pytest tests/ -v -m "not live"

echo ""
echo "All checks passed!"
