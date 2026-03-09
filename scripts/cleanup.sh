#!/usr/bin/env bash
set -euo pipefail

echo "🚀 Starting Python dev cleanup..."

# ----- Python bytecode -----
echo "Removing __pycache__ and *.py[co]..."
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.py[co]" -delete

# ----- Tool caches -----
echo "Removing tool caches..."
for cache in .mypy_cache .ruff_cache .pytest_cache .coverage .hypothesis .pytype .isort_cache; do
    [ -d "$cache" ] && rm -rf "$cache" && echo "Removed $cache"
done

# ----- Virtual environments -----
echo "Removing virtual environments..."
for venv in .venv venv env .env; do
    [ -d "$venv" ] && rm -rf "$venv" && echo "Removed $venv"
done

# ----- Build artifacts -----
echo "Removing build artifacts..."
for build in build dist *.egg-info; do
    [ -e "$build" ] && rm -rf "$build" && echo "Removed $build"
done

# ----- IDE / project folders -----
echo "Removing IDE folders..."
for ide in .idea; do
    [ -d "$ide" ] && rm -rf "$ide" && echo "Removed $ide"
done

echo "✅ Cleanup complete!"
