#!/usr/bin/env bash
# Setups the repository.

# Stop on errors
set -e

# Use copy mode for UV to avoid hardlink warnings on different filesystems
export UV_LINK_MODE=copy

# Estrae la versione di UV direttamente dal file di configurazione della CI
UV_VERSION=$(grep 'UV_VERSION:' .github/workflows/ci.yml | sed -E 's/.*"([^"]+)".*/\1/')

if ! uv --version 2>/dev/null; then
    pipx install "uv==$UV_VERSION"
elif ! uv --version 2>/dev/null | grep -q "$UV_VERSION"; then
    pipx upgrade "uv==$UV_VERSION"
fi
if ! prek --version 2>/dev/null; then
    uv tool install prek
fi
uv sync --frozen --all-groups
prek install --overwrite
prek install --hook-type commit-msg --overwrite

npm install @commitlint/config-conventional
