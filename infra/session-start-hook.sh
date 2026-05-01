#!/usr/bin/env bash
# Claude Code on Web - SessionStart hook for Threat-Emulation.
#
# Bootstraps the dev environment so an interactive web session can run linters
# and tests without further setup. Idempotent and fast: skips work that's
# already done.
#
# Configured via .claude/settings.json with:
#   "hooks": { "SessionStart": [{ "command": "bash infra/session-start-hook.sh" }] }

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() { printf '[session-start] %s\n' "$*"; }

# 1. Ensure uv is installed.
if ! command -v uv >/dev/null 2>&1; then
  log "installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

UV_VERSION="$(uv --version | awk '{print $2}')"
log "uv ${UV_VERSION}"

# 2. Sync the Python environment with dev extras.
if [[ ! -d .venv ]] || [[ pyproject.toml -nt .venv/pyvenv.cfg ]]; then
  log "syncing dependencies (dev extras)"
  uv sync --extra dev
else
  log "venv up to date"
fi

# 3. Sanity check: the package imports.
if ! uv run python -c "import threat_emulation" 2>/dev/null; then
  log "warning: package import failed; re-syncing"
  uv sync --extra dev --reinstall
fi

# 4. Print quick-start hints for the operator.
cat <<'EOF'

threat-emulation dev environment ready.

Quick checks:
  uv run ruff check .
  uv run ruff format --check .
  uv run mypy .
  uv run pytest -q

Reminders (CLAUDE.md):
  - Defensive research only.
  - No real-internet egress from the lab.
  - Destructive tier requires 2-person integrity.
  - TLP:AMBER+ uses the local embedder; never third-party APIs.
EOF
