#!/usr/bin/env bash
# Starts the Playwright MCP server for Claude Code.
# In the Claude Code cloud container, reuse the pre-installed Chromium headless;
# elsewhere, fall back to Playwright's defaults (local Chrome, headed).
set -euo pipefail

args=(--isolated)
if [ -x /opt/pw-browsers/chromium ]; then
  args+=(--browser chromium --executable-path /opt/pw-browsers/chromium --headless --no-sandbox)
fi

exec npx -y @playwright/mcp@0.0.83 "${args[@]}" "$@"
