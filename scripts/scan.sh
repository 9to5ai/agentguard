#!/usr/bin/env bash
# AgentGuard Scanner — OWASP ASI Top 10 Assessment
# Scans OpenClaw config, cron jobs, skills, and environment
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$SKILL_DIR/reports"
WORKSPACE="$HOME/.openclaw/workspace"

mkdir -p "$REPORT_DIR"

echo "🔍 AgentGuard Scanner — Running OWASP ASI Top 10 assessment..." >&2

# Step 1: Parse config to clean JSON
python3 -c "
import re, json
with open('$HOME/.openclaw/openclaw.json') as f:
    c = f.read()
c = re.sub(r',(\s*[}\]])', r'\1', c)
c = re.sub(r'(?<=[{,\n])\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*:', r' \"\1\":', c)
c = c.replace(\"'\", '\"')
data = json.loads(c)
with open('/tmp/agentguard-config.json', 'w') as f:
    json.dump(data, f)
" 2>/dev/null

# Step 2: Run the full scan in Python
python3 "$SCRIPT_DIR/scanner.py" "$@"
