#!/usr/bin/env python3
"""AgentGuard Module 3: Audit Trail Packager
Collects agent activity data and structures it for audit/compliance purposes."""

import json, os, sys, glob, csv, io
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).parent.parent
REPORT_DIR = SKILL_DIR / "reports"
WORKSPACE = Path.home() / ".openclaw" / "workspace"
OPENCLAW_DIR = Path.home() / ".openclaw"

timestamp = datetime.now(timezone.utc).isoformat()

def load_scan():
    f = REPORT_DIR / "latest.json"
    return json.load(open(f)) if f.exists() else {}

def load_risk_register():
    f = REPORT_DIR / "risk-register.json"
    return json.load(open(f)) if f.exists() else {}

def run_cmd(cmd, default=""):
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except:
        return default

print("📋 Collecting audit trail data...", file=sys.stderr)

# --- 1. Configuration snapshot ---
config_raw = ""
config_path = OPENCLAW_DIR / "openclaw.json"
if config_path.exists():
    import re
    with open(config_path) as f:
        c = f.read()
    c = re.sub(r',(\s*[}\]])', r'\1', c)
    c = re.sub(r'(?<=[{,\n])\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*:', r' "\1":', c)
    c = c.replace("'", '"')
    try:
        config_data = json.loads(c)
        # Redact sensitive fields
        def redact(d, keys=("token", "botToken", "apiKey", "password", "secret")):
            if isinstance(d, dict):
                return {k: "***REDACTED***" if any(s in k.lower() for s in keys) else redact(v, keys) for k, v in d.items()}
            elif isinstance(d, list):
                return [redact(i, keys) for i in d]
            return d
        config_data = redact(config_data)
    except:
        config_data = {"error": "Could not parse config"}

# --- 2. Git change log (last 30 days) ---
git_log = []
raw = run_cmd(f"cd {WORKSPACE} && git log --oneline --since='30 days ago' --format='%H|%ai|%s' 2>/dev/null")
for line in raw.split("\n"):
    if "|" in line:
        parts = line.split("|", 2)
        if len(parts) == 3:
            git_log.append({"hash": parts[0][:8], "date": parts[1].strip(), "message": parts[2].strip()})

# --- 3. Cron job activity ---
cron_data = run_cmd("openclaw cron list --json 2>/dev/null")
cron_jobs = []
try:
    parsed = json.loads(cron_data)
    jobs = parsed if isinstance(parsed, list) else parsed.get("jobs", [])
    for j in jobs:
        state = j.get("state", {})
        cron_jobs.append({
            "name": j.get("name", "unnamed"),
            "id": j.get("id", ""),
            "schedule": j.get("schedule", {}),
            "enabled": j.get("enabled", False),
            "session_target": j.get("sessionTarget", ""),
            "model": j.get("payload", {}).get("model", "default"),
            "has_timeout": bool(j.get("payload", {}).get("timeoutSeconds")),
            "timeout_seconds": j.get("payload", {}).get("timeoutSeconds"),
            "last_run": state.get("lastRunAtMs"),
            "last_status": state.get("lastRunStatus", "unknown"),
            "last_duration_ms": state.get("lastDurationMs"),
            "consecutive_errors": state.get("consecutiveErrors", 0),
            "delivery_mode": j.get("delivery", {}).get("mode", "none"),
        })
except:
    pass

# --- 4. Installed skills inventory ---
bundled_dir = Path("/opt/homebrew/lib/node_modules/openclaw/skills")
bundled = sorted(os.listdir(bundled_dir)) if bundled_dir.exists() else []
workspace_skills_dir = WORKSPACE / "skills"
custom = sorted(os.listdir(workspace_skills_dir)) if workspace_skills_dir.exists() else []

skills_inventory = [
    {"name": s, "type": "bundled", "location": str(bundled_dir / s)} for s in bundled
] + [
    {"name": s, "type": "custom", "location": str(workspace_skills_dir / s)} for s in custom
]

# --- 5. Memory file inventory ---
memory_dir = WORKSPACE / "memory"
memory_inventory = []
if memory_dir.exists():
    for f in sorted(os.listdir(memory_dir)):
        fp = memory_dir / f
        stat = fp.stat()
        memory_inventory.append({
            "filename": f,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        })

# Also check MEMORY.md
mem_md = WORKSPACE / "MEMORY.md"
if mem_md.exists():
    stat = mem_md.stat()
    memory_inventory.append({
        "filename": "MEMORY.md",
        "size_bytes": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    })

# --- 6. Browser profile data ---
browser_dir = Path.home() / ".openclaw" / "browser"
browser_info = []
if browser_dir.exists():
    for profile in os.listdir(browser_dir):
        pdir = browser_dir / profile
        if pdir.is_dir():
            size = sum(f.stat().st_size for f in pdir.rglob("*") if f.is_file())
            browser_info.append({
                "profile": profile,
                "size_mb": round(size / 1024 / 1024, 1),
            })

# --- 7. Environment metadata ---
env_info = {
    "hostname": os.uname().nodename,
    "os": f"{os.uname().sysname} {os.uname().release}",
    "arch": os.uname().machine,
    "openclaw_version": run_cmd("openclaw --version 2>/dev/null") or "unknown",
    "python_version": sys.version.split()[0],
    "node_version": run_cmd("node --version 2>/dev/null") or "unknown",
}

# --- Compile audit trail ---
audit = {
    "meta": {
        "title": "OpenClaw Agent Audit Trail",
        "generated_by": "AgentGuard v0.1.0",
        "timestamp": timestamp,
        "target": f"OpenClaw @ {os.uname().nodename}",
        "period": "Current state + 30-day git history",
    },
    "sections": {
        "configuration": {
            "description": "Current agent configuration (sensitive values redacted)",
            "config": config_data,
        },
        "change_log": {
            "description": f"Git commit history — last 30 days ({len(git_log)} commits)",
            "entries": git_log,
        },
        "cron_activity": {
            "description": f"{len(cron_jobs)} scheduled jobs with last run status",
            "jobs": cron_jobs,
        },
        "skills_inventory": {
            "description": f"{len(skills_inventory)} skills installed ({len(bundled)} bundled, {len(custom)} custom)",
            "skills": skills_inventory,
        },
        "memory_inventory": {
            "description": f"{len(memory_inventory)} memory/context files",
            "files": memory_inventory,
        },
        "browser_profiles": {
            "description": f"{len(browser_info)} browser profile(s)",
            "profiles": browser_info,
        },
        "environment": {
            "description": "System and runtime environment",
            "info": env_info,
        },
    },
}

# Save JSON
out_json = REPORT_DIR / "audit-trail.json"
with open(out_json, "w") as f:
    json.dump(audit, f, indent=2)

# Also generate CSV summary of cron activity
out_csv = REPORT_DIR / "cron-activity.csv"
with open(out_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Job Name", "Schedule", "Enabled", "Model", "Has Timeout", "Last Status", "Last Duration (s)", "Errors", "Delivery"])
    for j in cron_jobs:
        sched = j["schedule"]
        sched_str = sched.get("expr", f"every {sched.get('everyMs', 0)//1000}s") if sched else ""
        writer.writerow([
            j["name"], sched_str, j["enabled"], j["model"],
            j["has_timeout"], j["last_status"],
            round(j["last_duration_ms"]/1000, 1) if j["last_duration_ms"] else "",
            j["consecutive_errors"], j["delivery_mode"],
        ])

print(json.dumps(audit, indent=2))
print(f"\n✅ Audit trail: {out_json}", file=sys.stderr)
print(f"✅ Cron CSV: {out_csv}", file=sys.stderr)
