#!/usr/bin/env python3
"""AgentGuard Module 4: Continuous Monitoring
Compares current state against baseline to detect drift, new risks, and changes."""

import json, os, sys, subprocess
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).parent.parent
REPORT_DIR = SKILL_DIR / "reports"
BASELINE_FILE = REPORT_DIR / "baseline.json"
WORKSPACE = Path.home() / ".openclaw" / "workspace"

timestamp = datetime.now(timezone.utc).isoformat()

def run_cmd(cmd, default=""):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except:
        return default

def load_json(path):
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None

print("🔄 AgentGuard Monitor — Checking for drift...", file=sys.stderr)

# --- Collect current state ---
def get_current_state():
    # Config hash
    import re, hashlib
    config_path = Path.home() / ".openclaw" / "openclaw.json"
    config_hash = ""
    if config_path.exists():
        config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()[:16]
    
    # Skills
    bundled_dir = Path("/opt/homebrew/lib/node_modules/openclaw/skills")
    bundled = sorted(os.listdir(bundled_dir)) if bundled_dir.exists() else []
    ws_dir = WORKSPACE / "skills"
    custom = sorted(os.listdir(ws_dir)) if ws_dir.exists() else []
    
    # Cron jobs
    cron_raw = run_cmd("openclaw cron list --json 2>/dev/null")
    cron_names = []
    cron_count = 0
    try:
        parsed = json.loads(cron_raw)
        jobs = parsed if isinstance(parsed, list) else parsed.get("jobs", [])
        cron_names = sorted([j.get("name", "") for j in jobs])
        cron_count = len(jobs)
    except:
        pass
    
    # Memory files
    mem_dir = WORKSPACE / "memory"
    mem_files = sorted(os.listdir(mem_dir)) if mem_dir.exists() else []
    
    # Git status
    git_dirty = run_cmd(f"cd {WORKSPACE} && git status --porcelain 2>/dev/null | wc -l").strip()
    
    # OpenClaw version
    oc_version = run_cmd("openclaw --version 2>/dev/null")
    
    # Scan score (from latest report)
    scan = load_json(REPORT_DIR / "latest.json")
    scan_score = scan["summary"]["score_pct"] if scan else None
    scan_failures = scan["summary"]["failed"] if scan else None
    
    return {
        "timestamp": timestamp,
        "config_hash": config_hash,
        "bundled_skills": bundled,
        "bundled_skill_count": len(bundled),
        "custom_skills": custom,
        "custom_skill_count": len(custom),
        "cron_job_names": cron_names,
        "cron_job_count": cron_count,
        "memory_files": mem_files,
        "memory_file_count": len(mem_files),
        "git_uncommitted_changes": int(git_dirty) if git_dirty.isdigit() else 0,
        "openclaw_version": oc_version,
        "last_scan_score": scan_score,
        "last_scan_failures": scan_failures,
    }

current = get_current_state()

# --- Compare against baseline ---
baseline = load_json(BASELINE_FILE)
alerts = []
changes = []

if baseline is None:
    # First run — save baseline
    alerts.append({
        "severity": "INFO",
        "indicator": "ℹ️",
        "title": "Baseline Established",
        "detail": "First monitoring run. Current state saved as baseline for future comparisons.",
    })
else:
    # Config drift
    if current["config_hash"] != baseline.get("config_hash"):
        alerts.append({
            "severity": "HIGH",
            "indicator": "🔴",
            "title": "Configuration Changed",
            "detail": f"Config hash changed: {baseline.get('config_hash', '?')[:8]} → {current['config_hash'][:8]}. Review changes for security impact.",
        })
        changes.append("config_modified")
    
    # New skills installed
    old_bundled = set(baseline.get("bundled_skills", []))
    new_bundled = set(current["bundled_skills"]) - old_bundled
    removed_bundled = old_bundled - set(current["bundled_skills"])
    if new_bundled:
        alerts.append({
            "severity": "MEDIUM",
            "indicator": "🟡",
            "title": "New Bundled Skills Detected",
            "detail": f"New skills installed: {', '.join(sorted(new_bundled))}. Audit before use.",
        })
        changes.append("new_bundled_skills")
    if removed_bundled:
        alerts.append({
            "severity": "LOW",
            "indicator": "ℹ️",
            "title": "Bundled Skills Removed",
            "detail": f"Skills removed: {', '.join(sorted(removed_bundled))}",
        })
    
    old_custom = set(baseline.get("custom_skills", []))
    new_custom = set(current["custom_skills"]) - old_custom
    if new_custom:
        alerts.append({
            "severity": "HIGH",
            "indicator": "🔴",
            "title": "New Custom Skills Added",
            "detail": f"New custom skills: {', '.join(sorted(new_custom))}. These run with full agent privileges — audit immediately.",
        })
        changes.append("new_custom_skills")
    
    # Cron job changes
    old_crons = set(baseline.get("cron_job_names", []))
    new_crons = set(current["cron_job_names"]) - old_crons
    removed_crons = old_crons - set(current["cron_job_names"])
    if new_crons:
        alerts.append({
            "severity": "MEDIUM",
            "indicator": "🟡",
            "title": "New Cron Jobs Added",
            "detail": f"New autonomous jobs: {', '.join(sorted(new_crons))}. Review triggers and permissions.",
        })
        changes.append("new_cron_jobs")
    if removed_crons:
        alerts.append({
            "severity": "LOW",
            "indicator": "ℹ️",
            "title": "Cron Jobs Removed",
            "detail": f"Removed: {', '.join(sorted(removed_crons))}",
        })
    
    # Memory growth
    old_mem = baseline.get("memory_file_count", 0)
    if current["memory_file_count"] > old_mem + 10:
        alerts.append({
            "severity": "MEDIUM",
            "indicator": "🟡",
            "title": "Rapid Memory Growth",
            "detail": f"Memory files grew from {old_mem} to {current['memory_file_count']}. Check for data accumulation.",
        })
    
    # Uncommitted changes
    if current["git_uncommitted_changes"] > 20:
        alerts.append({
            "severity": "LOW",
            "indicator": "ℹ️",
            "title": "Uncommitted Workspace Changes",
            "detail": f"{current['git_uncommitted_changes']} uncommitted files. Run backup.",
        })
    
    # Version change
    if current["openclaw_version"] != baseline.get("openclaw_version"):
        alerts.append({
            "severity": "MEDIUM",
            "indicator": "🟡",
            "title": "OpenClaw Version Changed",
            "detail": f"Version: {baseline.get('openclaw_version', '?')} → {current['openclaw_version']}. Review changelog for security fixes.",
        })
        changes.append("version_changed")
    
    # Scan score degradation
    old_score = baseline.get("last_scan_score")
    if old_score and current["last_scan_score"] and current["last_scan_score"] < old_score:
        alerts.append({
            "severity": "HIGH",
            "indicator": "🔴",
            "title": "Security Score Degraded",
            "detail": f"Scan score dropped: {old_score}% → {current['last_scan_score']}%. Run full scan to investigate.",
        })
        changes.append("score_degraded")
    
    # No changes
    if not alerts:
        alerts.append({
            "severity": "INFO",
            "indicator": "✅",
            "title": "No Drift Detected",
            "detail": "Current state matches baseline. No changes since last monitoring run.",
        })

# --- Save new baseline ---
with open(BASELINE_FILE, "w") as f:
    json.dump(current, f, indent=2)

# --- Build monitoring report ---
report = {
    "meta": {
        "title": "AgentGuard Monitoring Report",
        "generated_by": "AgentGuard v0.1.0",
        "timestamp": timestamp,
        "baseline_from": baseline["timestamp"] if baseline else "NEW",
        "target": f"OpenClaw @ {os.uname().nodename}",
    },
    "summary": {
        "total_alerts": len(alerts),
        "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "low": sum(1 for a in alerts if a["severity"] == "LOW"),
        "info": sum(1 for a in alerts if a["severity"] == "INFO"),
        "changes_detected": changes,
        "drift_detected": len(changes) > 0,
    },
    "alerts": alerts,
    "current_state": current,
}

out_file = REPORT_DIR / "monitor.json"
with open(out_file, "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps(report, indent=2))
print(f"\n✅ Monitor report: {out_file}", file=sys.stderr)
print(f"✅ Baseline updated: {BASELINE_FILE}", file=sys.stderr)
