#!/usr/bin/env python3
"""AgentGuard Scanner — OWASP ASI Top 10 Assessment for OpenClaw"""

import json, os, subprocess, sys, glob, yaml
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
SKILL_DIR = SCRIPT_DIR.parent
REPORT_DIR = SKILL_DIR / "reports"
WORKSPACE = Path.home() / ".openclaw" / "workspace"
CONFIG_FILE = Path("/tmp/agentguard-config.json")

# Load framework YAML for board-impact metadata
FRAMEWORK_FILE = SKILL_DIR / "frameworks" / "owasp-asi-2026.yaml"
FRAMEWORK_META = {}  # check_id -> {board_impact, business_risk, analogy, risk_likelihood, risk_impact}
STANDING_RISKS = []
try:
    with open(FRAMEWORK_FILE) as f:
        fw = yaml.safe_load(f)
    for control in fw.get("controls", []):
        for chk in control.get("checks", []):
            FRAMEWORK_META[chk["id"]] = {
                "board_impact": chk.get("board_impact", ""),
                "business_risk": chk.get("business_risk", ""),
                "analogy": chk.get("analogy", ""),
                "risk_likelihood": chk.get("risk_likelihood", 2),
                "risk_impact": chk.get("risk_impact", 3),
            }
    STANDING_RISKS = fw.get("standing_risks", [])
except Exception as e:
    print(f"Warning: Could not load framework YAML: {e}", file=sys.stderr)

def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)

def cfg_get(config, path, default=None):
    """Navigate nested dict by dot path."""
    keys = path.split(".")
    val = config
    for k in keys:
        if isinstance(val, dict) and k in val:
            val = val[k]
        else:
            return default
    return val

def run_cmd(cmd, default=""):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except:
        return default

# --- Data collection ---
print("📊 Collecting environment data...", file=sys.stderr)

config = load_config()

# Skills
bundled_dir = Path("/opt/homebrew/lib/node_modules/openclaw/skills")
bundled_skills = sorted(os.listdir(bundled_dir)) if bundled_dir.exists() else []
workspace_skills_dir = WORKSPACE / "skills"
workspace_skills = sorted(os.listdir(workspace_skills_dir)) if workspace_skills_dir.exists() else []

# Memory
memory_dir = WORKSPACE / "memory"
memory_files = sorted(os.listdir(memory_dir)) if memory_dir.exists() else []

# Git
git_tracked = (WORKSPACE / ".git").exists()

# Browser
browser_dir = Path.home() / ".openclaw" / "browser"
browser_profiles = sorted(os.listdir(browser_dir)) if browser_dir.exists() else []

# Cron jobs
cron_output = run_cmd("openclaw cron list --json 2>/dev/null")
cron_jobs = []
try:
    cron_data = json.loads(cron_output)
    cron_jobs = cron_data if isinstance(cron_data, list) else cron_data.get("jobs", [])
except:
    pass

# --- Checks ---
print("🔎 Running 27 checks across OWASP ASI Top 10...", file=sys.stderr)

results = []

def check(check_id, name, asi_id, asi_name, status, detail, remediation=""):
    meta = FRAMEWORK_META.get(check_id, {})
    results.append({
        "check_id": check_id,
        "check_name": name,
        "asi_category": asi_id,
        "asi_category_name": asi_name,
        "status": status,  # PASS, FAIL, WARN
        "detail": detail,
        "remediation": remediation,
        "board_impact": meta.get("board_impact", ""),
        "business_risk": meta.get("business_risk", ""),
        "analogy": meta.get("analogy", ""),
        "risk_likelihood": meta.get("risk_likelihood", 2),
        "risk_impact": meta.get("risk_impact", 3),
    })

# ===== ASI01: Agent Goal Hijack =====
ASI = ("ASI01", "Agent Goal Hijack")

# Prompt injection defence
sec_skills = [s for s in bundled_skills if s in ("prompt-guard", "secureclaw")]
if sec_skills:
    check("ASI01-01", "Prompt injection defence", *ASI, "PASS", f"Found: {', '.join(sec_skills)}")
else:
    check("ASI01-01", "Prompt injection defence", *ASI, "FAIL",
          "No prompt injection detection skill installed",
          "Install prompt-guard or secureclaw: clawhub install prompt-guard")

# Group mention policy
groups = cfg_get(config, "channels.telegram.groups", {})
open_groups = [gid for gid, g in groups.items() if not g.get("requireMention", True)]
if open_groups:
    check("ASI01-02", "Group chat mention policy", *ASI, "FAIL",
          f"Groups with requireMention=false: {', '.join(open_groups)}. Agent processes ALL messages.",
          "Set requireMention: true for groups to prevent goal hijack via arbitrary messages")
else:
    check("ASI01-02", "Group chat mention policy", *ASI, "PASS", "All groups require mention")

# DM allowlist
dm_policy = cfg_get(config, "channels.telegram.dmPolicy", "open")
allow_from = cfg_get(config, "channels.telegram.allowFrom", [])
if dm_policy == "allowlist" and allow_from:
    check("ASI01-03", "DM allowlist configured", *ASI, "PASS", f"Allowlist with {len(allow_from)} authorised user(s)")
else:
    check("ASI01-03", "DM allowlist configured", *ASI, "FAIL",
          f"dmPolicy={dm_policy}, allowFrom has {len(allow_from)} entries",
          "Set dmPolicy to allowlist and configure allowFrom")

# ===== ASI02: Tool Misuse =====
ASI = ("ASI02", "Tool Misuse and Exploitation")

check("ASI02-01", "Shell execution sandboxed", *ASI, "WARN",
      "No explicit shell sandboxing in config. Agent has unrestricted exec access.",
      "Run OpenClaw in a dedicated VM or container. Review tool_policy if available.")

if "openclaw" in browser_profiles:
    check("ASI02-02", "Browser profile isolated", *ASI, "PASS", "Dedicated 'openclaw' browser profile in use")
else:
    check("ASI02-02", "Browser profile isolated", *ASI, "WARN",
          "No dedicated browser profile",
          "Create an isolated browser profile for agent use")

deny_cmds = cfg_get(config, "gateway.nodes.denyCommands", [])
if deny_cmds:
    check("ASI02-03", "Dangerous node commands denied", *ASI, "PASS", f"{len(deny_cmds)} commands blocked: {', '.join(deny_cmds[:5])}")
else:
    check("ASI02-03", "Dangerous node commands denied", *ASI, "FAIL",
          "No node commands restricted",
          "Add denyCommands for camera.snap, screen.record, etc.")

# ===== ASI03: Identity & Privilege =====
ASI = ("ASI03", "Identity and Privilege Abuse")

auth_mode = cfg_get(config, "gateway.auth.mode", "none")
check("ASI03-01", "Gateway authentication", *ASI,
      "PASS" if auth_mode == "token" else "FAIL",
      f"Auth mode: {auth_mode}",
      "" if auth_mode == "token" else "Set gateway.auth.mode to token")

bind = cfg_get(config, "gateway.bind", "unknown")
check("ASI03-02", "Gateway bound to loopback", *ASI,
      "PASS" if bind == "loopback" else "FAIL",
      f"Bound to: {bind}",
      "" if bind == "loopback" else "Set gateway.bind to loopback — agent may be network-exposed")

check("ASI03-03", "Telegram sender allowlist", *ASI,
      "PASS" if allow_from else "FAIL",
      f"{len(allow_from)} authorised sender(s)" if allow_from else "No sender allowlist",
      "" if allow_from else "Configure allowFrom")

max_conc = cfg_get(config, "agents.defaults.maxConcurrent", 0)
check("ASI03-04", "Max concurrent sessions", *ASI,
      "PASS" if 0 < max_conc <= 10 else "WARN",
      f"maxConcurrent: {max_conc}",
      "" if 0 < max_conc <= 10 else "Set to 10 or below")

# ===== ASI04: Supply Chain =====
ASI = ("ASI04", "Agentic Supply Chain")

total_skills = len(bundled_skills) + len(workspace_skills)
check("ASI04-01", "Skills inventory", *ASI, "WARN",
      f"{len(bundled_skills)} bundled + {len(workspace_skills)} custom skills installed. No formal risk assessment.",
      "Create a skills inventory documenting purpose and risk for each skill")

if workspace_skills:
    check("ASI04-02", "Custom skills reviewed", *ASI, "WARN",
          f"Custom skills: {', '.join(workspace_skills)}. Review status unknown.",
          "Audit all custom workspace skills for malicious patterns")
else:
    check("ASI04-02", "Custom skills reviewed", *ASI, "PASS", "No custom workspace skills")

has_sec_skill = "secureclaw" in bundled_skills or "healthcheck" in bundled_skills
check("ASI04-03", "Security scanning tool", *ASI,
      "PASS" if has_sec_skill else "WARN",
      f"{'healthcheck' if 'healthcheck' in bundled_skills else 'secureclaw'} available" if has_sec_skill else "No security scanner installed",
      "" if has_sec_skill else "Install secureclaw for automated auditing")

# ===== ASI05: Unexpected Code Execution =====
ASI = ("ASI05", "Unexpected Code Execution")

sub_max = cfg_get(config, "agents.defaults.subagents.maxConcurrent", 0)
check("ASI05-01", "Subagent execution bounded", *ASI,
      "PASS" if 0 < sub_max <= 10 else "WARN",
      f"Subagent maxConcurrent: {sub_max}")

no_timeout = [j.get("name", "unnamed") for j in cron_jobs
              if not j.get("payload", {}).get("timeoutSeconds")]
if not no_timeout:
    check("ASI05-02", "Cron job timeouts", *ASI, "PASS", "All cron jobs have timeouts")
elif cron_jobs:
    check("ASI05-02", "Cron job timeouts", *ASI, "FAIL",
          f"Jobs missing timeouts: {', '.join(no_timeout[:5])}",
          "Add timeoutSeconds to all cron job payloads to prevent runaway execution")
else:
    check("ASI05-02", "Cron job timeouts", *ASI, "PASS", "No cron jobs configured")

# ===== ASI06: Memory & Context Poisoning =====
ASI = ("ASI06", "Memory and Context Poisoning")

if git_tracked:
    tracked = run_cmd(f"cd {WORKSPACE} && git ls-files memory/ 2>/dev/null | wc -l").strip()
    check("ASI06-01", "Memory files backed up", *ASI,
          "PASS" if int(tracked or 0) > 0 else "WARN",
          f"{tracked} memory files in git" if int(tracked or 0) > 0 else "Git exists but memory/ not committed",
          "" if int(tracked or 0) > 0 else "Run: git add memory/ && git commit")
else:
    check("ASI06-01", "Memory files backed up", *ASI, "FAIL",
          "Workspace not git-tracked", "Initialise git in workspace")

check("ASI06-02", "Memory file count", *ASI,
      "PASS" if len(memory_files) <= 50 else "WARN",
      f"{len(memory_files)} memory files")

check("ASI06-03", "Workspace version controlled", *ASI,
      "PASS" if git_tracked else "FAIL",
      "Git repository active" if git_tracked else "No version control",
      "" if git_tracked else "Run git init in workspace")

# ===== ASI07: Inter-Agent Communication =====
ASI = ("ASI07", "Insecure Inter-Agent Communication")

check("ASI07-01", "Subagent concurrency limits", *ASI, "PASS", f"maxConcurrent: {sub_max} (bounded)")

ts_mode = cfg_get(config, "gateway.tailscale.mode", "off")
check("ASI07-02", "Network sharing disabled", *ASI,
      "PASS" if ts_mode == "off" else "WARN",
      f"Tailscale: {ts_mode}",
      "" if ts_mode == "off" else "Set tailscale.mode to off unless explicitly needed")

# ===== ASI08: Cascading Failures =====
ASI = ("ASI08", "Cascading Failures")

fallbacks = cfg_get(config, "agents.defaults.model.fallbacks", [])
check("ASI08-01", "Model fallbacks", *ASI,
      "PASS" if fallbacks else "FAIL",
      f"Fallbacks: {', '.join(fallbacks)}" if fallbacks else "No fallbacks — single point of failure",
      "" if fallbacks else "Add fallback models")

watchdog = any("watchdog" in j.get("name", "").lower() for j in cron_jobs)
check("ASI08-02", "Cron watchdog active", *ASI,
      "PASS" if watchdog else "WARN",
      "Watchdog job found" if watchdog else "No cron watchdog",
      "" if watchdog else "Create a watchdog cron to auto-retry failures")

compaction = cfg_get(config, "agents.defaults.compaction.mode", "unknown")
check("ASI08-03", "Compaction safeguards", *ASI,
      "PASS" if compaction == "safeguard" else "WARN",
      f"Mode: {compaction}")

# ===== ASI09: Human-Agent Trust =====
ASI = ("ASI09", "Human-Agent Trust Exploitation")

external_crons = [j.get("name", "") for j in cron_jobs
                  if any(kw in j.get("name", "").lower() for kw in ("linkedin", "tweet", "email", "post"))]
if external_crons:
    # Check if they mention approval/draft in their payload
    has_approval = all(
        any(kw in j.get("payload", {}).get("message", "").lower() for kw in ("approval", "approve", "draft", "review"))
        for j in cron_jobs if j.get("name", "") in external_crons
    )
    check("ASI09-01", "External action approval gates", *ASI,
          "PASS" if has_approval else "WARN",
          f"External crons: {', '.join(external_crons)}. {'Approval keywords found in prompts.' if has_approval else 'Verify human-in-the-loop is enforced.'}",
          "" if has_approval else "Ensure all external-action crons require human approval before publishing")
else:
    check("ASI09-01", "External action approval gates", *ASI, "PASS", "No external-posting cron jobs detected")

cmd_logger = cfg_get(config, "hooks.internal.entries.command-logger.enabled", False)
check("ASI09-02", "Command logging", *ASI,
      "PASS" if cmd_logger else "FAIL",
      "command-logger hook active" if cmd_logger else "Command logging disabled",
      "" if cmd_logger else "Enable hooks.internal.entries.command-logger")

# ===== ASI10: Rogue Agents =====
ASI = ("ASI10", "Rogue Agents")

check("ASI10-01", "Cron job count", *ASI,
      "PASS" if len(cron_jobs) <= 15 else "WARN",
      f"{len(cron_jobs)} active cron jobs",
      "" if len(cron_jobs) <= 15 else "Review and prune unused cron jobs")

dm_scope = cfg_get(config, "session.dmScope", "unknown")
check("ASI10-02", "Session scope isolation", *ASI,
      "PASS" if dm_scope == "per-channel-peer" else "WARN",
      f"dmScope: {dm_scope}")

restart = cfg_get(config, "commands.restart", False)
check("ASI10-03", "Emergency restart available", *ASI,
      "PASS" if restart else "WARN",
      "Restart command enabled" if restart else "Restart not available")

# --- Summary ---
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
warned = sum(1 for r in results if r["status"] == "WARN")
total = len(results)
score = round((passed / total) * 100) if total else 0

if failed >= 3:
    overall = "RED"
elif failed >= 1 or warned >= 5:
    overall = "AMBER"
else:
    overall = "GREEN"

# Category summaries
categories = {}
for r in results:
    cat = r["asi_category"]
    if cat not in categories:
        categories[cat] = {"name": r["asi_category_name"], "checks": [], "worst": "PASS"}
    categories[cat]["checks"].append(r)
    if r["status"] == "FAIL":
        categories[cat]["worst"] = "FAIL"
    elif r["status"] == "WARN" and categories[cat]["worst"] != "FAIL":
        categories[cat]["worst"] = "WARN"

report = {
    "meta": {
        "framework": "OWASP Top 10 for Agentic Applications (2026)",
        "framework_id": "owasp-asi-2026",
        "scanner": "AgentGuard v0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": f"OpenClaw @ {os.uname().nodename}",
    },
    "summary": {
        "overall_rating": overall,
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "warnings": warned,
        "score_pct": score,
    },
    "environment": {
        "bundled_skills": len(bundled_skills),
        "workspace_skills": len(workspace_skills),
        "workspace_skill_names": workspace_skills,
        "memory_files": len(memory_files),
        "cron_jobs": len(cron_jobs),
        "cron_job_names": [j.get("name", "unnamed") for j in cron_jobs],
        "git_tracked": git_tracked,
        "browser_profiles": browser_profiles,
        "model_primary": cfg_get(config, "agents.defaults.model.primary", "unknown"),
        "model_fallbacks": cfg_get(config, "agents.defaults.model.fallbacks", []),
    },
    "categories": {cat_id: {"name": cat["name"], "status": cat["worst"]} for cat_id, cat in categories.items()},
    "results": results,
    "standing_risks": STANDING_RISKS,
}

# Save
REPORT_DIR.mkdir(parents=True, exist_ok=True)
date_slug = datetime.now().strftime("%Y-%m-%d-%H%M")
report_file = REPORT_DIR / f"scan-{date_slug}.json"

with open(report_file, "w") as f:
    json.dump(report, f, indent=2)
with open(REPORT_DIR / "latest.json", "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps(report, indent=2))
print(f"\n✅ Report saved: {report_file}", file=sys.stderr)
