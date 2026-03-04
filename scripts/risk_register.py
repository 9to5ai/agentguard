#!/usr/bin/env python3
"""AgentGuard Module 2: Auto-generated Risk Register"""

import json, os, sys, hashlib
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).parent.parent
REPORT_DIR = SKILL_DIR / "reports"
WORKSPACE = Path.home() / ".openclaw" / "workspace"

def load_scan():
    latest = REPORT_DIR / "latest.json"
    if latest.exists():
        with open(latest) as f:
            return json.load(f)
    print("ERROR: No scan report found. Run scan.sh first.", file=sys.stderr)
    sys.exit(1)

def risk_id(cat, seq):
    return f"RISK-{cat}-{seq:02d}"

def calc_rating(likelihood, impact):
    """5x5 matrix: 1=Very Low, 5=Very High. Score = L×I"""
    score = likelihood * impact
    if score >= 15: return ("Critical", "🔴", score)
    if score >= 10: return ("High", "🟠", score)
    if score >= 5:  return ("Medium", "🟡", score)
    return ("Low", "🟢", score)

scan = load_scan()
env = scan["environment"]
results = scan["results"]
timestamp = datetime.now(timezone.utc).isoformat()

risks = []

# --- Generate risks from scan failures and warnings ---
fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]

# Map each finding to a proper risk entry
risk_templates = {
    "ASI01-01": {
        "title": "Prompt Injection Attack",
        "description": "Agent has no prompt injection detection capability. Malicious content in messages, web pages, or documents could hijack agent behaviour, exfiltrate data, or trigger unintended actions.",
        "category": "Agent Goal Hijack",
        "likelihood": 4, "impact": 5,
        "controls_present": "DM allowlist limits who can message agent directly",
        "controls_missing": "No runtime prompt injection scanning",
    },
    "ASI01-02": {
        "title": "Goal Hijack via Group Messages",
        "description": "Agent processes all messages in group chat without requiring @mention. Any group member could inject malicious instructions or manipulate agent behaviour through crafted messages.",
        "category": "Agent Goal Hijack",
        "likelihood": 3, "impact": 4,
        "controls_present": "Group limited to known members",
        "controls_missing": "requireMention not enforced",
    },
    "ASI02-01": {
        "title": "Unrestricted Shell Execution",
        "description": "Agent can execute arbitrary shell commands without sandboxing. A compromised prompt or malicious skill could run destructive commands, install malware, or exfiltrate credentials.",
        "category": "Tool Misuse",
        "likelihood": 2, "impact": 5,
        "controls_present": "Running in dedicated VM (isolation at hypervisor level)",
        "controls_missing": "No shell-level sandboxing or command allowlist",
    },
    "ASI04-01": {
        "title": "Unvetted Skill Supply Chain",
        "description": f"{env['bundled_skills']} bundled and {env['workspace_skills']} custom skills installed without formal security review or risk assessment. Malicious skills could steal credentials, modify memory, or establish persistence.",
        "category": "Supply Chain",
        "likelihood": 3, "impact": 4,
        "controls_present": "Skills from official ClawHub registry",
        "controls_missing": "No skills inventory, no per-skill risk assessment, no version pinning",
    },
    "ASI04-02": {
        "title": "Custom Skills Not Audited",
        "description": f"Custom workspace skills ({', '.join(env['workspace_skill_names'])}) have not been formally reviewed for security vulnerabilities or malicious patterns.",
        "category": "Supply Chain",
        "likelihood": 2, "impact": 4,
        "controls_present": "Skills authored by operator",
        "controls_missing": "No formal review or audit process",
    },
    "ASI05-02": {
        "title": "Unbounded Cron Execution",
        "description": "One or more cron jobs lack timeout configuration, allowing potentially infinite execution consuming resources and API credits.",
        "category": "Code Execution",
        "likelihood": 3, "impact": 3,
        "controls_present": "Cron watchdog monitors for failures",
        "controls_missing": "Missing timeoutSeconds on some jobs",
    },
}

# Additional standing risks (always present for any OpenClaw deployment)
standing_risks = [
    {
        "title": "Credential Exposure via Memory Files",
        "description": f"Agent maintains {env['memory_files']} persistent memory files that may accumulate sensitive information (API keys, personal data, credentials) over time. Memory files are accessible to the agent and backed up to git/cloud.",
        "category": "Data Protection",
        "likelihood": 3, "impact": 4,
        "controls_present": "Git-tracked for integrity, automated backups",
        "controls_missing": "No automated PII/credential scanning of memory files",
        "asi_ref": "ASI06",
    },
    {
        "title": "Browser Session Hijack",
        "description": "Agent maintains active browser sessions with authenticated access to services (LinkedIn, Gmail, etc). Compromised agent could access all authenticated sessions.",
        "category": "Identity & Access",
        "likelihood": 2, "impact": 5,
        "controls_present": "Isolated browser profile, VM separation",
        "controls_missing": "No session rotation policy, no access logging per browser action",
        "asi_ref": "ASI03",
    },
    {
        "title": "Autonomous External Actions",
        "description": f"Agent has {env['cron_jobs']} cron jobs running autonomously, including jobs that post to LinkedIn and send messages. Drift in prompt interpretation or model behaviour could result in unintended public communications.",
        "category": "Human Oversight",
        "likelihood": 2, "impact": 4,
        "controls_present": "LinkedIn crons use approval gates, drafts sent for review",
        "controls_missing": "No automated content policy checks before posting",
        "asi_ref": "ASI09",
    },
    {
        "title": "Model Provider Dependency",
        "description": f"Primary model: {env['model_primary']}. Agent operations depend on external API availability. Provider outage, policy change, or account suspension would halt all agent functions.",
        "category": "Operational Resilience",
        "likelihood": 3, "impact": 3,
        "controls_present": f"Fallback models configured: {', '.join(env['model_fallbacks'])}",
        "controls_missing": "No local model fallback, no SLA monitoring",
        "asi_ref": "ASI08",
    },
    {
        "title": "Shadow AI Governance Gap",
        "description": "OpenClaw deployment operates outside traditional IT governance. No formal change management, no approval process for new skills or cron jobs, no periodic governance review scheduled.",
        "category": "Governance",
        "likelihood": 4, "impact": 3,
        "controls_present": "Git-tracked workspace, command logging enabled",
        "controls_missing": "No change approval workflow, no governance review schedule, no formal owner assignment",
        "asi_ref": "ASI10",
    },
]

# Build risk register entries from scan findings
seq = 1
for r in fail_warn:
    tmpl = risk_templates.get(r["check_id"])
    if not tmpl:
        continue
    
    inherent = calc_rating(tmpl["likelihood"], tmpl["impact"])
    # Residual = reduced by existing controls (rough: -1 likelihood if controls present)
    residual_l = max(1, tmpl["likelihood"] - 1) if tmpl["controls_present"] else tmpl["likelihood"]
    residual = calc_rating(residual_l, tmpl["impact"])
    
    risks.append({
        "risk_id": risk_id(r["asi_category"], seq),
        "title": tmpl["title"],
        "description": tmpl["description"],
        "category": tmpl["category"],
        "asi_reference": r["asi_category"],
        "source_check": r["check_id"],
        "inherent_risk": {"likelihood": tmpl["likelihood"], "impact": tmpl["impact"], "rating": inherent[0], "indicator": inherent[1], "score": inherent[2]},
        "controls_present": tmpl["controls_present"],
        "controls_missing": tmpl["controls_missing"],
        "residual_risk": {"likelihood": residual_l, "impact": tmpl["impact"], "rating": residual[0], "indicator": residual[1], "score": residual[2]},
        "owner": "Agent Operator",
        "review_date": "",
        "remediation": r.get("remediation", ""),
        "status": "Open",
    })
    seq += 1

# Add standing risks
for sr in standing_risks:
    inherent = calc_rating(sr["likelihood"], sr["impact"])
    residual_l = max(1, sr["likelihood"] - 1) if sr["controls_present"] else sr["likelihood"]
    residual = calc_rating(residual_l, sr["impact"])
    
    risks.append({
        "risk_id": risk_id(sr["asi_ref"], seq),
        "title": sr["title"],
        "description": sr["description"],
        "category": sr["category"],
        "asi_reference": sr["asi_ref"],
        "source_check": "standing",
        "inherent_risk": {"likelihood": sr["likelihood"], "impact": sr["impact"], "rating": inherent[0], "indicator": inherent[1], "score": inherent[2]},
        "controls_present": sr["controls_present"],
        "controls_missing": sr["controls_missing"],
        "residual_risk": {"likelihood": residual_l, "impact": sr["impact"], "rating": residual[0], "indicator": residual[1], "score": residual[2]},
        "owner": "Agent Operator",
        "review_date": "",
        "remediation": "",
        "status": "Open",
    })
    seq += 1

# Sort by residual risk score descending
risks.sort(key=lambda r: r["residual_risk"]["score"], reverse=True)

register = {
    "meta": {
        "title": "AI Agent Risk Register",
        "generated_by": "AgentGuard v0.1.0",
        "timestamp": timestamp,
        "target": scan["meta"]["target"],
        "based_on_scan": scan["meta"]["timestamp"],
    },
    "summary": {
        "total_risks": len(risks),
        "critical": sum(1 for r in risks if r["residual_risk"]["rating"] == "Critical"),
        "high": sum(1 for r in risks if r["residual_risk"]["rating"] == "High"),
        "medium": sum(1 for r in risks if r["residual_risk"]["rating"] == "Medium"),
        "low": sum(1 for r in risks if r["residual_risk"]["rating"] == "Low"),
    },
    "risks": risks,
}

# Save
out_file = REPORT_DIR / "risk-register.json"
with open(out_file, "w") as f:
    json.dump(register, f, indent=2)

print(json.dumps(register, indent=2))
print(f"\n✅ Risk register saved: {out_file}", file=sys.stderr)
