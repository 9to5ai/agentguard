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
standing_risks_from_scan = scan.get("standing_risks", [])
timestamp = datetime.now(timezone.utc).isoformat()

risks = []

# --- Generate risks from scan failures and warnings ---
# Now reads board_impact, risk_likelihood, risk_impact from scan results (sourced from framework YAML)
fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]

seq = 1
for r in fail_warn:
    likelihood = r.get("risk_likelihood", 2)
    impact = r.get("risk_impact", 3)
    inherent = calc_rating(likelihood, impact)
    residual_l = max(1, likelihood - 1)
    residual = calc_rating(residual_l, impact)
    
    risks.append({
        "risk_id": risk_id(r["asi_category"], seq),
        "title": r["check_name"],
        "description": r.get("board_impact", r["detail"]),
        "category": r["asi_category_name"],
        "asi_reference": r["asi_category"],
        "source_check": r["check_id"],
        "inherent_risk": {"likelihood": likelihood, "impact": impact, "rating": inherent[0], "indicator": inherent[1], "score": inherent[2]},
        "controls_present": r["detail"] if r["status"] == "WARN" else "",
        "controls_missing": r.get("remediation", ""),
        "residual_risk": {"likelihood": residual_l, "impact": impact, "rating": residual[0], "indicator": residual[1], "score": residual[2]},
        "board_impact": r.get("board_impact", ""),
        "owner": "Agent Operator",
        "review_date": "",
        "remediation": r.get("remediation", ""),
        "status": "Open",
    })
    seq += 1

# Add standing risks (from framework YAML via scan output)
for sr in standing_risks_from_scan:
    likelihood = sr.get("risk_likelihood", 2)
    impact = sr.get("risk_impact", 3)
    inherent = calc_rating(likelihood, impact)
    residual_l = max(1, likelihood - 1) if sr.get("controls_present") else likelihood
    residual = calc_rating(residual_l, impact)
    
    risks.append({
        "risk_id": risk_id(sr.get("asi_ref", "GEN"), seq),
        "title": sr["title"],
        "description": sr.get("board_impact", ""),
        "category": sr.get("category", "General"),
        "asi_reference": sr.get("asi_ref", ""),
        "source_check": "standing",
        "inherent_risk": {"likelihood": likelihood, "impact": impact, "rating": inherent[0], "indicator": inherent[1], "score": inherent[2]},
        "controls_present": sr.get("controls_present", ""),
        "controls_missing": sr.get("controls_missing", ""),
        "residual_risk": {"likelihood": residual_l, "impact": impact, "rating": residual[0], "indicator": residual[1], "score": residual[2]},
        "board_impact": sr.get("board_impact", ""),
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
