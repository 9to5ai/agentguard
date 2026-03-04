#!/usr/bin/env python3
"""AgentGuard Module 5: Board Report Generator
Produces a polished HTML governance report from scan + risk register + audit data."""

import json, os, sys
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).parent.parent
REPORT_DIR = SKILL_DIR / "reports"

def load_json(name):
    f = REPORT_DIR / name
    if f.exists():
        with open(f) as fh:
            return json.load(fh)
    return None

scan = load_json("latest.json")
risks = load_json("risk-register.json")
audit = load_json("audit-trail.json")
monitor = load_json("monitor.json")

if not scan:
    print("ERROR: No scan report. Run scan.sh first.", file=sys.stderr)
    sys.exit(1)

ts = datetime.now(timezone.utc)
date_str = ts.strftime("%d %B %Y")

# --- Helpers ---
def rag_color(status):
    return {"PASS": "#22c55e", "FAIL": "#ef4444", "WARN": "#f59e0b", "GREEN": "#22c55e", "AMBER": "#f59e0b", "RED": "#ef4444"}.get(status, "#6b7280")

def rag_bg(status):
    return {"PASS": "#052e16", "FAIL": "#450a0a", "WARN": "#451a03", "GREEN": "#052e16", "AMBER": "#451a03", "RED": "#450a0a"}.get(status, "#1a1a2e")

def rag_label(status):
    return {"PASS": "🟢 PASS", "FAIL": "🔴 FAIL", "WARN": "🟡 WARN", "GREEN": "🟢 GREEN", "AMBER": "🟡 AMBER", "RED": "🔴 RED"}.get(status, status)

overall = scan["summary"]["overall_rating"]
score = scan["summary"]["score_pct"]

# Board-friendly impact translations
BOARD_IMPACT = {
    "ASI01-01": {
        "so_what": "The AI agent cannot detect when someone is trying to manipulate it. An attacker could embed hidden instructions in a document, email, or web page that cause the agent to leak confidential data, send unauthorised messages, or take actions on behalf of the organisation without anyone realising.",
        "business_risk": "Data breach, reputational damage, regulatory sanction",
        "analogy": "Like having an employee who follows any instruction from anyone, including strangers, without questioning it.",
    },
    "ASI01-02": {
        "so_what": "The agent reads and responds to every message in the group chat, not just ones directed at it. Any member of the group — or anyone who gains access to it — could give the agent instructions, potentially triggering actions like accessing files, browsing websites, or sending messages on behalf of the organisation.",
        "business_risk": "Unauthorised access, social engineering vector, loss of control",
        "analogy": "Like giving every person in an open-plan office the authority to instruct your PA, not just you.",
    },
    "ASI02-01": {
        "so_what": "The agent can run any system command on the machine it's hosted on — install software, read files, make network connections. While it runs in a virtual machine (limiting blast radius), there are no restrictions on what commands it can execute within that environment.",
        "business_risk": "System compromise, credential theft, lateral movement if VM is breached",
        "analogy": "Like giving an employee admin access to a company laptop with no usage monitoring or restricted applications.",
    },
    "ASI04-01": {
        "so_what": "The agent has 56 software extensions ('skills') installed, but there is no formal register of what each one does, who built it, or what access it has. Any one of these could contain vulnerabilities or malicious code that the agent would execute with full privileges.",
        "business_risk": "Supply chain compromise, shadow functionality, unvetted third-party code running with full access",
        "analogy": "Like installing 56 browser extensions on a corporate machine without IT approval or review.",
    },
    "ASI04-02": {
        "so_what": "Four custom-built extensions are running that have not been through a formal security review. While they were created by the operator, there is no documented audit trail confirming they are free from vulnerabilities or unintended behaviours.",
        "business_risk": "Unaudited code with full agent privileges",
        "analogy": "Like running homemade scripts on production systems without peer review.",
    },
    "ASI05-02": {
        "so_what": "At least one scheduled task has no time limit. If it malfunctions, it could run indefinitely — consuming API credits, generating unintended outputs, or holding system resources hostage. There is no automatic kill switch.",
        "business_risk": "Runaway costs, resource exhaustion, uncontrolled autonomous behaviour",
        "analogy": "Like approving a standing order with no expiry date and no spending cap.",
    },
}

RISK_BOARD_IMPACT = {
    "Prompt Injection Attack": "An attacker could take control of the agent's behaviour by hiding instructions in everyday content the agent processes — emails, documents, web pages. The agent would follow these instructions believing them to be legitimate, potentially leaking confidential information or taking unauthorised actions.",
    "Goal Hijack via Group Messages": "Anyone in the group chat can give the agent instructions. This means the agent's behaviour is only as trustworthy as the least trustworthy person in the group.",
    "Unrestricted Shell Execution": "The agent can run any command on its host machine. While VM isolation limits the damage, a sophisticated attack could use this to access credentials, install persistent backdoors, or pivot to other systems.",
    "Unvetted Skill Supply Chain": "The agent relies on 56 third-party extensions with no formal vetting process. This is the AI equivalent of a supply chain attack — one compromised extension gives an attacker full access.",
    "Custom Skills Not Audited": "Internally-built extensions have no audit trail. If something goes wrong, there is no documented review to fall back on for accountability.",
    "Unbounded Cron Execution": "A scheduled task without a timeout is a financial and operational risk. It could silently consume resources or generate unintended outputs for hours before anyone notices.",
    "Credential Exposure via Memory Files": "The agent accumulates information over time in persistent files. These files may contain sensitive data — API keys, personal information, business intelligence — that could be exposed if the agent is compromised.",
    "Browser Session Hijack": "The agent maintains logged-in sessions to services like LinkedIn and email. If the agent is compromised, the attacker inherits all of those active sessions — no passwords needed.",
    "Autonomous External Actions": "The agent publishes content to LinkedIn and sends messages on scheduled timers. A subtle drift in behaviour could result in inappropriate or damaging communications going out under the organisation's name.",
    "Model Provider Dependency": "All agent operations depend on a single external AI provider. If that provider has an outage, changes its policies, or suspends the account, every automated function stops immediately.",
    "Shadow AI Governance Gap": "This AI agent operates outside the organisation's normal IT governance. There is no change management process, no approval workflow for new capabilities, and no scheduled governance review. It is, in effect, shadow AI with significant access.",
}

# --- Build HTML ---
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentGuard Governance Report — {date_str}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0f0f1a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 24px; }}
  h1 {{ font-size: 28px; color: #fff; margin-bottom: 4px; }}
  h2 {{ font-size: 20px; color: #d4a02e; margin: 32px 0 16px; border-bottom: 1px solid #2a2a45; padding-bottom: 8px; }}
  h3 {{ font-size: 16px; color: #fff; margin: 16px 0 8px; }}
  .subtitle {{ color: #888; font-size: 14px; margin-bottom: 24px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: 600; font-size: 13px; }}
  .card {{ background: #1a1a2e; border-radius: 8px; padding: 20px; margin: 12px 0; border: 1px solid #2a2a45; }}
  .hero {{ background: {rag_bg(overall)}; border: 2px solid {rag_color(overall)}; text-align: center; padding: 32px; border-radius: 12px; margin: 24px 0; }}
  .hero .rating {{ font-size: 48px; font-weight: 700; color: {rag_color(overall)}; }}
  .hero .score {{ font-size: 24px; color: #ccc; margin-top: 4px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
  .stat {{ background: #1a1a2e; border-radius: 8px; padding: 16px; text-align: center; border: 1px solid #2a2a45; }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .label {{ font-size: 12px; color: #888; margin-top: 4px; }}
  .pass {{ color: #22c55e; }}
  .fail {{ color: #ef4444; }}
  .warn {{ color: #f59e0b; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th {{ text-align: left; padding: 10px 12px; background: #1a1a2e; color: #d4a02e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #2a2a45; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1f1f35; font-size: 13px; }}
  tr:hover {{ background: #1a1a2e; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }}
  .tag-pass {{ background: #052e16; color: #22c55e; }}
  .tag-fail {{ background: #450a0a; color: #ef4444; }}
  .tag-warn {{ background: #451a03; color: #f59e0b; }}
  .tag-critical {{ background: #450a0a; color: #ef4444; }}
  .tag-high {{ background: #451a03; color: #f59e0b; }}
  .tag-medium {{ background: #1a1a2e; color: #f59e0b; }}
  .tag-low {{ background: #052e16; color: #22c55e; }}
  .footer {{ margin-top: 48px; padding-top: 24px; border-top: 1px solid #2a2a45; color: #555; font-size: 12px; text-align: center; }}
  .finding {{ margin: 8px 0; padding: 12px 16px; border-left: 3px solid; border-radius: 0 4px 4px 0; }}
  .finding-fail {{ border-color: #ef4444; background: #1a0a0a; }}
  .finding-warn {{ border-color: #f59e0b; background: #1a1508; }}
  .env-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
  .env-item {{ background: #1a1a2e; padding: 12px; border-radius: 6px; }}
  .env-item .val {{ font-size: 20px; font-weight: 600; color: #fff; }}
  .env-item .lbl {{ font-size: 11px; color: #888; }}
</style>
</head>
<body>
<div class="container">

<h1>🛡️ AI Agent Governance Report</h1>
<p class="subtitle">Generated by AgentGuard v0.1.0 · {date_str} · {scan['meta']['target']}</p>

<!-- Hero -->
<div class="hero">
  <div class="rating">{rag_label(overall)}</div>
  <div class="score">{score}% compliance score · {scan['summary']['total_checks']} checks</div>
</div>

<!-- Summary stats -->
<div class="stats">
  <div class="stat"><div class="num pass">{scan['summary']['passed']}</div><div class="label">Passed</div></div>
  <div class="stat"><div class="num fail">{scan['summary']['failed']}</div><div class="label">Failed</div></div>
  <div class="stat"><div class="num warn">{scan['summary']['warnings']}</div><div class="label">Warnings</div></div>
  <div class="stat"><div class="num" style="color:#fff">{score}%</div><div class="label">Score</div></div>
</div>

<h2>Executive Summary</h2>
<div class="card">
  <p>This report assesses the governance posture of an OpenClaw AI agent deployment against the <strong>OWASP Top 10 for Agentic Applications (2026)</strong> framework. The assessment covers {scan['summary']['total_checks']} automated controls across 10 risk categories.</p>
  <br>
  <p><strong>Key findings:</strong></p>
  <ul style="margin: 8px 0 0 20px;">
"""

# Add key findings from failures
failures = [r for r in scan["results"] if r["status"] == "FAIL"]
warnings = [r for r in scan["results"] if r["status"] == "WARN"]

for f in failures:
    html += f'    <li style="color:#ef4444;margin:4px 0"><strong>{f["check_name"]}</strong> — {f["detail"]}</li>\n'
for w in warnings[:3]:
    html += f'    <li style="color:#f59e0b;margin:4px 0"><strong>{w["check_name"]}</strong> — {w["detail"]}</li>\n'

html += """  </ul>
</div>

<h2>OWASP ASI Top 10 — Category Scorecard</h2>
<table>
  <tr><th>Category</th><th>Status</th><th>Details</th></tr>
"""

for cat_id, cat in scan["categories"].items():
    tag_class = f"tag-{cat['status'].lower()}"
    cat_checks = [r for r in scan["results"] if r["asi_category"] == cat_id]
    passed = sum(1 for c in cat_checks if c["status"] == "PASS")
    total = len(cat_checks)
    html += f'  <tr><td><strong>{cat_id}: {cat["name"]}</strong></td><td><span class="tag {tag_class}">{cat["status"]}</span></td><td>{passed}/{total} checks passed</td></tr>\n'

html += "</table>\n"

# Detailed findings
def render_finding(r, color, bg_color, accent):
    impact = BOARD_IMPACT.get(r["check_id"], {})
    so_what = impact.get("so_what", "")
    biz_risk = impact.get("business_risk", "")
    analogy = impact.get("analogy", "")
    icon = "🔴" if color == "fail" else "🟡"
    accent_hex = "#ef4444" if color == "fail" else "#f59e0b"
    block = '<div class="finding finding-{color}">'.format(color=color)
    block += '<strong>{icon} {cid}: {name}</strong><br>'.format(icon=icon, cid=r["check_id"], name=r["check_name"])
    block += '<span style="color:#ccc;font-size:13px">{detail}</span>'.format(detail=r["detail"])
    if so_what:
        block += '<div style="margin:10px 0;padding:12px;background:{bg};border-radius:6px">'.format(bg=bg_color)
        block += '<div style="color:#e0e0e0;font-size:13px;line-height:1.5"><strong style="color:{c}">What this means:</strong> {sw}</div>'.format(c=accent_hex, sw=so_what)
        if biz_risk:
            block += '<div style="color:#f59e0b;font-size:12px;margin-top:6px"><strong>Business risk:</strong> {br}</div>'.format(br=biz_risk)
        if analogy:
            block += '<div style="color:#888;font-size:12px;margin-top:4px;font-style:italic">In plain terms: {a}</div>'.format(a=analogy)
        block += '</div>'
    block += '<div style="margin-top:8px;padding:8px 12px;background:#0a1a0a;border-radius:4px;border-left:2px solid #22c55e">'
    block += '<span style="color:#22c55e;font-size:12px"><strong>Recommended action:</strong> {rem}</span>'.format(rem=r["remediation"])
    block += '</div></div>'
    return block

html += "<h2>Findings Requiring Action</h2>\n"
for r in scan["results"]:
    if r["status"] == "FAIL":
        html += render_finding(r, "fail", "#1a1020", "#ef4444")
for r in scan["results"]:
    if r["status"] == "WARN":
        html += render_finding(r, "warn", "#1a1508", "#f59e0b")

# Risk Register section
if risks:
    html += "<h2>Risk Register</h2>\n"
    rs = risks["summary"]
    html += f'<p style="color:#888;margin-bottom:12px">{rs["total_risks"]} identified risks — {rs["critical"]} Critical, {rs["high"]} High, {rs["medium"]} Medium, {rs["low"]} Low</p>\n'
    html += "<table>\n<tr><th>ID</th><th>Risk</th><th>Inherent</th><th>Residual</th><th>Board Impact</th></tr>\n"
    for r in risks["risks"]:
        ir = r["inherent_risk"]
        rr = r["residual_risk"]
        tag_class = f"tag-{rr['rating'].lower()}"
        board_impact = RISK_BOARD_IMPACT.get(r["title"], r["controls_missing"])
        # Truncate for table, show first sentence
        short_impact = board_impact.split(". ")[0] + "." if ". " in board_impact else board_impact
        html += f'<tr><td>{r["risk_id"]}</td><td><strong>{r["title"]}</strong></td>'
        html += f'<td>{ir["indicator"]} {ir["rating"]} ({ir["score"]})</td>'
        html += f'<td><span class="tag {tag_class}">{rr["rating"]} ({rr["score"]})</span></td>'
        html += f'<td style="font-size:12px;color:#ccc">{short_impact}</td></tr>\n'
    html += "</table>\n"

# Environment
html += "<h2>Environment Overview</h2>\n<div class='env-grid'>\n"
env = scan["environment"]
env_items = [
    (str(env["bundled_skills"]) + "+" + str(env["workspace_skills"]), "Skills Installed"),
    (str(env["cron_jobs"]), "Cron Jobs"),
    (str(env["memory_files"]), "Memory Files"),
    (env["model_primary"].split("/")[-1], "Primary Model"),
    (", ".join(env["browser_profiles"]), "Browser Profiles"),
    ("✓" if env["git_tracked"] else "✗", "Git Tracked"),
]
for val, lbl in env_items:
    html += f'<div class="env-item"><div class="val">{val}</div><div class="lbl">{lbl}</div></div>\n'
html += "</div>\n"

# Cron job inventory
if audit and "cron_activity" in audit.get("sections", {}):
    crons = audit["sections"]["cron_activity"]["jobs"]
    html += "<h2>Autonomous Job Inventory</h2>\n"
    html += "<table><tr><th>Job</th><th>Schedule</th><th>Model</th><th>Timeout</th><th>Last Status</th><th>Delivery</th></tr>\n"
    for j in crons:
        sched = j.get("schedule", {})
        sched_str = sched.get("expr", f"every {sched.get('everyMs', 0)//60000}m") if sched else ""
        timeout_str = f"{j['timeout_seconds']}s" if j.get("timeout_seconds") else "<span style='color:#ef4444'>NONE</span>"
        status_color = "#22c55e" if j["last_status"] == "ok" else "#ef4444"
        html += f'<tr><td>{j["name"]}</td><td><code>{sched_str}</code></td><td style="font-size:11px">{j.get("model","default")}</td>'
        html += f'<td>{timeout_str}</td><td style="color:{status_color}">{j["last_status"]}</td><td>{j["delivery_mode"]}</td></tr>\n'
    html += "</table>\n"

# Footer
html += f"""
<div class="footer">
  <p>AgentGuard v0.1.0 · Framework: OWASP Top 10 for Agentic Applications (2026)</p>
  <p>Report generated {ts.strftime('%Y-%m-%d %H:%M UTC')} · This report is auto-generated and should be reviewed by a qualified risk professional.</p>
</div>

</div>
</body>
</html>"""

# Save
out_file = REPORT_DIR / f"board-report-{ts.strftime('%Y-%m-%d')}.html"
with open(out_file, "w") as f:
    f.write(html)

# Also save as latest
with open(REPORT_DIR / "board-report-latest.html", "w") as f:
    f.write(html)

print(f"✅ Board report generated: {out_file}", file=sys.stderr)
print(str(out_file))
