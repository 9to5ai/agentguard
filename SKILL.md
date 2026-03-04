---
name: agentguard
description: AI agent governance and security assessment tool. Scans OpenClaw deployments against OWASP Top 10 for Agentic Applications (2026), auto-generates risk registers, packages audit trails, monitors for configuration drift, and produces board-ready HTML governance reports with plain-English business impact analysis. Use when asked for a security audit, governance scan, compliance check, risk assessment, board report, or agent security status.
---

# AgentGuard — AI Agent Governance Skill

Automated governance assessment for OpenClaw deployments.

## Commands

### Full Governance Scan
When asked for a governance scan, security audit, or compliance check:

```bash
bash <skill_dir>/scripts/scan.sh
```

Read the output JSON and present a formatted scorecard. The scan checks 28 controls across the OWASP ASI Top 10 categories and outputs a RAG-rated report.

### Risk Register
Generate an auto-populated risk register from the latest scan:

```bash
python3 <skill_dir>/scripts/risk_register.py
```

Maps each finding to inherent/residual risk ratings with controls gap analysis.

### Audit Trail
Package current agent state into an audit-ready format:

```bash
python3 <skill_dir>/scripts/audit_trail.py
```

Captures: config snapshot (redacted), git history, cron activity, skills inventory, memory files, browser profiles, environment metadata. Also exports cron activity as CSV.

### Continuous Monitor
Check for drift since the last baseline:

```bash
python3 <skill_dir>/scripts/monitor.py
```

First run establishes a baseline. Subsequent runs detect: config changes, new skills, new cron jobs, memory growth, version changes, score degradation. Set up as a weekly cron for automated monitoring.

### Board Report
Generate a polished HTML governance report:

```bash
python3 <skill_dir>/scripts/report.py
```

Produces a dark-themed HTML report with: executive summary, OWASP category scorecard, findings with plain-English "what this means" for board members, risk register, environment overview, and cron job inventory. Reports saved to `<skill_dir>/reports/`.

### Quick Status
For a quick "how's my governance?" check, run the scan and summarise the overall RAG rating and top 3 issues in one message.

## Frameworks
Modular YAML files in `<skill_dir>/frameworks/`:
- `owasp-asi-2026.yaml` — OWASP Agentic Security Initiative Top 10 (28 checks)
- More frameworks coming: APRA CPS 234, CPS 230, NIST AI RMF, ISO 42001

## Notes
- Everything runs locally. No data leaves the machine.
- Scanner reads config from `~/.openclaw/openclaw.json`
- Reports saved to `<skill_dir>/reports/`
- The scan requires `openclaw cron list --json` to work (runs via CLI)
