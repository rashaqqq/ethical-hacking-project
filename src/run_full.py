import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.chdir(ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from agent import SecurityAssessmentAgent
from audit import AuditLog
from models import Finding
from policy import PolicyEngine
from report import build_report
from review_cli import Decision
from sanitizer import sanitize_finding
from scope import ScopeGuard, ScopeViolation
from zap_client import ZapClient

console = Console()

CWE_NAMES = {
    "16": "Configuration", "20": "Improper Input Validation",
    "79": "Cross-site Scripting (XSS)", "89": "SQL Injection",
    "200": "Exposure of Sensitive Information", "264": "Permissions, Privileges, and Access Controls",
    "352": "Cross-Site Request Forgery (CSRF)", "525": "Sensitive Data Cached by Browser",
    "548": "Directory Listing Exposure", "614": "Cookie Missing Secure Attribute",
    "693": "Protection Mechanism Failure (e.g. missing CSP header)",
    "1004": "Cookie Missing HttpOnly Attribute", "1021": "Clickjacking (Missing X-Frame-Options)",
    "1275": "Cookie Missing SameSite Attribute",
}
RISK = {"high": "high", "medium": "medium", "low": "low", "informational": "low"}
ORDER = {"high": 3, "medium": 2, "low": 1}


def read_raw(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("findings", [])


def load(path, limit):
    seen, out = set(), []
    for a in read_raw(path):
        key = (a.get("name"), a.get("url"), a.get("parameter", ""))
        if key in seen:
            continue
        seen.add(key)
        sev = RISK.get(str(a.get("risk", "")).lower(), "medium")
        parts = []
        if a.get("parameter"):
            parts.append(f"param={a['parameter']}")
        if a.get("evidence"):
            parts.append(f"evidence={a['evidence']}")
        parts.append((a.get("description") or "")[:300])
        cwe = str(a.get("cwe_id") or "")
        out.append(Finding(
            finding_id="", title=a.get("name") or "Finding", target=a.get("url") or "",
            category="general", severity_hint=sev, evidence=" | ".join(p for p in parts if p),
            cwe_id=cwe if cwe not in ("", "0", "-1") else None))
    out.sort(key=lambda f: -ORDER.get(f.severity_hint, 2))
    out = out[:limit]
    for i, f in enumerate(out, 1):
        f.finding_id = f"F{i:03d}"
    return out


def show_cvss_panel(i, n, a):
    t = Table.grid(padding=(0, 2))
    t.add_row("CWE:", f"CWE-{a.cwe_id} ({a.cwe_name})")
    t.add_row("CVSS v3.1:", f"[bold]{a.risk_score}/10 ({a.severity})[/bold]  [{a.cvss_vector}]")
    if getattr(a, "root_cause", ""):
        t.add_row("Root Cause:", a.root_cause)
    t.add_row("Assessment:", a.summary)
    t.add_row("Remediation:", "; ".join(a.remediation[:2]))
    console.print(Panel(t, title=f"Finding {i}/{n} - {a.finding_id}"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="data/findings.json")
    ap.add_argument("--target", default="http://127.0.0.1:3000", help="Target URL for live ZAP scan")
    ap.add_argument("--live", action="store_true", help="Run live OWASP ZAP scan before analysis")
    ap.add_argument("--zap-url", default="http://127.0.0.1:8090")
    ap.add_argument("--name", default="Juice Shop")
    ap.add_argument("--max", type=int, default=10)
    ap.add_argument("--auto", action="store_true", help="approve all without asking")
    args = ap.parse_args()

    audit = AuditLog("logs/audit.jsonl")
    scope = ScopeGuard.from_config("config.yaml", audit=audit)
    policy = PolicyEngine(scope, audit)
    audit.log("pipeline_start", mode="live" if args.live else "saved", target=args.target)

    if args.live:
        console.print(f"[cyan]Starting live OWASP ZAP scan on {args.target}...[/cyan]")
        zap = ZapClient(policy, audit, zap_url=args.zap_url)
        zap.passive_scan(args.target)
        args.findings = "data/findings.json"

    kept = []
    for f in load(args.findings, args.max):
        try:
            policy.check_network(f.target)
            kept.append(f)
        except ScopeViolation as e:
            console.print(f"[red]Skipped out-of-scope:[/red] {f.target} ({e})")
    audit.log("scope_filtered", kept=len(kept))

    safe = [sanitize_finding(f) for f in kept]
    audit.log("sanitized", count=len(safe))

    report = SecurityAssessmentAgent().evaluate_findings(safe, target=args.name)
    for n in report.notes:
        console.print(f"[cyan]{n}[/cyan]")
    audit.log("assessed", count=len(report.assessments))

    sol = {r.get("name"): (r.get("solution") or "").strip()[:300] for r in read_raw(args.findings)}
    title = {f.finding_id: f.title for f in safe}
    for a in report.assessments:
        old_name = a.cwe_name
        a.cwe_id = str(a.cwe_id).replace("CWE-", "")
        a.cwe_name = CWE_NAMES.get(a.cwe_id, a.cwe_name)
        a.summary = a.summary.replace(f"({old_name})", f"({a.cwe_name})").replace("CWE-CWE-", "CWE-")
        if not a.remediation:
            s = sol.get(title.get(a.finding_id, ""), "")
            if s:
                a.remediation = [s]

    decisions = {}
    n = len(report.assessments)
    for i, a in enumerate(report.assessments, 1):
        if args.auto:
            d = Decision(finding_id=a.finding_id, decision="approve", note="auto")
        else:
            show_cvss_panel(i, n, a)
            c = Prompt.ask("\\[a]pprove / \\[r]eject / \\[m]odify", choices=["a", "r", "m"], default="a")
            d = Decision(finding_id=a.finding_id,
                         decision={"a": "approve", "r": "reject", "m": "modify"}[c])
            if c == "m":
                d.final_severity = Prompt.ask("New severity", choices=["Low", "Medium", "High", "Critical"],
                                              default=a.severity)
                a.severity = d.final_severity
                d.note = Prompt.ask("Note", default="")
            elif c == "r":
                d.note = Prompt.ask("Reason", default="")
        decisions[a.finding_id] = d
        audit.log("human_decision", finding=a.finding_id, decision=d.decision,
                  final_severity=d.final_severity, note=d.note[:200])

    path = build_report(report.assessments, args.name, audit, decisions=decisions)
    audit.log("report_built", path=str(path))
    console.print(f"[green]Report:[/green] {path}")
    console.print("Audit chain:", "[green]OK[/green]" if audit.verify() else "[red]BROKEN[/red]")


if __name__ == "__main__":
    main()
