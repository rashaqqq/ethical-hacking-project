import argparse
import json
import os
import re
import sys
import time
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

from agent import SecurityAssessmentAgent
from audit import AuditLog
from llm_client import GroqClient
from policy import PolicyEngine
from report import build_report
from review_cli import Decision
from run_full import CWE_NAMES, load, read_raw
from sanitizer import sanitize_finding
from scope import ScopeGuard, ScopeViolation
from zap_client import ZapClient

console = Console()

ROUTER_PROMPT = """You are SecureScope AI, a concise, professional ethical-hacking assistant.
Analyze the user's message and reply ONLY with a JSON object:
{
  "action": "scan" | "chat",
  "target": "clean URL if user wants to scan/test a site or domain (e.g. http://127.0.0.1:3000 or http://google.com), else empty string",
  "reply": "short, clear answer in the user's language ONLY when action is 'chat' (leave empty when action is 'scan')"
}
Rules:
- If the user asks to scan, test, or check ANY URL/domain/localhost, set action="scan", put the clean URL in "target" (prepend http:// if no scheme is given), and set "reply": "".
- Otherwise set action="chat" and answer clearly using Last Scan Context."""


def phase_banner(num: int, title: str, detail: str):
    console.print(f"\n[bold cyan]▶ [Phase {num}/5] {title}[/bold cyan]")
    console.print(f"  [dim]↳ {detail}[/dim]")
    time.sleep(0.5)


def run_narrated_pipeline(target_url: str, live: bool, zap_url: str, max_items: int, auto: bool) -> str:
    audit = AuditLog("logs/audit.jsonl")
    scope = ScopeGuard.from_config("config.yaml", audit=audit)
    policy = PolicyEngine(scope, audit)

    # Phase 1: Scope & Authorization
    phase_banner(1, "Scope & Authorization Check", f"Validating {target_url} against authorized lab policy...")
    try:
        policy.check_network(target_url)
    except ScopeViolation as e:
        msg = f"OUT OF SCOPE: '{target_url}' is blocked ({e}). Only http://127.0.0.1 or http://localhost targets are permitted."
        console.print(f"  [bold red]✖ {msg}[/bold red]")
        audit.log("chat_scope_blocked", target=target_url, reason=str(e))
        return msg
    console.print("  [bold green]✔ Authorized (In-Scope).[/bold green]")

    # Phase 2: Passive Inspection
    findings_path = "data/findings.json"
    if live:
        phase_banner(2, "OWASP ZAP Live Passive Scan", f"Spidering & inspecting {target_url} with redirect scope guard...")
        try:
            zap = ZapClient(policy, audit, zap_url=zap_url)
            zap.passive_scan(target_url)
        except Exception as e:
            console.print(f"  [yellow]! ZAP daemon busy/starting ({type(e).__name__}); falling back cleanly to saved passive findings.[/yellow]")
    else:
        phase_banner(2, "Scanner Ingestion & Scope Filtering", f"Loading passive findings for {target_url}...")

    kept = []
    for f in load(findings_path, max_items):
        try:
            policy.check_network(f.target)
            kept.append(f)
        except ScopeViolation:
            pass
    console.print(f"  [bold green]✔ {len(kept)} in-scope findings collected.[/bold green]")

    # Phase 3: Sanitization
    phase_banner(3, "PII & Secret Sanitization", "Redacting tokens, cookies, and credentials before LLM analysis...")
    safe = [sanitize_finding(f) for f in kept]
    audit.log("sanitized", count=len(safe))
    console.print(f"  [bold green]✔ {len(safe)} findings sanitized.[/bold green]")

    # Phase 4: AI Root-Cause & CVSS v3.1
    phase_banner(4, "Evidence Root-Cause & CVSS v3.1 Scoring", "Analyzing HTTP evidence via Groq and computing deterministic CVSS v3.1 vectors...")
    report = SecurityAssessmentAgent().evaluate_findings(safe, target=target_url)
    sol = {r.get("name"): (r.get("solution") or "").strip()[:300] for r in read_raw(findings_path)}
    title_map = {f.finding_id: f.title for f in safe}
    for a in report.assessments:
        a.cwe_id = str(a.cwe_id).replace("CWE-", "")
        a.cwe_name = CWE_NAMES.get(a.cwe_id, a.cwe_name)
        if not a.remediation and sol.get(title_map.get(a.finding_id, "")):
            a.remediation = [sol[title_map[a.finding_id]]]
    console.print(f"  [bold green]✔ {len(report.assessments)} findings scored.[/bold green]")

    # Phase 5: Human Review & SHA-256 Audit Chain
    phase_banner(5, "Human-in-the-Loop Sign-Off & SHA-256 Audit Chain", "Confirming analyst review and sealing tamper-evident audit log...")
    decisions = {}
    approve_rest = auto
    for a in report.assessments:
        if approve_rest:
            d = Decision(finding_id=a.finding_id, decision="approve", note="approved")
        else:
            console.print(f"\n  [bold]{a.finding_id}[/bold] | CWE-{a.cwe_id} ({a.cwe_name}) | [yellow]{a.severity} ({a.risk_score}/10)[/yellow]")
            console.print(f"  Vector: [cyan]{a.cvss_vector}[/cyan]")
            if a.root_cause:
                console.print(f"  Root Cause: {a.root_cause}")
            c = Prompt.ask("  Decision (a=approve, all=approve all, r=reject, m=modify)", choices=["a", "all", "r", "m"], default="a")
            if c == "all":
                approve_rest = True
                c = "a"
            d = Decision(finding_id=a.finding_id, decision={"a": "approve", "r": "reject", "m": "modify"}[c])
        decisions[a.finding_id] = d
        audit.log("human_decision", finding=a.finding_id, decision=d.decision)

    path = build_report(report.assessments, target_url, audit, decisions=decisions)
    chain_ok = audit.verify()
    console.print(f"\n  [bold green]✔ Report saved:[/bold green] {path} | [bold green]Audit Chain:[/bold green] {'VERIFIED' if chain_ok else 'BROKEN'}")

    lines = [f"Assessment completed on {target_url}. Report: {path}."]
    for a in report.assessments:
        lines.append(f"- {a.finding_id} (CWE-{a.cwe_id} {a.cwe_name}): {a.severity} {a.risk_score}/10 [{a.cvss_vector}] | Root cause: {a.root_cause}")
    return "\n".join(lines)


def _clean_url(raw_url: str) -> str:
    m = re.search(r"https?://[^\s\)\]]+", raw_url)
    return m.group(0).rstrip(".,;)") if m else raw_url.strip("[]() ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="Use live OWASP ZAP for in-scope scans")
    ap.add_argument("--zap-url", default="http://127.0.0.1:8090")
    ap.add_argument("--max", type=int, default=3)
    ap.add_argument("--auto", action="store_true", help="Auto-approve findings")
    args = ap.parse_args()

    llm = GroqClient()
    last_context = "No scan has been executed yet in this session."

    console.print(Panel.fit(
        "[bold cyan]SecureScope AI — Conversational Security Agent[/bold cyan]\n"
        "Ask security questions, test scope blocking (e.g. 'scan google.com'),\n"
        "or run 'scan http://127.0.0.1:3000' to watch all 5 narrated phases. Type 'exit' to quit.",
        border_style="cyan"
    ))

    while True:
        user_msg = input("\nYou: ").strip()
        if not user_msg or len(user_msg) > 500:
            continue
        if user_msg.lower() in ("exit", "quit", "خروج"):
            break

        raw = llm.analyze_text(f"{ROUTER_PROMPT}\nLast Scan Context:\n{last_context}\nUser Message: {user_msg}")
        m = re.search(r"\{.*\}", raw or "", re.S)
        action, target, reply = "chat", "", raw or "How can I assist you?"
        if m:
            try:
                data = json.loads(m.group(0))
                action = data.get("action", "chat")
                target = _clean_url(data.get("target") or "")
                reply = (data.get("reply") or "").strip()
            except Exception:
                pass

        if action == "scan" and target:
            last_context = run_narrated_pipeline(target, live=args.live, zap_url=args.zap_url, max_items=args.max, auto=args.auto)
            followup = llm.analyze_text(
                f"In 3-4 short bullet points in the user's language, summarize this outcome clearly:\n{last_context}"
            )
            console.print(f"\n[bold magenta]SecureScope AI:[/bold magenta]\n{followup}")
        else:
            console.print(f"\n[bold magenta]SecureScope AI:[/bold magenta] {reply}")


if __name__ == "__main__":
    main()
