from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()


@dataclass
class Decision:
    finding_id: str
    decision: str  # "approve" | "reject" | "modify"
    note: str = ""
    final_severity: Optional[str] = None
    approve_active_verification: bool = False


def _show(i, n, assessment):
    t = Table.grid(padding=(0, 2))
    t.add_row("CWE:", f"CWE-{assessment.cwe_id} ({assessment.cwe_name})")
    t.add_row("Severity:", assessment.severity)
    t.add_row("Risk score:", f"{assessment.risk_score}/10")
    t.add_row("Summary:", assessment.summary)
    t.add_row("Remediation:", "; ".join(assessment.remediation) or "-")
    if assessment.safe_verification:
        t.add_row("Suggested safe check:", assessment.safe_verification)
    console.print(Panel(t, title=f"Finding {i}/{n} - {assessment.finding_id}"))


def review(assessments):
    decisions = []
    for i, a in enumerate(assessments, 1):
        _show(i, len(assessments), a)
        c = Prompt.ask("[a]pprove / [r]eject / [m]odify", choices=["a", "r", "m"], default="a")
        d = Decision(finding_id=a.finding_id, decision={"a": "approve", "r": "reject", "m": "modify"}[c])
        if c == "m":
            d.final_severity = Prompt.ask("New severity", choices=["low", "medium", "high", "critical"],
                                          default=a.severity)
            d.note = Prompt.ask("Note", default="")
        elif c == "r":
            d.note = Prompt.ask("Reason", default="")
        if a.safe_verification and c != "r":
            console.print(f"[cyan]Agent suggests safe verification:[/cyan] {a.safe_verification}")
            d.approve_active_verification = Confirm.ask("Approve this safe active check?", default=False)
        decisions.append(d)
    return decisions


def auto_review(assessments):
    """للتجارب فقط: يوافق على الكل ولا يطلب أي فحص نشط أبدًا."""
    return [Decision(finding_id=a.finding_id, decision="approve", note="auto") for a in assessments]


def ask_phrase(target, reason):
    console.print(Panel(f"[bold red]ACTIVE VERIFICATION[/bold red] on [bold]{target}[/bold]\nReason: {reason}\n"
                        "This may send attack-like requests. Local lab targets only.", title="Approval gate"))
    return input("Type the approval phrase exactly (Enter to cancel): ")
