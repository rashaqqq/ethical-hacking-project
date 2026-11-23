import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from audit import AuditLog

console = Console()

def main():
    path = Path("logs/audit.jsonl")
    audit = AuditLog(str(path))
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    table = Table(title="SecureScope AI — SHA-256 Audit Chain (Last 5 Events)")
    table.add_column("#", style="cyan")
    table.add_column("Event", style="bold")
    table.add_column("Prev Hash (prefix)", style="dim")
    table.add_column("Current Hash (prefix)", style="green")

    start = max(0, len(lines) - 5)
    for idx, line in enumerate(lines[start:], start + 1):
        rec = json.loads(line)
        table.add_row(
            str(idx),
            rec.get("event", ""),
            str(rec.get("prev_hash", ""))[:16] + "...",
            str(rec.get("hash", ""))[:16] + "...",
        )
    console.print(table)

    if audit.verify():
        console.print("[bold green]✔ AUDIT CHAIN INTEGRITY: VERIFIED (No tampering detected)[/bold green]")
    else:
        console.print("[bold red]✖ AUDIT CHAIN INTEGRITY: BROKEN / TAMPERED![/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
