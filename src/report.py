from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


def _severity_rank(s: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)


def build_report(assessments, target, audit, decisions=None, out_dir="reports", templates="templates") -> str:
    env = Environment(loader=FileSystemLoader(templates), autoescape=select_autoescape(["html"]))
    decisions = decisions or {}
    items = sorted(assessments, key=lambda a: -_severity_rank(a.severity))
    counts: dict = {}
    for a in items:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    ctx = dict(
        target=target,
        ts=datetime.now().strftime("%Y-%m-%d %H:%M"),
        items=items,
        decisions=decisions,
        counts=counts,
        audit_ok=audit.verify(),
        audit_entries=sum(1 for _ in audit.path.open(encoding="utf-8")),
    )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = out / f"report_{stamp}.html"
    html_path.write_text(env.get_template("report.html").render(**ctx), encoding="utf-8")
    (out / f"report_{stamp}.md").write_text(env.get_template("report.md").render(**ctx), encoding="utf-8")
    return str(html_path)
