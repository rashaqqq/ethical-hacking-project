import json
from pathlib import Path
from typing import Iterable, List, Optional

from llm_client import GroqClient
from models import AgentReport, Finding, RiskAssessment
from prompts import SYSTEM_PROMPT
from risk import assess_finding


class SecurityAssessmentAgent:
    def __init__(self, llm_client: Optional[GroqClient] = None):
        self.llm = llm_client or GroqClient()
        self.system_prompt = SYSTEM_PROMPT

    def evaluate_findings(self, findings: Iterable[Finding], target: str = "lab-target") -> AgentReport:
        assessments: List[RiskAssessment] = []
        notes: List[str] = [f"LLM status: {self.llm.ping()}"]

        for item in findings:
            assessment = assess_finding(item)
            insight = self.llm.analyze_text(
                f"{self.system_prompt}\nFinding: {item.title} | Category: {item.category} | CWE: {assessment.cwe_id}"
            )
            if insight and not assessment.summary.endswith(insight):
                assessment.summary = f"{assessment.summary} {insight}"
            assessments.append(assessment)

        return AgentReport(target=target, assessments=assessments, notes=notes)


def load_findings_from_json(path: str | Path) -> List[Finding]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    data = json.loads(file_path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("findings", [])
    result: List[Finding] = []
    for idx, raw in enumerate(items, start=1):
        result.append(
            Finding(
                finding_id=str(raw.get("id") or raw.get("finding_id") or f"F-{idx:03d}"),
                title=str(raw.get("title") or raw.get("name") or f"Finding {idx}"),
                target=str(raw.get("target") or "http://localhost"),
                category=str(raw.get("category") or "general"),
                severity_hint=str(raw.get("severity") or raw.get("severity_hint") or "medium"),
                evidence=str(raw.get("evidence") or ""),
                cwe_id=raw.get("cwe_id"),
            )
        )
    return result
