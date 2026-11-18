from pathlib import Path
from typing import List, Optional

from agent import SecurityAssessmentAgent, load_findings_from_json
from models import AgentReport, Finding


def default_sample_findings(target: str = "http://localhost:8080") -> List[Finding]:
    return [
        Finding(
            finding_id="LAB-001",
            title="Potential Unvalidated Input Parameter",
            target=target,
            category="sql",
            severity_hint="high",
            evidence="Detected parameterized query/input handler in lab scope.",
        ),
        Finding(
            finding_id="LAB-002",
            title="Reflected Input Display Check",
            target=target,
            category="xss",
            severity_hint="medium",
            evidence="Observed unencoded reflection candidate in lab response.",
        ),
    ]


def run_pipeline(findings_file: Optional[str | Path] = None, target: str = "http://localhost:8080") -> AgentReport:
    findings: List[Finding] = []
    if findings_file:
        findings = load_findings_from_json(findings_file)
    if not findings:
        findings = default_sample_findings(target=target)

    agent = SecurityAssessmentAgent()
    return agent.evaluate_findings(findings=findings, target=target)
