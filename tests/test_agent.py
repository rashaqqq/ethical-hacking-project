import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from orchestrator import run_pipeline


def test_run_pipeline_returns_assessments():
    report = run_pipeline(target="http://localhost:8080")
    assert report.target == "http://localhost:8080"
    assert len(report.assessments) == 2
    assert all(a.cwe_id.startswith("CWE-") for a in report.assessments)


def test_agent_sanitizes_evidence_and_sets_cvss():
    from agent import SecurityAssessmentAgent
    from models import Finding

    class DummyLLM:
        def __init__(self):
            self.last_prompt = ""

        def ping(self) -> str:
            return "mock-ok"

        def analyze_text(self, prompt: str) -> str:
            self.last_prompt = prompt
            return json.dumps({
                "root_cause": "Missing X-Frame-Options header on response.",
                "impact_summary": "Clickjacking risk in embedded frames.",
                "remediation": ["Add X-Frame-Options: DENY header."],
                "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
            })

    dummy = DummyLLM()
    agent = SecurityAssessmentAgent(llm_client=dummy)
    finding = Finding(
        finding_id="F-101",
        title="Missing Anti-Clickjacking Header",
        target="http://localhost:8080",
        category="headers",
        severity_hint="medium",
        evidence="Authorization: Bearer super_secret_token_999\nHTTP/1.1 200 OK",
    )
    report = agent.evaluate_findings([finding], target="http://localhost:8080")
    assert "super_secret_token_999" not in dummy.last_prompt
    assert "<data>" in dummy.last_prompt and "</data>" in dummy.last_prompt
    assert len(report.assessments) == 1
    assert report.assessments[0].cvss_vector.startswith("CVSS:3.1/")
    assert report.assessments[0].root_cause == "Missing X-Frame-Options header on response."
