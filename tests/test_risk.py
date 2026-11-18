import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from models import Finding
from risk import assess_finding


def test_assess_finding_maps_cwe_and_score():
    finding = Finding(
        finding_id="T-001",
        title="SQL Input Check",
        target="http://localhost:8080",
        category="sql",
        severity_hint="high",
    )
    assessment = assess_finding(finding)
    assert assessment.cwe_id == "CWE-89"
    assert assessment.risk_score == 8.2
    assert assessment.severity == "High"
    assert len(assessment.remediation) > 0
