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
