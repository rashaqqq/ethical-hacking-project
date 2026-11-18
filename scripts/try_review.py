import sys
sys.path.insert(0, "src")
from models import RiskAssessment
from review_cli import review

a = RiskAssessment(
    finding_id="F001", cwe_id="693", cwe_name="Protection Mechanism Failure",
    risk_score=5.0, severity="medium",
    summary="Missing CSP header detected by scanner.",
    remediation=["Add Content-Security-Policy header"],
    safe_verification="Check response headers manually"
)
print(review([a]))
