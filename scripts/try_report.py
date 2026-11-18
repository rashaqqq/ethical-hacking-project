import sys
sys.path.insert(0, "src")
from models import RiskAssessment
from audit import AuditLog
from report import build_report

audit = AuditLog("logs/_t.jsonl")
audit.log("demo")
a = RiskAssessment(
    finding_id="F001", cwe_id="693", cwe_name="Protection Mechanism Failure",
    risk_score=5.0, severity="medium",
    summary="Missing CSP header detected by scanner.",
    remediation=["Add Content-Security-Policy header"],
)
path = build_report([a], "Juice Shop", audit)
print(path)
