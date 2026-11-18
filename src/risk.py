from models import Finding, RiskAssessment
from tools import map_category_to_cwe

SEVERITY_SCORES = {
    "low": 3.0,
    "medium": 6.0,
    "high": 8.2,
    "critical": 9.5,
}


def assess_finding(finding: Finding) -> RiskAssessment:
    cwe_id, cwe_name = map_category_to_cwe(finding.category, finding.cwe_id)
    hint = (finding.severity_hint or "medium").strip().lower()
    score = SEVERITY_SCORES.get(hint, 6.0)

    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"

    remediation = [
        "Validate and sanitize all untrusted inputs on the server side.",
        "Enforce least-privilege access controls and secure configuration baselines.",
        "Re-test the affected endpoint in a controlled lab environment after patching.",
    ]
    safe_verification = (
        f"Verify configuration/response behavior on {finding.target} using non-destructive checks "
        f"and confirm {cwe_id} mitigation."
    )
    summary = (
        f"Finding '{finding.title}' ({finding.finding_id}) mapped to {cwe_id} ({cwe_name}) "
        f"with a risk score of {score}/10 ({severity})."
    )

    return RiskAssessment(
        finding_id=finding.finding_id,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        risk_score=score,
        severity=severity,
        summary=summary,
        remediation=remediation,
        safe_verification=safe_verification,
    )
