from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    finding_id: str
    title: str
    target: str
    category: str = "general"
    severity_hint: str = "medium"
    evidence: str = ""
    cwe_id: Optional[str] = None


@dataclass
class RiskAssessment:
    finding_id: str
    cwe_id: str
    cwe_name: str
    risk_score: float
    severity: str
    summary: str
    remediation: List[str] = field(default_factory=list)
    safe_verification: str = ""


@dataclass
class AgentReport:
    target: str
    assessments: List[RiskAssessment] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
