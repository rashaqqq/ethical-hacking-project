import pytest

from audit import AuditLog
from policy import APPROVAL_PHRASE, ActiveScanApproval, ApprovalDenied, PolicyEngine
from scope import ScopeGuard, ScopeViolation

URL = "http://127.0.0.1:3000/rest/products"


@pytest.fixture
def policy(tmp_path):
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    return PolicyEngine(ScopeGuard.from_config("config.yaml", audit=audit), audit)


def test_right_phrase_then_single_use(policy):
    ap = policy.request_active_approval(URL, APPROVAL_PHRASE)
    policy.consume(ap, URL)
    with pytest.raises(ApprovalDenied):
        policy.consume(ap, URL)


@pytest.mark.parametrize("phrase", ["", "approve local lab scan", APPROVAL_PHRASE + " ",
                                    "APPROVE  LOCAL LAB SCAN", "yes", None, 123, APPROVAL_PHRASE + "\n"])
def test_wrong_phrase_denied(policy, phrase):
    with pytest.raises(ApprovalDenied):
        policy.request_active_approval(URL, phrase)
    assert "active_scan_denied" in policy.audit.path.read_text(encoding="utf-8")


def test_out_of_scope_rejected_even_with_right_phrase(policy):
    with pytest.raises(ScopeViolation):
        policy.request_active_approval("http://example.com", APPROVAL_PHRASE)


def test_token_rules(policy):
    ap = policy.request_active_approval(URL, APPROVAL_PHRASE)
    with pytest.raises(ApprovalDenied):
        policy.consume(ap, "http://127.0.0.1:8081/")
    with pytest.raises(ApprovalDenied):
        policy.consume("fake-token", URL)
    old = ActiveScanApproval(url=URL, issued_at=ap.issued_at - 1000)
    with pytest.raises(ApprovalDenied):
        policy.consume(old, URL)
