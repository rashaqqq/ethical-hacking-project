import hmac
import time
from dataclasses import dataclass

APPROVAL_PHRASE = "APPROVE LOCAL LAB SCAN"
APPROVAL_TTL_SEC = 300


class ApprovalDenied(Exception):
    pass


@dataclass
class ActiveScanApproval:
    url: str
    issued_at: float
    used: bool = False


class PolicyEngine:
    def __init__(self, scope, audit):
        self.scope, self.audit = scope, audit

    def check_network(self, url):
        return self.scope.validate(url)

    def request_active_approval(self, url, typed_phrase) -> ActiveScanApproval:
        self.scope.validate(url)
        ok = isinstance(typed_phrase, str) and hmac.compare_digest(
            typed_phrase.encode("utf-8"), APPROVAL_PHRASE.encode("utf-8"))
        if not ok:
            self.audit.log("active_scan_denied", url=url, reason="wrong approval phrase")
            raise ApprovalDenied("wrong approval phrase")
        self.audit.log("active_scan_approved", url=url)
        return ActiveScanApproval(url=url, issued_at=time.time())

    def consume(self, approval, url):
        if not isinstance(approval, ActiveScanApproval):
            raise ApprovalDenied("no valid approval token")
        if approval.used:
            raise ApprovalDenied("approval already used")
        if approval.url != url:
            raise ApprovalDenied("approval is for a different URL")
        if time.time() - approval.issued_at > APPROVAL_TTL_SEC:
            raise ApprovalDenied("approval expired")
        self.scope.validate(url)
        approval.used = True
        self.audit.log("active_scan_authorized", url=url)
