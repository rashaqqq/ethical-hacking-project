import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from policy import PolicyEngine
from scope import ScopeGuard
from zap_client import ZapClient


class DummyAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **kwargs):
        self.events.append((event, kwargs))


def test_validate_redirect_chain_blocks_out_of_scope_redirect():
    scope = ScopeGuard(
        allowed_schemes=["http"],
        allowed_targets=[{"host": "127.0.0.1", "port": 3000, "name": "Juice Shop"}],
    )
    audit = DummyAudit()
    policy = PolicyEngine(scope, audit)
    client = ZapClient(policy, audit, zap_url="http://127.0.0.1:8090")

    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"Location": "http://evil.com/steal"}

    with patch("zap_client.requests.get", return_value=resp):
        final_url = client.validate_redirect_chain("http://127.0.0.1:3000/")

    assert final_url == "http://127.0.0.1:3000/"
    assert any(ev == "redirect_blocked" for ev, _ in audit.events)
