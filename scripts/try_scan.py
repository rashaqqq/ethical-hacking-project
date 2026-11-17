import sys
sys.path.insert(0, "src")
from dotenv import load_dotenv
load_dotenv()
from zap_client import ZapClient

try:
    from audit import AuditLog
    from scope import ScopeGuard
    from policy import PolicyEngine
    audit = AuditLog("logs/audit.jsonl")
    policy = PolicyEngine(ScopeGuard.from_config("config.yaml", audit=audit), audit)
except ImportError:
    print("[stub mode] C files not pulled yet")
    class _A:
        def log(self, *a, **k): pass
    class _P:
        def check_network(self, url): return None
        def consume(self, a, u): return None
    audit, policy = _A(), _P()

zap = ZapClient(policy, audit)
print("ZAP:", zap.version())
raw = zap.passive_scan("http://127.0.0.1:3000")
print("raw alerts:", len(raw))
print("saved to data/raw_alerts.json")

