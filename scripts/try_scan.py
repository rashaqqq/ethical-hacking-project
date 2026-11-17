from src.zap_client import ZapClient


class _A:
    def log(self, *a, **k):
        pass


class _P:
    def check_network(self, url):
        return None

    def consume(self, a, u):
        return None


zap = ZapClient(_P(), _A())
print("ZAP:", zap.version())
raw = zap.passive_scan("http://127.0.0.1:3000")
print("raw alerts:", len(raw))
