import pytest

from audit import AuditLog
from scope import ScopeGuard, ScopeViolation


@pytest.fixture
def guard(tmp_path):
    audit = AuditLog(str(tmp_path / "a.jsonl"))
    return ScopeGuard.from_config("config.yaml", audit=audit)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:3000/rest/products",
    "http://127.0.0.1:8081/login.php",
])
def test_allowed(guard, url):
    t = guard.validate(url)
    assert t.name in ("Juice Shop", "DVWA")


@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://127.0.0.1:3000/",
    "http://127.0.0.1:9999/",
    "http://localhost:3000/",
    "ftp://127.0.0.1:3000/",
    "http://127.0.0.1:3000@evil.com/",
    "http://127.0.0.1:3000%40evil.com",
    "http://127.0.0.1:3000#@evil.com",
])
def test_rejected(guard, url):
    with pytest.raises(ScopeViolation):
        guard.validate(url)
