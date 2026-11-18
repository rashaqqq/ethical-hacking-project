import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zap.alert_normalizer import normalize_alert, normalize_alerts

EXPECTED_KEYS = {
    "alert_id", "name", "risk", "confidence", "url", "method",
    "parameter", "description", "evidence", "solution", "reference", "cwe_id",
}


def test_keys_are_unified():
    out = normalize_alert({"pluginId": "10038", "name": "CSP", "risk": "Low"})
    assert set(out) == EXPECTED_KEYS


def test_values_are_mapped():
    out = normalize_alert({"pluginId": "10038", "name": "CSP", "risk": "Low", "param": "x", "cweid": "693"})
    assert out["alert_id"] == "10038"
    assert out["name"] == "CSP"
    assert out["risk"] == "Low"
    assert out["parameter"] == "x"
    assert out["cwe_id"] == "693"


def test_missing_fields_become_empty_string():
    out = normalize_alert({})
    assert all(v == "" for v in out.values())


def test_normalize_alerts_list():
    out = normalize_alerts([{"pluginId": "1"}, {"pluginId": "2"}])
    assert [a["alert_id"] for a in out] == ["1", "2"]


def test_normalize_alerts_empty():
    assert normalize_alerts([]) == []


def test_sample_fixture():
    import json
    data = json.load(open(Path(__file__).parent / "fixtures" / "zap_alerts_sample.json"))
    out = normalize_alerts(data)
    assert len(out) == len(data)
    assert all(set(a) == EXPECTED_KEYS for a in out)
