import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[0]).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zap.alert_normalizer import normalize_alerts

SECRET = re.compile(r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|(?i:cookie|authorization)\s*[:=]\s*\S+)")


def clean(value):
    return SECRET.sub("[REDACTED]", value) if isinstance(value, str) else value


raw = json.load(open(ROOT / "data" / "raw_alerts.json", encoding="utf-8"))
findings = [{k: clean(v) for k, v in f.items()} for f in normalize_alerts(raw)]
for f in findings:
    f["target"] = "Juice Shop"

with open(ROOT / "data" / "findings.json", "w", encoding="utf-8") as fh:
    json.dump(findings, fh, indent=2, ensure_ascii=False)

print(len(raw), "alerts ->", len(findings), "findings")
