import hashlib
import json
import time
from pathlib import Path


class AuditLog:
    """سجل أحداث بسلسلة hash: كل سطر مرتبط بالسطر اللي قبله، فأي تعديل يكسر السلسلة."""

    def __init__(self, path="logs/audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def _last_hash(self) -> str:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return "0" * 64
        return json.loads(lines[-1])["hash"]

    def log(self, event: str, **fields):
        prev = self._last_hash()
        entry = {"ts": time.time(), "event": event, **fields, "prev": prev}
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry["hash"] = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def verify(self) -> bool:
        prev = "0" * 64
        for line in self.path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            claimed_hash = entry.pop("hash")
            payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
            real_hash = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
            if real_hash != claimed_hash or entry["prev"] != prev:
                return False
            prev = claimed_hash
        return True
