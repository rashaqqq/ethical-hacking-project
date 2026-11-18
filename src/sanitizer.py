import re
from dataclasses import replace

from models import Finding

_RULES = [
    (re.compile(r"(?i)\b(cookie|set-cookie|authorization|proxy-authorization|x-api-key)\s*:\s*[^\r\n]+"),
     r"\1: [REDACTED]"),
    (re.compile(r"eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{5,}"), "[JWT_REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|session(?:id)?|phpsessid|auth)\b"
                r"([\"']?\s*[:=]\s*[\"']?)[^\s&\"',;]+"), r"\1\2[REDACTED]"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "[EMAIL]"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[HEX_REDACTED]"),
]
_CAPS = {"title": 300, "target": 300, "evidence": 1500}


def sanitize_text(t: str, limit: int = 1500) -> str:
    for pat, rep in _RULES:
        t = pat.sub(rep, t)
    return t[:limit]


def sanitize_finding(f: Finding) -> Finding:
    clean = {
        "title": sanitize_text(f.title or "", _CAPS["title"]),
        "target": sanitize_text(f.target or "", _CAPS["target"]),
        "evidence": sanitize_text(f.evidence or "", _CAPS["evidence"]),
    }
    return replace(f, **clean)
