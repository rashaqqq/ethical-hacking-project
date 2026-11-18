from typing import Dict, Tuple

CWE_REFERENCE: Dict[str, Tuple[str, str]] = {
    "sql": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
    "auth": ("CWE-287", "Improper Authentication"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "config": ("CWE-16", "Configuration"),
    "general": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
}


def map_category_to_cwe(category: str, explicit_cwe: str | None = None) -> Tuple[str, str]:
    if explicit_cwe:
        return explicit_cwe.upper(), f"Mapped CWE ({explicit_cwe.upper()})"
    key = (category or "general").strip().lower()
    for k, val in CWE_REFERENCE.items():
        if k in key:
            return val
    return CWE_REFERENCE["general"]
