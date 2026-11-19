from typing import Dict, Optional, Tuple

CWE_REFERENCE: Dict[str, Tuple[str, str]] = {
    "sql": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"),
    "auth": ("CWE-287", "Improper Authentication"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "config": ("CWE-16", "Configuration"),
    "general": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
}


def map_category_to_cwe(category: str, explicit_cwe: Optional[str] = None) -> Tuple[str, str]:
    if explicit_cwe is not None:
        cleaned = str(explicit_cwe).strip()
        if cleaned and cleaned not in ("-1", "None", "null", "0"):
            formatted = cleaned.upper() if cleaned.upper().startswith("CWE-") else f"CWE-{cleaned}"
            return formatted, f"Mapped CWE ({formatted})"

    key = (category or "general").strip().lower()
    for k, val in CWE_REFERENCE.items():
        if k in key:
            return val
    return CWE_REFERENCE["general"]
