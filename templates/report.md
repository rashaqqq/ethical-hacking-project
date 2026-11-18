# SecureScope AI - Assessment Report
Target: {{ target }} | Generated: {{ ts }} | Audit chain: {{ "VERIFIED" if audit_ok else "BROKEN" }} ({{ audit_entries }} entries)

*Findings detected by the scanner; AI assessed severity and risk; a human reviewer decided. Nothing here is a confirmed exploit.*

| ID | CWE | Severity | Score | Human |
|---|---|---|---|---|
{% for a in items %}| {{ a.finding_id }} | CWE-{{ a.cwe_id }} | {{ a.severity }} | {{ a.risk_score }} | {{ decisions[a.finding_id].decision if a.finding_id in decisions else "-" }} |
{% endfor %}
