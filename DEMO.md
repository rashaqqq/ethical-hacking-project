# SecureScope AI - Demo

1. `pytest -v`  → 41 tests (scope attacks, secrets sanitizer, approval gate, audit chain)
2. `python src/run_full.py --max 5`  → scope → sanitize → assess (Groq) → human review → report
3. Open the HTML report (hash chain VERIFIED)
4. Tamper demo: edit line 2 of logs/audit.jsonl, verify() returns False; restore from audit.bak

Reset before each run: `cp logs/audit.bak logs/audit.jsonl`
