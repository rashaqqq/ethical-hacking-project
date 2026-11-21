# SecureScope AI

**SecureScope AI** is a scope-enforced, human-in-the-loop security assessment pipeline combining **OWASP ZAP** passive scanning, deterministic **CVSS v3.1** risk scoring, and **Groq LLM** root-cause analysis under strict security guardrails.

## Key Capabilities

* **Isolated Lab & Live Scanning (`OWASP ZAP` + `Docker`):** Supports live passive scanning (`--live`) against local lab targets (`OWASP Juice Shop`, `DVWA`) and offline replay mode (`data/findings.json`).
* **Code-Enforced Scope & Redirect Protection (`ScopeGuard` & `PolicyEngine`):** Restricts targets to `127.0.0.1` / `localhost`, disables automatic redirect following (`allow_redirects=False`), validates every `Location` hop against `ScopeGuard`, and enforces ZAP `protect` mode.
* **PII & Secret Redaction (`Sanitizer`):** Strips tokens, cookies, API keys, passwords, and sensitive identifiers from HTTP evidence before any data reaches the external LLM.
* **Evidence-Driven Root Cause & Deterministic CVSS v3.1:** Analyzes sanitized HTTP evidence inside `<data>` delimiters to identify the technical root cause and propose CVSS v3.1 vector metrics (`AV, AC, PR, UI, S, C, I, A`), while Python (`src/cvss.py`) computes the exact base score (`0.0-10.0`) deterministically.
* **Human-in-the-Loop Governance & Tamper-Evident Audit Chain:** Every finding requires explicit analyst review (`approve`, `reject`, or `modify`), and every event is recorded in `logs/audit.jsonl` using a SHA-256 hash chain (`AuditLog.verify()`).
* **Executive Security Reporting:** Generates clean HTML and Markdown reports (`reports/`) featuring severity KPIs, CVSS v3.1 vectors, root-cause explanations, remediation steps, and analyst sign-offs.

## Quick Start

```bash
git clone [https://github.com/rashaqqq/ethical-hacking-project.git](https://github.com/rashaqqq/ethical-hacking-project.git)
cd ethical-hacking-project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Add `GROQ_API_KEY=your_key` to `.env`, then run:

```bash
# Run automated tests
pytest -v

# Run live OWASP ZAP scan (requires Docker lab running)
docker compose up -d
python src/run_full.py --live --target [http://127.0.0.1:3000](http://127.0.0.1:3000) --max 5

# Run fast replay mode using saved findings
python src/run_full.py --max 5
```
