import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from llm_client import GroqClient
from orchestrator import run_pipeline


def cmd_check() -> int:
    llm = GroqClient()
    required_paths = [
        ROOT_DIR / "src" / "models.py",
        ROOT_DIR / "src" / "risk.py",
        ROOT_DIR / "src" / "agent.py",
        ROOT_DIR / "src" / "orchestrator.py",
    ]
    missing = [str(p.relative_to(ROOT_DIR)) for p in required_paths if not p.exists()]
    print("LLM Status:", llm.ping())
    print("Missing core files:", missing if missing else "None")
    return 1 if missing else 0


def cmd_scan(target: str, findings_file: str | None) -> int:
    report = run_pipeline(findings_file=findings_file, target=target)
    output = {
        "target": report.target,
        "notes": report.notes,
        "assessments": [
            {
                "finding_id": a.finding_id,
                "cwe_id": a.cwe_id,
                "cwe_name": a.cwe_name,
                "risk_score": a.risk_score,
                "severity": a.severity,
                "summary": a.summary,
                "remediation": a.remediation,
                "safe_verification": a.safe_verification,
            }
            for a in report.assessments
        ],
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureScope AI - Role B CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("check", help="Verify environment and core Role B files")

    scan_parser = subparsers.add_parser("scan", help="Run risk and CWE assessment pipeline")
    scan_parser.add_argument("--target", default="http://localhost:8080", help="Lab target URL/identifier")
    scan_parser.add_argument("--findings", default=None, help="Optional path to findings JSON file")

    args = parser.parse_args()
    if args.command == "check":
        return cmd_check()
    if args.command == "scan":
        return cmd_scan(target=args.target, findings_file=args.findings)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
