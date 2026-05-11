"""CLI for PQ migration scanner."""
from __future__ import annotations
import argparse
import json
import os
import sys
from typing import Sequence

from .source_scanner import SourceScanner
from .binary_scanner import BinaryScanner
from .migration import MigrationPlanner


def _llm():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from llm_client import LLMClient
    return LLMClient(timeout=180.0)


def _cmd_scan(ns) -> int:
    scanner = SourceScanner()
    result = scanner.scan(ns.path)
    findings = result.findings
    planner = MigrationPlanner()
    plan = planner.build(findings)
    out = {
        "n_files_scanned": result.n_files_scanned,
        "n_files_skipped": result.n_files_skipped,
        "n_findings": len(findings),
        "plan": plan.to_dict(),
    }
    if ns.findings:
        out["findings"] = [f.to_dict() for f in findings[:200]]
    print(json.dumps(out, indent=2))
    return 0


def _cmd_scan_binary(ns) -> int:
    scanner = BinaryScanner()
    r = scanner.scan_file(ns.path)
    plan = MigrationPlanner().build(r.findings)
    out = {
        "path": ns.path,
        "n_symbols": r.n_symbols,
        "used_strings_fallback": r.used_strings_fallback,
        "n_findings": len(r.findings),
        "plan": plan.to_dict(),
    }
    if ns.findings:
        out["findings"] = [f.to_dict() for f in r.findings[:200]]
    print(json.dumps(out, indent=2))
    return 0


def _cmd_advise(ns) -> int:
    from .llm_advisor import LLMMigrationAdvisor
    with open(ns.plan) as f:
        plan_dict = json.load(f)
    # Rebuild a minimal MigrationPlan-shape object that the advisor accepts;
    # we go through the planner so we get all defaults consistently.
    from .findings import Algorithm, MigrationItem, MigrationPlan, Severity
    items = []
    for raw in plan_dict.get("plan", plan_dict).get("items", []):
        items.append(MigrationItem(
            algorithm=Algorithm(raw["algorithm"]),
            n_findings=int(raw["n_findings"]),
            severity=Severity(raw["severity"]),
            suggested_kem=raw.get("suggested_kem", ""),
            suggested_signature=raw.get("suggested_signature", ""),
            effort_hours=float(raw.get("effort_hours", 0)),
            rationale=raw.get("rationale", ""),
            sample_locations=raw.get("sample_locations", []),
        ))
    base = plan_dict.get("plan", plan_dict)
    plan = MigrationPlan(
        items=items,
        total_findings=int(base.get("total_findings", 0)),
        total_effort_hours=float(base.get("total_effort_hours", 0)),
        risk_score=float(base.get("risk_score", 0)),
        summary=base.get("summary", ""),
    )
    advice = LLMMigrationAdvisor(_llm()).advise(plan)
    print(json.dumps(advice.to_dict(), indent=2))
    return 0 if advice.error is None else 1


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pqcscan",
                                  description="Post-quantum migration scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan a source tree")
    sc.add_argument("path")
    sc.add_argument("--findings", action="store_true",
                     help="include raw findings list in output")
    sc.set_defaults(func=_cmd_scan)

    sb = sub.add_parser("scan-binary", help="scan a single binary")
    sb.add_argument("path")
    sb.add_argument("--findings", action="store_true")
    sb.set_defaults(func=_cmd_scan_binary)

    ad = sub.add_parser("advise", help="LLM advisor over a plan JSON file")
    ad.add_argument("--plan", required=True)
    ad.set_defaults(func=_cmd_advise)

    ns = p.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
