"""Migration planner: groups findings into recommendations w/ effort estimates."""
from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Sequence

from .findings import (
    Algorithm, Finding, MigrationItem, MigrationPlan, PQ_REPLACEMENT,
    PQ_VULNERABLE, Severity,
)


# Per-finding base hours (rough industry benchmark for swap+test).
EFFORT_HOURS_BY_ALG: Dict[Algorithm, float] = {
    Algorithm.RSA:    4.0,
    Algorithm.DSA:    4.0,
    Algorithm.ECDSA:  3.0,
    Algorithm.ECDH:   3.0,
    Algorithm.DH:     2.5,
    Algorithm.X25519: 2.0,
    Algorithm.ED25519: 2.0,
    Algorithm.MD5:    0.5,
    Algorithm.SHA1:   0.5,
}


SEVERITY_RANK = {
    Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3,
}

SEVERITY_WEIGHT = {
    Severity.LOW: 1.0, Severity.MEDIUM: 4.0,
    Severity.HIGH: 12.0, Severity.CRITICAL: 25.0,
}


class MigrationPlanner:
    def __init__(self, *,
                  effort_overrides: Dict[Algorithm, float] = None):
        self.effort: Dict[Algorithm, float] = dict(EFFORT_HOURS_BY_ALG)
        if effort_overrides:
            self.effort.update(effort_overrides)

    # --------------------------------------------------------------
    def build(self, findings: Sequence[Finding]) -> MigrationPlan:
        grouped: Dict[Algorithm, List[Finding]] = defaultdict(list)
        for f in findings:
            grouped[f.algorithm].append(f)

        items: List[MigrationItem] = []
        total_effort = 0.0
        total_risk = 0.0

        for alg, group in grouped.items():
            n = len(group)
            sev_max = max((g.severity for g in group),
                           key=lambda s: SEVERITY_RANK[s])
            # Non-linear effort: first finding full, additional 50% each
            base = self.effort.get(alg, 2.0)
            effort = base + (n - 1) * (base * 0.5) if n > 1 else base
            kem, sig = PQ_REPLACEMENT.get(alg, ("-", "-"))
            rationale = self._rationale(alg, n, sev_max, kem, sig)
            locs = sorted({f"{f.path}:{f.line}" for f in group})[:5]
            items.append(MigrationItem(
                algorithm=alg, n_findings=n, severity=sev_max,
                suggested_kem=kem, suggested_signature=sig,
                effort_hours=round(effort, 2),
                rationale=rationale,
                sample_locations=locs,
            ))
            total_effort += effort
            if alg in PQ_VULNERABLE:
                total_risk += SEVERITY_WEIGHT[sev_max] * min(n, 10)

        # Sort by severity then volume
        items.sort(key=lambda i: (-SEVERITY_RANK[i.severity], -i.n_findings))

        risk_score = min(100.0, total_risk)
        summary = self._summary(len(findings), items, risk_score)

        return MigrationPlan(
            items=items,
            total_findings=len(findings),
            total_effort_hours=round(total_effort, 2),
            risk_score=round(risk_score, 2),
            summary=summary,
        )

    # --------------------------------------------------------------
    @staticmethod
    def _rationale(alg: Algorithm, n: int, sev: Severity,
                     kem: str, sig: str) -> str:
        parts = [
            f"{n} usage(s) of {alg.value.upper()} flagged ({sev.value})."
        ]
        if alg in PQ_VULNERABLE:
            if kem and kem != "-":
                parts.append(f"Replace KEX with {kem}.")
            if sig and sig != "-":
                parts.append(f"Replace signatures with {sig}.")
            parts.append("Consider a hybrid transition (classical + PQ in parallel).")
        else:
            parts.append("Non-PQ-scope; replace with SHA-256 / SHA-3.")
        return " ".join(parts)

    @staticmethod
    def _summary(n_findings: int, items: List[MigrationItem],
                  risk: float) -> str:
        if not items:
            return ("No PQ-vulnerable cryptography detected. "
                    "Codebase looks PQ-clean per regex/symbol scan.")
        top = items[0]
        return (f"{n_findings} crypto usages across {len(items)} "
                  f"algorithm groups. Top risk: {top.algorithm.value.upper()} "
                  f"({top.n_findings} findings, severity={top.severity.value}). "
                  f"Overall risk score {risk:.1f}/100.")
