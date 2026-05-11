"""LLM-driven migration advisor.

Given a migration plan, asks the LLM for:
  - phased rollout plan
  - per-team / per-component recommendations
  - hybrid-mode transition advice
  - residual-risk explanations
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .findings import MigrationItem, MigrationPlan


SYSTEM_PROMPT = """You are a senior cryptography migration consultant.

You will receive a JSON object summarising a codebase's classical crypto
usage and a draft migration plan. Produce a STRICT JSON object with the
following shape and nothing else:

{
  "phases": [
    {"name": "<phase name>",
      "duration_weeks": <int>,
      "components": ["<list>"],
      "goals": ["<list>"]}
  ],
  "hybrid_strategy": "<one paragraph>",
  "blockers": ["<short strings>"],
  "residual_risks": ["<short strings>"],
  "executive_summary": "<<= 280 chars>"
}

Be specific about hybrid X25519+Kyber768, ECDSA+ML-DSA-65 dual-signing,
and KMS rotation considerations.

Output JSON only, no prose."""


@dataclass
class MigrationAdvice:
    phases: List[Dict[str, Any]] = field(default_factory=list)
    hybrid_strategy: str = ""
    blockers: List[str] = field(default_factory=list)
    residual_risks: List[str] = field(default_factory=list)
    executive_summary: str = ""
    error: Optional[str] = None
    raw: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        return d


_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_json(blob: str) -> Optional[Dict]:
    if not blob:
        return None
    m = _FENCE.search(blob)
    if m:
        blob = m.group(1)
    blob = blob.strip()
    if not blob.startswith("{"):
        s = blob.find("{")
        e = blob.rfind("}")
        if s == -1 or e == -1 or e <= s:
            return None
        blob = blob[s:e + 1]
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


class LLMMigrationAdvisor:
    def __init__(self, llm_client, *, model: str = "glm-5.1",
                  temperature: float = 0.0, max_tokens: int = 1200):
        self.client = llm_client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    def advise(self, plan: MigrationPlan) -> MigrationAdvice:
        payload = self._build_payload(plan)
        user_msg = (
            "Here is the draft plan:\n"
            + json.dumps(payload, indent=2)
            + "\n\nProduce the migration advice JSON now."
        )
        try:
            resp = self.client.chat(
                [{"role": "system", "content": SYSTEM_PROMPT},
                 {"role": "user", "content": user_msg}],
                model=self.model, temperature=self.temperature,
                max_tokens=self.max_tokens)
            raw = resp.content if hasattr(resp, "content") else str(resp)
        except Exception as e:
            return MigrationAdvice(error=f"LLM error: {e}")

        parsed = _extract_json(raw)
        if not parsed:
            return MigrationAdvice(error="invalid JSON from model", raw=raw)
        phases = parsed.get("phases", [])
        if isinstance(phases, dict):
            phases = [phases]
        if not isinstance(phases, list):
            phases = []
        blockers = parsed.get("blockers", [])
        if isinstance(blockers, str):
            blockers = [blockers]
        rr = parsed.get("residual_risks", [])
        if isinstance(rr, str):
            rr = [rr]
        return MigrationAdvice(
            phases=phases[:10],
            hybrid_strategy=str(parsed.get("hybrid_strategy", ""))[:1200],
            blockers=[str(b)[:240] for b in blockers][:16],
            residual_risks=[str(r)[:240] for r in rr][:16],
            executive_summary=str(parsed.get("executive_summary", ""))[:300],
            raw=raw,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _build_payload(plan: MigrationPlan) -> Dict[str, Any]:
        return {
            "total_findings": plan.total_findings,
            "total_effort_hours": plan.total_effort_hours,
            "risk_score": plan.risk_score,
            "items": [
                {
                    "algorithm": i.algorithm.value,
                    "n_findings": i.n_findings,
                    "severity": i.severity.value,
                    "suggested_kem": i.suggested_kem,
                    "suggested_signature": i.suggested_signature,
                    "effort_hours": i.effort_hours,
                    "rationale": i.rationale,
                    "sample_locations": i.sample_locations[:3],
                }
                for i in plan.items[:20]
            ],
        }
