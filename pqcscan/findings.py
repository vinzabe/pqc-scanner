"""Finding/severity/algorithm data classes."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    LOW = "low"           # Not crypto-critical / vestigial
    MEDIUM = "medium"     # In-product but limited blast radius
    HIGH = "high"         # Authentication/signatures, broadly used
    CRITICAL = "critical" # Long-lived keys / key exchange / data at rest


class Algorithm(Enum):
    RSA = "rsa"
    DSA = "dsa"
    ECDSA = "ecdsa"
    ECDH = "ecdh"
    DH = "dh"
    MD5 = "md5"          # Hash; informational only for PQ scope
    SHA1 = "sha1"        # Hash; informational only
    X25519 = "x25519"
    ED25519 = "ed25519"  # PQ-vulnerable Ed25519 still in-scope


# PQ-vulnerable classical algorithms only. Hashes (MD5/SHA1) tracked separately.
PQ_VULNERABLE = {
    Algorithm.RSA, Algorithm.DSA, Algorithm.ECDSA, Algorithm.ECDH,
    Algorithm.DH, Algorithm.X25519, Algorithm.ED25519,
}


PQ_REPLACEMENT = {
    Algorithm.RSA:       ("ML-KEM (Kyber)", "ML-DSA (Dilithium)"),
    Algorithm.DSA:       ("-", "ML-DSA (Dilithium)"),
    Algorithm.ECDSA:     ("-", "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)"),
    Algorithm.ECDH:      ("ML-KEM (Kyber)", "-"),
    Algorithm.DH:        ("ML-KEM (Kyber)", "-"),
    Algorithm.X25519:    ("ML-KEM (Kyber)", "-"),
    Algorithm.ED25519:   ("-", "ML-DSA (Dilithium)"),
}


@dataclass
class Finding:
    """A single classical-crypto usage location."""
    path: str
    line: int
    algorithm: Algorithm
    severity: Severity
    snippet: str = ""
    rule_id: str = ""
    confidence: float = 1.0
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["algorithm"] = self.algorithm.value
        d["severity"] = self.severity.value
        return d


@dataclass
class MigrationItem:
    """One migration recommendation grouped by algorithm + location group."""
    algorithm: Algorithm
    n_findings: int
    severity: Severity
    suggested_kem: str = ""
    suggested_signature: str = ""
    effort_hours: float = 0.0
    rationale: str = ""
    sample_locations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm.value,
            "n_findings": self.n_findings,
            "severity": self.severity.value,
            "suggested_kem": self.suggested_kem,
            "suggested_signature": self.suggested_signature,
            "effort_hours": self.effort_hours,
            "rationale": self.rationale,
            "sample_locations": list(self.sample_locations),
        }


@dataclass
class MigrationPlan:
    """Full migration plan summarising findings."""
    items: List[MigrationItem]
    total_findings: int
    total_effort_hours: float
    risk_score: float                            # 0..100
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": [i.to_dict() for i in self.items],
            "total_findings": self.total_findings,
            "total_effort_hours": self.total_effort_hours,
            "risk_score": self.risk_score,
            "summary": self.summary,
        }
