"""Post-Quantum Migration Scanner.

Scans source code and binaries for classical cryptography (RSA, ECDSA, DH, ECDH)
and produces a migration plan with Kyber/Dilithium suggestions and effort
estimates.
"""
from .findings import (
    Finding, Severity, Algorithm, MigrationPlan, MigrationItem,
)
from .source_scanner import SourceScanner, scan_source_file
from .binary_scanner import BinaryScanner
from .migration import MigrationPlanner
from .llm_advisor import LLMMigrationAdvisor, MigrationAdvice

__all__ = [
    "Finding", "Severity", "Algorithm",
    "MigrationPlan", "MigrationItem",
    "SourceScanner", "scan_source_file",
    "BinaryScanner",
    "MigrationPlanner",
    "LLMMigrationAdvisor", "MigrationAdvice",
]
