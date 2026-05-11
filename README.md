# Post-Quantum Migration Scanner

Scans codebases and binaries for classical cryptography (RSA, ECDSA, ECDH, DH, X25519/Ed25519) and produces a migration plan suggesting NIST PQC replacements (ML-KEM / Kyber and ML-DSA / Dilithium) with per-finding effort estimates. An optional LLM advisor turns the plan into a phased rollout with hybrid-mode guidance.

## Features

- **Source scanner**: regex-based detectors across Python, Java/Kotlin, Go, Rust, C/C++, JavaScript/TypeScript, Solidity, and embedded PEM keys
- **Binary scanner**: lief-based symbol introspection (ELF/PE/Mach-O) with a strings-based fallback when the binary cannot be parsed
- **Migration planner**: groups findings by algorithm, picks NIST-approved PQ replacements (ML-KEM-768 / ML-DSA-65 by default), estimates effort hours with a non-linear scaling, and produces a 0--100 risk score
- **LLM advisor**: turns the structured plan into a phased rollout (discovery -> hybrid -> cutover -> cleanup), hybrid-mode strategy (X25519+Kyber768 KEMs, dual-signing with Ed25519+ML-DSA-65), blockers, and residual risks

## Quick Start

```bash
pip install -r requirements.txt

# Scan a source tree
python -m pqcscan.cli scan /path/to/repo --findings | jq .

# Scan a binary
python -m pqcscan.cli scan-binary /usr/bin/openssl --findings

# Run the LLM advisor on a previously-generated plan
python -m pqcscan.cli advise --plan /tmp/plan.json
```

## Testing

```bash
pytest tests/ -v
LLM_LIVE=1 pytest tests/ -v
```

## Architecture

```
pqcscan/
  findings.py        - Finding, Severity, Algorithm, MigrationPlan, MigrationItem
  source_scanner.py  - SourceScanner + 18 detection rules (RULES)
  binary_scanner.py  - BinaryScanner (lief + strings fallback)
  migration.py       - MigrationPlanner (effort + risk scoring)
  llm_advisor.py     - LLMMigrationAdvisor (phased rollout JSON)
  cli.py
samples/
  legacy_rsa.py, legacy_openssl.c, legacy.go, clean.py,
  embedded_key.pem, legacy_bin
```

## Algorithm coverage

| Algorithm | Recommended KEM | Recommended Signature |
|-----------|-----------------|-----------------------|
| RSA       | ML-KEM (Kyber)  | ML-DSA (Dilithium)    |
| DSA       | -               | ML-DSA (Dilithium)    |
| ECDSA     | -               | ML-DSA / SLH-DSA      |
| ECDH      | ML-KEM (Kyber)  | -                     |
| DH        | ML-KEM (Kyber)  | -                     |
| X25519    | ML-KEM (Kyber)  | -                     |
| Ed25519   | -               | ML-DSA (Dilithium)    |

## License

MIT
