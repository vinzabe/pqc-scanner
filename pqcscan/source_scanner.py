"""Source-code scanner that finds classical-crypto usage.

Uses regex + lightweight AST-aware heuristics across Python, Java, Go, Rust,
C/C++, JavaScript/TypeScript. The goal is high-recall scanning; the migration
planner can de-duplicate / re-rank.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .findings import Algorithm, Finding, Severity


# Detection patterns. Each tuple: (rule_id, regex, algorithm, severity, ctx).
RULES: List[Tuple[str, re.Pattern, Algorithm, Severity, str]] = [
    # ---- RSA -----------------------------------------------------------
    ("PQ-RSA-PY-GEN",
        re.compile(r"\b(RSA\.generate|generate_private_key)\s*\(\s*(?:public_exponent\s*=\s*\d+\s*,\s*)?key_size\s*=\s*(\d+)"),
        Algorithm.RSA, Severity.HIGH,
        "Python: RSA key generation"),
    ("PQ-RSA-PY-LOAD",
        re.compile(r"\bRSA\.import_key|load_pem_private_key\b.*rsa", re.IGNORECASE),
        Algorithm.RSA, Severity.MEDIUM,
        "Python: RSA key load"),
    ("PQ-RSA-OPENSSL",
        re.compile(r"\bRSA_generate_key(?:_ex)?\s*\("),
        Algorithm.RSA, Severity.HIGH,
        "C/C++: OpenSSL RSA"),
    ("PQ-RSA-JAVA",
        re.compile(r"KeyPairGenerator\.getInstance\(\s*\"RSA\""),
        Algorithm.RSA, Severity.HIGH,
        "Java: RSA KPG"),
    ("PQ-RSA-GO",
        re.compile(r"\brsa\.GenerateKey\s*\("),
        Algorithm.RSA, Severity.HIGH,
        "Go: rsa.GenerateKey"),
    ("PQ-RSA-NODE",
        re.compile(r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]"),
        Algorithm.RSA, Severity.HIGH,
        "Node: generateKeyPair rsa"),
    ("PQ-RSA-CERT",
        re.compile(r"-----BEGIN RSA (PUBLIC|PRIVATE) KEY-----"),
        Algorithm.RSA, Severity.CRITICAL,
        "Embedded RSA key material"),

    # ---- ECDSA / ECDH --------------------------------------------------
    ("PQ-ECDSA-PY",
        re.compile(r"\bec\.generate_private_key\s*\(\s*ec\.SECP\d+R1\(\s*\)|ECDSA\.sign", re.IGNORECASE),
        Algorithm.ECDSA, Severity.HIGH,
        "Python: ECDSA"),
    ("PQ-ECDSA-OPENSSL",
        re.compile(r"\bECDSA_(do_sign|sign|verify)\b|\bEC_KEY_new_by_curve_name"),
        Algorithm.ECDSA, Severity.HIGH,
        "C/C++: ECDSA"),
    ("PQ-ECDSA-JAVA",
        re.compile(r"KeyPairGenerator\.getInstance\(\s*\"EC\""),
        Algorithm.ECDSA, Severity.HIGH,
        "Java: EC KPG"),
    ("PQ-ECDSA-GO",
        re.compile(r"\becdsa\.GenerateKey\s*\("),
        Algorithm.ECDSA, Severity.HIGH,
        "Go: ecdsa.GenerateKey"),
    ("PQ-ECDH-PY",
        re.compile(r"\.exchange\s*\(\s*ec\.ECDH\(\)"),
        Algorithm.ECDH, Severity.HIGH,
        "Python: ECDH exchange"),
    ("PQ-ECDH-OPENSSL",
        re.compile(r"\bECDH_compute_key\b"),
        Algorithm.ECDH, Severity.HIGH,
        "C/C++: ECDH"),

    # ---- DH ------------------------------------------------------------
    ("PQ-DH-PY",
        re.compile(r"\bdh\.generate_parameters\s*\(|DH\.generate"),
        Algorithm.DH, Severity.MEDIUM,
        "Python: DH"),
    ("PQ-DH-OPENSSL",
        re.compile(r"\bDH_generate_(key|parameters)\b|DH_compute_key\b"),
        Algorithm.DH, Severity.MEDIUM,
        "C/C++: DH"),

    # ---- X25519/Ed25519 ----------------------------------------------
    ("PQ-X25519",
        re.compile(r"\b(X25519PrivateKey|x25519\.GenerateKey|nacl\.box)\b"),
        Algorithm.X25519, Severity.MEDIUM,
        "X25519 key exchange"),
    ("PQ-ED25519",
        re.compile(r"\b(Ed25519PrivateKey|ed25519\.GenerateKey|nacl\.signing)\b"),
        Algorithm.ED25519, Severity.MEDIUM,
        "Ed25519 signing"),

    # ---- Legacy hashes (informational; not PQ-replaced but flagged) ----
    ("HASH-MD5",
        re.compile(r"\b(MD5\.new|hashlib\.md5|md5_init|EVP_md5)\b"),
        Algorithm.MD5, Severity.LOW,
        "Weak hash: MD5"),
    ("HASH-SHA1",
        re.compile(r"\b(SHA1\.new|hashlib\.sha1|EVP_sha1)\b"),
        Algorithm.SHA1, Severity.LOW,
        "Weak hash: SHA-1"),
]


# Files we will scan by default.
DEFAULT_INCLUDE_EXT = {
    ".py", ".pyi", ".java", ".kt", ".scala", ".go", ".rs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm",
    ".js", ".jsx", ".ts", ".tsx", ".sol",
    ".pem", ".crt", ".cer", ".key",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "build", "dist", ".tox", "target",
}


@dataclass
class SourceScanResult:
    findings: List[Finding]
    n_files_scanned: int
    n_files_skipped: int


def scan_source_file(path: str, *, max_bytes: int = 2_000_000) -> List[Finding]:
    """Scan a single source file for PQ-vulnerable crypto usage."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
    except OSError:
        return []
    # Try utf-8 -> latin-1 fallback (binary-ish files such as .pem)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")

    findings: List[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue  # Skip pathological minified lines
        for rule_id, rx, alg, sev, ctx in RULES:
            m = rx.search(line)
            if not m:
                continue
            findings.append(Finding(
                path=path, line=line_no, algorithm=alg,
                severity=sev, snippet=line.strip()[:240],
                rule_id=rule_id, confidence=1.0,
                context={"description": ctx},
            ))
    return findings


class SourceScanner:
    def __init__(self, *,
                  include_exts: Optional[set] = None,
                  exclude_dirs: Optional[set] = None,
                  max_files: int = 50_000):
        self.include_exts = set(include_exts or DEFAULT_INCLUDE_EXT)
        self.exclude_dirs = set(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
        self.max_files = max_files

    def scan(self, root: str) -> SourceScanResult:
        findings: List[Finding] = []
        scanned = 0
        skipped = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # In-place filter so os.walk skips excluded dirs.
            dirnames[:] = [d for d in dirnames if d not in self.exclude_dirs]
            for fn in filenames:
                if scanned >= self.max_files:
                    break
                ext = os.path.splitext(fn)[1].lower()
                if ext not in self.include_exts:
                    skipped += 1
                    continue
                fpath = os.path.join(dirpath, fn)
                findings.extend(scan_source_file(fpath))
                scanned += 1
        return SourceScanResult(findings=findings,
                                  n_files_scanned=scanned,
                                  n_files_skipped=skipped)
