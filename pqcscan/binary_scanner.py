"""Binary scanner for PQ-vulnerable crypto symbols.

Strategy:
  1. Prefer lief if available; iterate imported_functions / symbols.
  2. Fall back to a "strings"-style scan over the raw bytes.

Both modes are cheap and run in tens of ms even on big binaries.
"""
from __future__ import annotations
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

from .findings import Algorithm, Finding, Severity


# Symbol -> (algorithm, severity, label). Order matters: most specific first.
SYMBOL_MAP = [
    # RSA
    ("RSA_generate_key_ex", Algorithm.RSA, Severity.HIGH, "OpenSSL RSA generate"),
    ("RSA_generate_key",    Algorithm.RSA, Severity.HIGH, "OpenSSL RSA generate"),
    ("RSA_public_encrypt",  Algorithm.RSA, Severity.MEDIUM, "OpenSSL RSA encrypt"),
    ("RSA_private_decrypt", Algorithm.RSA, Severity.MEDIUM, "OpenSSL RSA decrypt"),
    ("RSA_sign",            Algorithm.RSA, Severity.HIGH, "OpenSSL RSA sign"),
    ("RSA_verify",          Algorithm.RSA, Severity.MEDIUM, "OpenSSL RSA verify"),
    # ECDSA
    ("ECDSA_do_sign",       Algorithm.ECDSA, Severity.HIGH, "OpenSSL ECDSA sign"),
    ("ECDSA_sign",          Algorithm.ECDSA, Severity.HIGH, "OpenSSL ECDSA sign"),
    ("ECDSA_verify",        Algorithm.ECDSA, Severity.MEDIUM, "OpenSSL ECDSA verify"),
    ("EC_KEY_new_by_curve_name", Algorithm.ECDSA, Severity.MEDIUM, "OpenSSL EC key"),
    # ECDH
    ("ECDH_compute_key",    Algorithm.ECDH,  Severity.HIGH, "OpenSSL ECDH"),
    # DH
    ("DH_generate_key",     Algorithm.DH,    Severity.MEDIUM, "OpenSSL DH"),
    ("DH_compute_key",      Algorithm.DH,    Severity.MEDIUM, "OpenSSL DH"),
    # X25519/Ed25519 (libsodium/EVP)
    ("crypto_sign_ed25519", Algorithm.ED25519, Severity.MEDIUM, "libsodium Ed25519"),
    ("crypto_box_curve25519", Algorithm.X25519, Severity.MEDIUM, "libsodium curve25519"),
    # Hashes (informational)
    ("MD5_Init",            Algorithm.MD5,   Severity.LOW, "MD5 used"),
    ("SHA1_Init",           Algorithm.SHA1,  Severity.LOW, "SHA-1 used"),
]


_STRINGS_RX = re.compile(rb"[ -~]{4,}")


@dataclass
class BinaryScanResult:
    findings: List[Finding]
    n_symbols: int
    used_strings_fallback: bool


class BinaryScanner:
    """Scan ELF/PE/Mach-O binaries for classical-crypto symbols."""

    def __init__(self, *, max_bytes: int = 50 * 1024 * 1024):
        self.max_bytes = max_bytes

    # --------------------------------------------------------------
    def scan_file(self, path: str) -> BinaryScanResult:
        try:
            with open(path, "rb") as f:
                buf = f.read(self.max_bytes)
        except OSError:
            return BinaryScanResult(findings=[], n_symbols=0,
                                       used_strings_fallback=False)

        # Try lief first
        syms = self._symbols_via_lief(buf)
        used_fallback = False
        if syms is None:
            syms = self._symbols_via_strings(buf)
            used_fallback = True
        findings = []
        for sym in syms:
            mapped = self._classify_symbol(sym)
            if not mapped:
                continue
            alg, sev, label = mapped
            findings.append(Finding(
                path=path, line=0,
                algorithm=alg, severity=sev,
                snippet=sym, rule_id="BIN-" + alg.value.upper(),
                confidence=0.9 if not used_fallback else 0.5,
                context={"description": label,
                          "source": "lief" if not used_fallback else "strings"},
            ))
        # De-dup (path, algorithm, snippet)
        seen = set()
        deduped: List[Finding] = []
        for f in findings:
            k = (f.path, f.algorithm, f.snippet)
            if k in seen:
                continue
            seen.add(k)
            deduped.append(f)
        return BinaryScanResult(findings=deduped, n_symbols=len(syms),
                                  used_strings_fallback=used_fallback)

    # --------------------------------------------------------------
    @staticmethod
    def _classify_symbol(sym: str) -> Optional[tuple]:
        for needle, alg, sev, label in SYMBOL_MAP:
            if needle in sym:
                return (alg, sev, label)
        return None

    @staticmethod
    def _symbols_via_lief(buf: bytes) -> Optional[List[str]]:
        try:
            import lief  # type: ignore
        except Exception:
            return None
        try:
            try:
                obj = lief.parse(raw=list(buf))
            except Exception:
                import io
                obj = lief.parse(io.BytesIO(buf))
        except Exception:
            return None
        if obj is None:
            return None
        out: List[str] = []
        try:
            for f in (getattr(obj, "imported_functions", []) or []):
                name = getattr(f, "name", "") or str(f)
                if name:
                    out.append(name)
        except Exception:
            pass
        try:
            for s in (getattr(obj, "symbols", []) or [])[:50_000]:
                name = getattr(s, "name", "") or ""
                if name:
                    out.append(name)
        except Exception:
            pass
        try:
            for s in (getattr(obj, "dynamic_symbols", []) or [])[:50_000]:
                name = getattr(s, "name", "") or ""
                if name:
                    out.append(name)
        except Exception:
            pass
        return out

    @staticmethod
    def _symbols_via_strings(buf: bytes) -> List[str]:
        out: List[str] = []
        ident_rx = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,79}")
        for m in _STRINGS_RX.finditer(buf):
            try:
                s = m.group(0).decode("ascii", errors="replace")
            except Exception:
                continue
            # Each printable run may contain several identifier-like tokens
            for tok in ident_rx.findall(s):
                out.append(tok)
                if len(out) >= 200_000:
                    return out
        return out
