"""Tests for the post-quantum migration scanner."""
import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from pqcscan.findings import (
    Algorithm, Finding, Severity, MigrationItem, MigrationPlan,
    PQ_VULNERABLE, PQ_REPLACEMENT,
)
from pqcscan.source_scanner import (
    SourceScanner, scan_source_file, RULES, DEFAULT_INCLUDE_EXT,
)
from pqcscan.binary_scanner import BinaryScanner, SYMBOL_MAP
from pqcscan.migration import (
    MigrationPlanner, EFFORT_HOURS_BY_ALG, SEVERITY_RANK,
)
from pqcscan.llm_advisor import (
    LLMMigrationAdvisor, MigrationAdvice, _extract_json, SYSTEM_PROMPT,
)
from pqcscan import cli as pqcli


SAMPLES = os.path.join(_HERE, "..", "samples")


def _has_sample(name):
    return os.path.exists(os.path.join(SAMPLES, name))


# ─── Findings / data classes ─────────────────────────────────────────
class TestFindings(unittest.TestCase):
    def test_severity_values(self):
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.CRITICAL.value, "critical")

    def test_algorithm_values(self):
        self.assertEqual(Algorithm.RSA.value, "rsa")
        self.assertIn(Algorithm.RSA, PQ_VULNERABLE)
        self.assertNotIn(Algorithm.MD5, PQ_VULNERABLE)

    def test_pq_replacement_table(self):
        kem, sig = PQ_REPLACEMENT[Algorithm.RSA]
        self.assertIn("Kyber", kem)
        self.assertIn("Dilithium", sig)
        kem, _ = PQ_REPLACEMENT[Algorithm.ECDH]
        self.assertIn("Kyber", kem)

    def test_finding_to_dict(self):
        f = Finding(path="p.py", line=1, algorithm=Algorithm.RSA,
                     severity=Severity.HIGH, snippet="x")
        d = f.to_dict()
        self.assertEqual(d["algorithm"], "rsa")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["path"], "p.py")


# ─── Source scanner ─────────────────────────────────────────────────
class TestSourceScanner(unittest.TestCase):
    def test_python_rsa_detect(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import rsa\n")
            f.write("k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
            p = f.name
        try:
            findings = scan_source_file(p)
            algs = {f.algorithm for f in findings}
            self.assertIn(Algorithm.RSA, algs)
            rsa_findings = [f for f in findings if f.algorithm == Algorithm.RSA]
            self.assertEqual(rsa_findings[0].severity, Severity.HIGH)
        finally:
            os.unlink(p)

    def test_python_ecdsa_detect(self):
        src = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
                 "k = ec.generate_private_key(ec.SECP256R1())\n")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.algorithm == Algorithm.ECDSA for f in findings))
        finally:
            os.unlink(p)

    def test_openssl_c_detect(self):
        src = "RSA *r = RSA_generate_key_ex(NULL, 2048, NULL, NULL);\n"
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.algorithm == Algorithm.RSA for f in findings))
        finally:
            os.unlink(p)

    def test_go_rsa(self):
        src = "k, err := rsa.GenerateKey(rand.Reader, 2048)\n"
        with tempfile.NamedTemporaryFile("w", suffix=".go", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.algorithm == Algorithm.RSA for f in findings))
        finally:
            os.unlink(p)

    def test_java_kpg(self):
        src = "KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\");\n"
        with tempfile.NamedTemporaryFile("w", suffix=".java", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.algorithm == Algorithm.RSA for f in findings))
        finally:
            os.unlink(p)

    def test_node_keygen(self):
        src = "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);\n"
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.algorithm == Algorithm.RSA for f in findings))
        finally:
            os.unlink(p)

    def test_embedded_key_pem(self):
        src = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertTrue(any(f.rule_id == "PQ-RSA-CERT" for f in findings))
            cert = [f for f in findings if f.rule_id == "PQ-RSA-CERT"][0]
            self.assertEqual(cert.severity, Severity.CRITICAL)
        finally:
            os.unlink(p)

    def test_clean_file_no_findings(self):
        src = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                 "AESGCM(key).encrypt(nonce, data, None)\n")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(src); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertEqual(findings, [])
        finally:
            os.unlink(p)

    def test_md5_sha1_detect(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("import hashlib\nh = hashlib.md5()\ns = hashlib.sha1()\n")
            p = f.name
        try:
            findings = scan_source_file(p)
            algs = {f.algorithm for f in findings}
            self.assertIn(Algorithm.MD5, algs)
            self.assertIn(Algorithm.SHA1, algs)
        finally:
            os.unlink(p)

    def test_excluded_dirs(self):
        # Build a sandbox with two .py files: one in node_modules, one not.
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "node_modules"))
            os.makedirs(os.path.join(d, "src"))
            for sub, fname in [("node_modules", "skip.py"), ("src", "keep.py")]:
                with open(os.path.join(d, sub, fname), "w") as f:
                    f.write("rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
            r = SourceScanner().scan(d)
            # Only the "src" file should contribute findings
            paths = {f.path for f in r.findings}
            self.assertTrue(any("src" in p for p in paths))
            self.assertFalse(any("node_modules" in p for p in paths))
        finally:
            import shutil
            shutil.rmtree(d)

    def test_bigfile_skip_long_lines(self):
        big = "x" * 5000 + " rsa.generate_private_key(key_size=2048)"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(big); p = f.name
        try:
            findings = scan_source_file(p)
            self.assertEqual(findings, [])
        finally:
            os.unlink(p)

    def test_missing_file_no_crash(self):
        self.assertEqual(scan_source_file("/no/such/file"), [])

    @unittest.skipUnless(_has_sample("legacy_rsa.py"), "no sample")
    def test_scan_samples_tree(self):
        r = SourceScanner().scan(SAMPLES)
        self.assertGreater(r.n_files_scanned, 1)
        self.assertGreater(len(r.findings), 0)
        algs = {f.algorithm for f in r.findings}
        self.assertIn(Algorithm.RSA, algs)


# ─── Binary scanner ─────────────────────────────────────────────────
class TestBinaryScanner(unittest.TestCase):
    @unittest.skipUnless(_has_sample("legacy_bin"), "no legacy_bin sample")
    def test_legacy_bin(self):
        r = BinaryScanner().scan_file(os.path.join(SAMPLES, "legacy_bin"))
        algs = {f.algorithm for f in r.findings}
        self.assertIn(Algorithm.RSA, algs)
        self.assertIn(Algorithm.ECDSA, algs)
        self.assertIn(Algorithm.ECDH, algs)

    def test_nonexistent(self):
        r = BinaryScanner().scan_file("/no/such/binary")
        self.assertEqual(r.findings, [])

    def test_dedup_findings(self):
        # Build a fake "binary" via raw bytes that contains a symbol twice
        b = b"\x00abcd " + b"RSA_generate_key_ex " * 4 + b"\x00abcd"
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b); p = f.name
        try:
            r = BinaryScanner().scan_file(p)
            rsa_findings = [f for f in r.findings if f.algorithm == Algorithm.RSA]
            # Must be deduped to 1 entry per (path, alg, symbol)
            self.assertEqual(len(rsa_findings), 1)
        finally:
            os.unlink(p)


# ─── Migration planner ─────────────────────────────────────────────
class TestMigrationPlanner(unittest.TestCase):
    def _findings(self, *recipe):
        out = []
        for alg, sev, count in recipe:
            for i in range(count):
                out.append(Finding(path=f"f{i}.py", line=i + 1,
                                       algorithm=alg, severity=sev))
        return out

    def test_empty_plan(self):
        plan = MigrationPlanner().build([])
        self.assertEqual(plan.total_findings, 0)
        self.assertEqual(plan.items, [])
        self.assertEqual(plan.risk_score, 0.0)

    def test_grouping(self):
        plan = MigrationPlanner().build(self._findings(
            (Algorithm.RSA, Severity.HIGH, 3),
            (Algorithm.RSA, Severity.LOW, 2),  # severity_max should remain HIGH
        ))
        self.assertEqual(plan.total_findings, 5)
        self.assertEqual(len(plan.items), 1)
        self.assertEqual(plan.items[0].n_findings, 5)
        self.assertEqual(plan.items[0].severity, Severity.HIGH)

    def test_sort_by_severity(self):
        plan = MigrationPlanner().build(self._findings(
            (Algorithm.MD5, Severity.LOW, 5),
            (Algorithm.RSA, Severity.CRITICAL, 1),
        ))
        # CRITICAL must come first
        self.assertEqual(plan.items[0].algorithm, Algorithm.RSA)
        self.assertEqual(plan.items[0].severity, Severity.CRITICAL)

    def test_effort_grows_with_count(self):
        single = MigrationPlanner().build(self._findings((Algorithm.RSA, Severity.HIGH, 1)))
        many = MigrationPlanner().build(self._findings((Algorithm.RSA, Severity.HIGH, 5)))
        self.assertGreater(many.total_effort_hours, single.total_effort_hours)

    def test_risk_score_bounded(self):
        plan = MigrationPlanner().build(self._findings(
            (Algorithm.RSA, Severity.CRITICAL, 100),
        ))
        self.assertLessEqual(plan.risk_score, 100.0)

    def test_replacement_advice(self):
        plan = MigrationPlanner().build(self._findings(
            (Algorithm.RSA, Severity.HIGH, 1)))
        self.assertIn("Kyber", plan.items[0].suggested_kem)
        self.assertIn("Dilithium", plan.items[0].suggested_signature)

    def test_effort_override(self):
        p = MigrationPlanner(effort_overrides={Algorithm.RSA: 100.0})
        plan = p.build(self._findings((Algorithm.RSA, Severity.HIGH, 1)))
        self.assertEqual(plan.items[0].effort_hours, 100.0)


# ─── LLM advisor (mocked) ──────────────────────────────────────────
class _MockResp:
    def __init__(self, content): self.content = content


class _MockLLM:
    def __init__(self, content): self._content = content
    def chat(self, messages, **kw): return _MockResp(self._content)


class _FailLLM:
    def chat(self, *a, **kw): raise ConnectionError("simulated")


class TestExtractJson(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(_extract_json('{"a": 1}'), {"a": 1})

    def test_with_fence(self):
        self.assertEqual(_extract_json('```json\n{"x": 2}\n```'), {"x": 2})

    def test_with_prefix(self):
        self.assertEqual(_extract_json('prelude {"k": "v"}'), {"k": "v"})

    def test_invalid(self):
        self.assertIsNone(_extract_json("not json"))
        self.assertIsNone(_extract_json(""))
        self.assertIsNone(_extract_json(None))


class TestLLMAdvisor(unittest.TestCase):
    def _plan(self):
        return MigrationPlanner().build([
            Finding(path="a.py", line=1, algorithm=Algorithm.RSA,
                     severity=Severity.HIGH),
            Finding(path="b.go", line=1, algorithm=Algorithm.ECDSA,
                     severity=Severity.HIGH),
        ])

    def test_happy_path(self):
        payload = json.dumps({
            "phases": [
                {"name": "discovery", "duration_weeks": 2,
                  "components": ["api"], "goals": ["inventory"]},
            ],
            "hybrid_strategy": "Use X25519+Kyber768 KEM for TLS.",
            "blockers": ["KMS rotation"],
            "residual_risks": ["HSM coverage"],
            "executive_summary": "Plan looks ok",
        })
        adv = LLMMigrationAdvisor(_MockLLM(payload)).advise(self._plan())
        self.assertIsNone(adv.error)
        self.assertEqual(len(adv.phases), 1)
        self.assertIn("Kyber", adv.hybrid_strategy)
        self.assertEqual(adv.blockers, ["KMS rotation"])

    def test_invalid_json(self):
        adv = LLMMigrationAdvisor(_MockLLM("nope")).advise(self._plan())
        self.assertIsNotNone(adv.error)

    def test_llm_error(self):
        adv = LLMMigrationAdvisor(_FailLLM()).advise(self._plan())
        self.assertIsNotNone(adv.error)
        self.assertIn("LLM error", adv.error)

    def test_str_blockers_normalised(self):
        payload = json.dumps({
            "phases": [], "hybrid_strategy": "x",
            "blockers": "just a string",
            "residual_risks": "another",
            "executive_summary": "y",
        })
        adv = LLMMigrationAdvisor(_MockLLM(payload)).advise(self._plan())
        self.assertEqual(adv.blockers, ["just a string"])
        self.assertEqual(adv.residual_risks, ["another"])

    def test_to_dict_no_raw(self):
        payload = json.dumps({
            "phases": [], "hybrid_strategy": "",
            "blockers": [], "residual_risks": [],
            "executive_summary": "",
        })
        adv = LLMMigrationAdvisor(_MockLLM(payload)).advise(self._plan())
        d = adv.to_dict()
        self.assertNotIn("raw", d)


# ─── CLI smoke ─────────────────────────────────────────────────────
class TestCLI(unittest.TestCase):
    @unittest.skipUnless(_has_sample("legacy_rsa.py"), "no sample")
    def test_scan(self):
        # Capture stdout
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pqcli.main(["scan", SAMPLES, "--findings"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertGreater(out["n_findings"], 0)
        self.assertIn("plan", out)

    @unittest.skipUnless(_has_sample("legacy_bin"), "no binary sample")
    def test_scan_binary(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pqcli.main(["scan-binary",
                               os.path.join(SAMPLES, "legacy_bin"),
                               "--findings"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertGreaterEqual(out["n_findings"], 1)


# ─── Live LLM smoke test ──────────────────────────────────────────
@unittest.skipUnless(os.environ.get("LLM_LIVE"), "LLM_LIVE not set")
class TestLLMLive(unittest.TestCase):
    def test_advise(self):
        sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))
        from llm_client import LLMClient
        plan = MigrationPlanner().build([
            Finding(path="server.py", line=10, algorithm=Algorithm.RSA,
                     severity=Severity.HIGH),
            Finding(path="auth.py",   line=22, algorithm=Algorithm.ECDSA,
                     severity=Severity.HIGH),
        ])
        adv = LLMMigrationAdvisor(LLMClient(timeout=180.0),
                                       model="glm-5.1").advise(plan)
        self.assertIsNone(adv.error, f"LLM error: {adv.error}")
        self.assertTrue(adv.executive_summary or adv.hybrid_strategy)
        print("\nLIVE advice:")
        print(f"  exec summary: {adv.executive_summary[:120]}")
        print(f"  hybrid     : {adv.hybrid_strategy[:120]}")
        print(f"  blockers   : {adv.blockers[:3]}")


if __name__ == "__main__":
    unittest.main()
