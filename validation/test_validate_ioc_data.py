"""Unit tests for validate-ioc-data.py hash-format rejection (AndroDR #128).

Covers the extension added in #128: structural rejection of hash IOC formats
that cannot match on-device (MD5, SHA-1 in APK context, TLSH, SHA-512, ssdeep).

Run:
    python3 -m pytest validation/test_validate_ioc_data.py -v
"""
import pathlib
import subprocess
import sys
import textwrap


THIS_DIR = pathlib.Path(__file__).parent
SCRIPT = THIS_DIR / "validate-ioc-data.py"


def run_validator(tmp_path, filename: str, body: str):
    """Write `body` to tmp_path/filename and run the validator on it."""
    p = tmp_path / filename
    p.write_text(body)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(p)],
        capture_output=True, text=True,
    )
    return result


# ---------- malware-hashes.yml (APK): SHA-256 only ----------

SHA256 = "b2be8ef1895f42981a717359ab2d263dc1351f7893ac8629ea6863dc76601d8e"
MD5    = "b4489cb4fac743246f29abf7f605dd15"
SHA1   = "774cb9a0f6593befe30469dd3b73c4064aa0fb96"
TLSH   = "t1" + "a" * 70  # 72 chars total
SHA512 = "a" * 128
SSDEEP = "3072:abc123xyz:def456uvw"


def _apk_body(indicator: str, source: str = "malwarebazaar") -> str:
    return textwrap.dedent(f"""
        version: "2026-04-16"
        description: "test"
        sources: [{source}]
        entries:
          - indicator: "{indicator}"
            family: DogfoodSpy
            category: MALWARE
            severity: HIGH
            source: {source}
    """).strip()


def _cert_body(indicator: str) -> str:
    return textwrap.dedent(f"""
        version: "2026-04-16"
        description: "test"
        sources: [stalkerware-indicators]
        entries:
          - indicator: "{indicator}"
            family: DogfoodSpy
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip()


def test_apk_sha256_accepted(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA256))
    assert r.returncode == 0, r.stderr


def test_apk_md5_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr
    assert "SHA-256" in r.stderr


def test_apk_sha1_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA1))
    assert r.returncode == 1
    assert "SHA-1 is not matched on-device" in r.stderr


def test_apk_tlsh_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(TLSH.replace("t1", "aa")))
    # TLSH detector expects 72 hex only; force all-hex for detection
    assert r.returncode == 1
    assert "TLSH" in r.stderr or "72 hex" in r.stderr


def test_apk_sha512_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SHA512))
    assert r.returncode == 1
    assert "SHA-512" in r.stderr


def test_apk_ssdeep_rejected(tmp_path):
    r = run_validator(tmp_path, "malware-hashes.yml", _apk_body(SSDEEP))
    assert r.returncode == 1
    # Either classified as ssdeep OR falls through to generic format error —
    # both are acceptable rejections.
    assert ("ssdeep" in r.stderr.lower()) or ("invalid APK hash format" in r.stderr)


def test_apk_filename_variant_apk_hashes_yml_also_strict(tmp_path):
    """apk-hashes.yml is reserved per ioc-lookup-definitions.yml — same rule."""
    r = run_validator(tmp_path, "apk-hashes.yml", _apk_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr


# ---------- cert-hashes.yml: SHA-256 OR SHA-1 accepted, MD5 rejected with clear hint ----------


def test_cert_sha256_accepted(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(SHA256))
    assert r.returncode == 0, r.stderr


def test_cert_sha1_accepted(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(SHA1))
    assert r.returncode == 0, r.stderr


def test_cert_md5_rejected_with_named_hint(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body(MD5))
    assert r.returncode == 1
    assert "likely MD5" in r.stderr
    assert "cert-hashes.yml accepts SHA-256 or SHA-1 only" in r.stderr


def test_cert_tlsh_rejected(tmp_path):
    r = run_validator(tmp_path, "cert-hashes.yml", _cert_body("a" * 72))
    assert r.returncode == 1
    assert "TLSH" in r.stderr or "72 hex" in r.stderr


# ---------- No regressions on non-hash files ----------


def test_package_names_yml_unaffected(tmp_path):
    """package-names.yml stores PACKAGE_NAME strings, not hashes — the new
    APK-hash format check must NOT fire on this file."""
    body = textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        sources: [stalkerware-indicators]
        entries:
          - indicator: com.example.spyware
            family: DogfoodSpy
            category: STALKERWARE
            severity: CRITICAL
            source: stalkerware-indicators
    """).strip()
    r = run_validator(tmp_path, "package-names.yml", body)
    assert r.returncode == 0, r.stderr


def test_c2_domains_yml_unaffected(tmp_path):
    body = textwrap.dedent("""
        version: "2026-04-16"
        description: "test"
        sources: [threatfox]
        entries:
          - indicator: c2.evil.example.com
            family: DogfoodSpy
            category: MALWARE
            severity: CRITICAL
            source: threatfox
    """).strip()
    r = run_validator(tmp_path, "c2-domains.yml", body)
    assert r.returncode == 0, r.stderr
