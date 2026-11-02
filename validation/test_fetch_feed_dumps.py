"""scripts/fetch-feed-dumps.sh regression gates.

2026-11-02: ThreatFox retired threatfox.abuse.ch/export/json/* (HTTP 410). The script still fetched it,
and under `set -euo pipefail` the failure aborted the run before the MalwareBazaar dump was written, so
every threatfox and malwarebazaar candidate would have come back NOT_FOUND at Gate 2b.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "fetch-feed-dumps.sh"


def test_uses_the_auth_key_threatfox_export_not_the_retired_one():
    text = SCRIPT.read_text()
    assert not re.search(r"https://threatfox\.abuse\.ch/export", text), "retired ThreatFox export URL (HTTP 410)"
    assert "https://threatfox-api.abuse.ch/v2/files/exports/${MALWAREBAZAAR_API_KEY}/full.json.zip" in text
    tracing = re.search(r"^\s*set\s+-[a-z]*x", text, re.M) or re.search(r"^#!.*\s-[a-z]*x", text)
    assert not tracing, "the ThreatFox export URL carries the Auth-Key; never trace the script"


def test_without_a_key_the_script_completes_and_writes_every_dump(tmp_path):
    stubs = tmp_path / "bin"
    stubs.mkdir()
    # `git clone ... DIR` -> an empty checkout; curl must not be reached without a key.
    for name, body in {
        "git": '#!/bin/sh\nfor last; do :; done\nmkdir -p "$last"\n',
        "curl": '#!/bin/sh\necho "curl must not run without MALWAREBAZAAR_API_KEY: $*" >&2\nexit 99\n',
    }.items():
        p = stubs / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    env = {k: v for k, v in os.environ.items() if k != "MALWAREBAZAAR_API_KEY"}
    env["PATH"] = f"{stubs}:{env['PATH']}"
    out = tmp_path / "feeds"
    r = subprocess.run(["bash", str(SCRIPT), str(out)], env=env, capture_output=True, text=True, timeout=110)
    assert r.returncode == 0, r.stderr
    assert "threatfox dump is empty" in r.stderr
    for name in ("stalkerware-indicators", "mvt-indicators", "amnesty-investigations", "prodaft-malware-ioc",
                 "zimperium-ioc", "threatfox", "malwarebazaar"):
        assert (out / f"{name}.txt").exists(), name
    assert (out / "threatfox.txt").read_text() == "## threatfox/full.jsonl\n"
