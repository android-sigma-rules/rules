#!/usr/bin/env bash
# Plain-text dumps of each mirror feed, one file per allowed-sources id.
set -euo pipefail
out="${1:?usage: fetch-feed-dumps.sh DIR}"; mkdir -p "$out"
repo="$(cd "$(dirname "$0")/.." && pwd)"   # rules repo root, independent of cwd
source "$repo/scripts/feed-dump.sh"           # cap() and dump(); unit-tested (test_check_reference.py)
tmp=$(mktemp -d)
git clone -q --depth 1 https://github.com/AssoEchap/stalkerware-indicators "$tmp/echap"
dump "$tmp/echap" \( -name '*.yaml' -o -name '*.csv' \) > "$out/stalkerware-indicators.txt"
git clone -q --depth 1 https://github.com/mvt-project/mvt-indicators "$tmp/mvt"
dump "$tmp/mvt" -name '*.stix2' > "$out/mvt-indicators.txt"
git clone -q --depth 1 https://github.com/AmnestyTech/investigations "$tmp/amnesty"
dump "$tmp/amnesty" \( -name '*.txt' -o -name '*.csv' -o -name '*.stix2' -o -name '*.json' \) > "$out/amnesty-investigations.txt"
git clone -q --depth 1 https://github.com/prodaft/malware-ioc "$tmp/prodaft"
dump "$tmp/prodaft" -name '*' > "$out/prodaft-malware-ioc.txt"
git clone -q --depth 1 https://github.com/Zimperium/IOC "$tmp/zimperium"
dump "$tmp/zimperium" -name '*' > "$out/zimperium-ioc.txt"
curl -fsSL https://threatfox.abuse.ch/export/json/full/ -o "$tmp/tf.zip"
# One record per line, so the checker's family test sees only that IOC's own malware name.
unzip -p "$tmp/tf.zip" | python3 -I -c '
import json, sys
print("## threatfox/full.jsonl")
for recs in json.load(sys.stdin).values():
    for r in (recs if isinstance(recs, list) else [recs]):
        print("| " + json.dumps(r, separators=(",", ":")))' | cap > "$out/threatfox.txt"
# MalwareBazaar needs MALWAREBAZAAR_API_KEY (204 per-hash calls). Without the key every
# malwarebazaar entry lands on the review list, so set it before running.
REPO="$repo" python3 - "$out/malwarebazaar.txt" <<'PY'
import os, sys, json, urllib.request, urllib.parse, yaml
key = os.environ.get("MALWAREBAZAAR_API_KEY")
hashes = [e["indicator"] for e in yaml.safe_load(open(os.path.join(os.environ["REPO"], "ioc-data/malware-hashes.yml")))["entries"]
          if e.get("source") == "malwarebazaar"]
with open(sys.argv[1], "w") as out:
    out.write("## malwarebazaar/get_info.jsonl\n")
    for h in hashes if key else []:
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/",
              data=urllib.parse.urlencode({"query": "get_info", "hash": h}).encode(),
              headers={"Auth-Key": key})
        for rec in json.loads(urllib.request.urlopen(req, timeout=30).read().decode()).get("data") or []:
            out.write("| " + json.dumps(rec, separators=(",", ":")) + "\n")   # one record per line
PY
rm -rf "$tmp"; ls -la "$out"
