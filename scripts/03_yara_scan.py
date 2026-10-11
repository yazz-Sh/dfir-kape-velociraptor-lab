#!/usr/bin/env python3
"""
Scan folders with the YARA rules and save the hits for the dashboard.

    pip install yara-python
    python scripts/03_yara_scan.py C:\\yara_test C:\\AtomicRedTeam\\atomics
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    import yara
except ImportError:
    sys.exit("Missing module: pip install yara-python")

ROOT = Path(__file__).resolve().parent.parent
MAX_SIZE = 50 * 1024 * 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="folders or files to scan")
    ap.add_argument("--rules", default=ROOT / "yara" / "dfir_rules.yar")
    ap.add_argument("--out", default=ROOT / "dashboard" / "data" / "yara_hits.json")
    a = ap.parse_args()

    rules = yara.compile(filepath=str(a.rules))
    hits, scanned = [], 0

    for p in a.paths:
        root = Path(p)
        files = [root] if root.is_file() else (f for f in root.rglob("*") if f.is_file())
        for f in files:
            try:
                if f.stat().st_size > MAX_SIZE:
                    continue
                scanned += 1
                for m in rules.match(str(f), timeout=30):
                    hits.append({
                        "rule": m.rule,
                        "file": str(f),
                        "mitre": m.meta.get("mitre", ""),
                        "severity": m.meta.get("severity", ""),
                        "description": m.meta.get("description", ""),
                        "scanned_at": datetime.now().isoformat(timespec="seconds"),
                    })
            except Exception as e:  # unreadable file, locked file, timeout...
                print("skip", f, "-", e)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(hits, fh, indent=2)
    print(f"Scanned {scanned} files, {len(hits)} hits -> {a.out}")
    for h in hits[:20]:
        print(f"  [{h['rule']}] {h['file']}")


if __name__ == "__main__":
    main()
