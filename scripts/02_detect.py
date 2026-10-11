#!/usr/bin/env python3
"""
Analyst side: run Zircolite with the project's Sigma rules on every .evtx in logs/ and write one
JSON file per log into dashboard/data/ (the dashboard reads them).

Zircolite reads the Sigma YAML folder natively (pySigma, Sysmon pipeline), no conversion step.

Install (once, analyst machine):
    git clone https://github.com/wagga40/Zircolite
    cd Zircolite && pip install .          # or use the release binary: Zircolite.exe / Zircolite

Usage:
    python scripts/02_detect.py --zircolite /path/to/Zircolite/zircolite.py
    python scripts/02_detect.py --zircolite C:\\Tools\\Zircolite.exe        # release binary
    python scripts/02_detect.py --zircolite /path/to/zircolite.py --community
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(cmd, cwd=None):
    print("\n$", " ".join(str(c) for c in cmd))
    return subprocess.run([str(c) for c in cmd], cwd=cwd).returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zircolite", required=True, help="path to zircolite.py or to the Zircolite binary")
    ap.add_argument("--logs", default=ROOT / "logs")
    ap.add_argument("--rules", default=ROOT / "sigma")
    ap.add_argument("--out", default=ROOT / "dashboard" / "data")
    ap.add_argument("--community", action="store_true",
                    help="also run Zircolite's bundled Sysmon ruleset (extra coverage, useful if a custom rule misses)")
    a = ap.parse_args()

    zir = Path(a.zircolite).resolve()
    if not zir.exists():
        sys.exit(f"Zircolite not found: {zir}")
    launcher = [sys.executable, zir] if zir.suffix == ".py" else [zir]

    logs, out, rules = Path(a.logs).resolve(), Path(a.out).resolve(), Path(a.rules).resolve()
    out.mkdir(parents=True, exist_ok=True)
    evtx_files = sorted(logs.glob("*.evtx"))
    if not evtx_files:
        sys.exit(f"No .evtx files in {logs}. Copy C:\\logs\\*.evtx from the Victim VM first.")

    for evtx in evtx_files:
        target = out / f"{evtx.stem}.json"
        target.unlink(missing_ok=True)
        run(launcher + ["-e", evtx, "-r", rules, "-p", "sysmon", "-p", "windows-logsources", "-o", target],
            cwd=zir.parent)
        print("->", target if target.exists() else "no detections written for " + evtx.name)

        if a.community:
            bundled = zir.parent / "rules" / "rules_windows_sysmon.json"
            if bundled.exists():
                t2 = out / f"{evtx.stem}__community.json"
                t2.unlink(missing_ok=True)
                run(launcher + ["-e", evtx, "-r", bundled, "-o", t2], cwd=zir.parent)
            else:
                print("Bundled ruleset not found:", bundled)

    print("\nDone. Next: python dashboard/app.py")


if __name__ == "__main__":
    main()
