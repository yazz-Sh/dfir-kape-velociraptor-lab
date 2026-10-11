#!/usr/bin/env python3
"""
Build the IOC list for the dashboard (lightweight replacement for MISP/OpenCTI).

Sources:
  1. Indicators extracted from the detections (SHA256 hashes, public IPs, DNS names, registry keys)
  2. iocs/seed_iocs.csv  (indicators you note by hand while testing)
Optional enrichment: set VT_API_KEY to look up hashes/IPs on VirusTotal (free tier: 4 requests/min).

    python scripts/04_enrich_iocs.py            # offline
    set VT_API_KEY=xxxx & python scripts/04_enrich_iocs.py   (Windows cmd)
    export VT_API_KEY=xxxx; python scripts/04_enrich_iocs.py (Linux/macOS)

Never screenshot or commit your API key.
"""
import csv
import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "dashboard" / "data"
SKIP = {"iocs.json", "yara_hits.json"}
SHA = re.compile(r"SHA256=([A-Fa-f0-9]{64})")


def load_matches():
    for p in sorted(DATA.glob("*.json")):
        if p.name in SKIP or p.name.startswith("_sample"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for rule in data:
            tags = " ".join(rule.get("tags") or [])
            mitre = ", ".join(t.upper() for t in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", tags, re.I))
            for m in rule.get("matches") or []:
                yield rule.get("title", ""), mitre, p.name, m


def public_ip(v):
    try:
        ip = ipaddress.ip_address(v)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def extract():
    found = {}

    def add(t, v, ctx, mitre, src):
        if v and (t, v) not in found:
            found[(t, v)] = {"type": t, "value": v, "context": ctx, "mitre": mitre, "source": src}

    for title, mitre, src, m in load_matches():
        h = SHA.search(str(m.get("Hashes", "")))
        if h:
            add("sha256", h.group(1).lower(), f"{m.get('Image', '')} ({title})", mitre, src)
        ip = m.get("DestinationIp")
        if ip and public_ip(str(ip)):
            add("ip", str(ip), title, mitre, src)
        if m.get("QueryName"):
            add("domain", str(m["QueryName"]), title, mitre, src)
        if m.get("TargetObject") and "\\Run" in str(m["TargetObject"]):
            add("registry", f"{m['TargetObject']} = {m.get('Details', '')}", title, mitre, src)
        if "schtasks" in str(m.get("Image", "")).lower() and m.get("CommandLine"):
            add("command", str(m["CommandLine"]), title, mitre, src)
    return list(found.values())


def seed():
    p = ROOT / "iocs" / "seed_iocs.csv"
    if not p.exists():
        return []
    with open(p, newline="", encoding="utf-8") as fh:
        return [dict(r, source="seed_iocs.csv") for r in csv.DictReader(fh)]


def vt_lookup(ioc, key):
    import requests
    kind = {"sha256": "files", "ip": "ip_addresses", "domain": "domains"}.get(ioc["type"])
    if not kind:
        return
    r = requests.get(f"https://www.virustotal.com/api/v3/{kind}/{ioc['value']}",
                     headers={"x-apikey": key}, timeout=30)
    if r.status_code == 404:
        ioc["vt"] = "not found"
    elif r.ok:
        s = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        ioc["vt"] = f"{s.get('malicious', 0)} malicious / {sum(s.values())} engines"
        ioc["vt_link"] = f"https://www.virustotal.com/gui/{'file' if kind == 'files' else kind[:-1] if kind != 'ip_addresses' else 'ip-address'}/{ioc['value']}"
    else:
        ioc["vt"] = f"error {r.status_code}"


def main():
    iocs = extract() + seed()
    key = os.environ.get("VT_API_KEY")
    if key:
        todo = [i for i in iocs if i["type"] in ("sha256", "ip", "domain")][:12]
        print(f"VirusTotal lookups: {len(todo)} (about {len(todo) * 16}s on the free tier)")
        for i in todo:
            try:
                vt_lookup(i, key)
            except Exception as e:
                i["vt"] = f"error: {e}"
            time.sleep(16)
    else:
        print("VT_API_KEY not set - offline mode (no enrichment).")

    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "iocs.json").write_text(json.dumps(iocs, indent=2), encoding="utf-8")
    print(f"{len(iocs)} IOCs -> {DATA / 'iocs.json'}")


if __name__ == "__main__":
    sys.exit(main())
