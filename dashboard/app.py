"""
DFIR detections dashboard (Flask).
Reads Zircolite JSON outputs from dashboard/data/ and shows detections mapped to MITRE ATT&CK,
the enriched IOCs (data/iocs.json) and YARA hits (data/yara_hits.json).

    pip install -r dashboard/requirements.txt
    python dashboard/app.py            # http://127.0.0.1:5000
    DEMO=1 python dashboard/app.py     # also loads data/_sample_*.json (UI test only, never for the report)
"""
import glob
import json
import os
import re
from collections import Counter, defaultdict

from flask import Flask, abort, render_template, request

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
DEMO = os.environ.get("DEMO") == "1"
NON_DETECTION_FILES = {"iocs.json", "yara_hits.json"}

app = Flask(__name__)

# Techniques planned for the project (coverage panel)
PLANNED = ["T1059.001", "T1547.001", "T1053.005", "T1003.001"]
TECHNIQUES = {
    "T1059.001": "PowerShell",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1053.005": "Scheduled Task",
    "T1003.001": "LSASS Memory",
    "T1055": "Process Injection",
}
TECH_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
DETAIL_FIELDS = ["SystemTime", "UtcTime", "EventID", "Computer", "User", "Image", "ParentImage", "CommandLine",
                 "SourceImage", "TargetImage", "GrantedAccess", "TargetObject", "Details", "Hashes"]


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def load_detections():
    rows = []
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "*.json"))):
        name = os.path.basename(path)
        if name in NON_DETECTION_FILES or (name.startswith("_sample") and not DEMO):
            continue
        data = _read(path)
        if not isinstance(data, list):
            continue
        for rule in data:
            tags = rule.get("tags") or []
            techniques = sorted({m.group(1).upper() for t in tags if (m := TECH_RE.search(t))})
            tactics = [t.split(".", 1)[1].replace("_", " ").title()
                       for t in tags if t.lower().startswith("attack.") and not TECH_RE.search(t)]
            matches = rule.get("matches") or []
            first = matches[0] if matches else {}
            rows.append({
                "id": len(rows),
                "file": name,
                "title": rule.get("title", "(untitled)"),
                "description": rule.get("description", ""),
                "level": str(rule.get("rule_level", rule.get("level", "unknown"))).lower(),
                "techniques": techniques,
                "tactics": tactics,
                "count": rule.get("count", len(matches)),
                "time": first.get("SystemTime") or first.get("UtcTime") or "",
                "computer": first.get("Computer", ""),
                "image": first.get("Image") or first.get("SourceImage") or "",
                "detail": (first.get("CommandLine") or first.get("TargetObject")
                           or first.get("TargetImage") or ""),
                "matches": matches,
            })
    return rows


def load_list(filename):
    data = _read(os.path.join(DATA_DIR, filename))
    return data if isinstance(data, list) else []


@app.context_processor
def helpers():
    return {"technique_url": technique_url, "TECHNIQUES": TECHNIQUES, "demo": DEMO}


@app.route("/")
def index():
    rows = load_detections()
    q = request.args.get("q", "").strip().lower()
    tech = request.args.get("technique", "")
    level = request.args.get("level", "")
    src = request.args.get("file", "")

    shown = []
    for r in rows:
        if tech and tech not in r["techniques"]:
            continue
        if level and r["level"] != level:
            continue
        if src and r["file"] != src:
            continue
        if q and q not in " ".join([r["title"], r["description"], r["image"], r["detail"]]).lower():
            continue
        shown.append(r)
    shown.sort(key=lambda r: (-LEVEL_RANK.get(r["level"], -1), -int(r["count"] or 0)))

    events_by_tech = Counter()
    for r in rows:
        for t in r["techniques"]:
            events_by_tech[t] += int(r["count"] or 0)
    detected = set(events_by_tech)
    coverage = [{"id": t, "name": TECHNIQUES.get(t, ""), "events": events_by_tech.get(t, 0),
                 "ok": t in detected} for t in PLANNED]
    extra = [{"id": t, "name": TECHNIQUES.get(t, ""), "events": n, "ok": True}
             for t, n in events_by_tech.items() if t not in PLANNED]
    max_events = max([c["events"] for c in coverage + extra] + [1])

    return render_template(
        "index.html",
        rows=shown,
        total_rules=len(rows),
        total_events=sum(int(r["count"] or 0) for r in rows),
        by_level=Counter(r["level"] for r in rows),
        coverage=coverage + extra, planned_ok=sum(1 for c in coverage if c["ok"]), planned_total=len(coverage),
        max_events=max_events,
        all_techniques=sorted({t for r in rows for t in r["techniques"]}),
        all_files=sorted({r["file"] for r in rows}),
        all_levels=sorted({r["level"] for r in rows}, key=lambda l: -LEVEL_RANK.get(l, -1)),
        iocs=load_list("iocs.json"),
        yara=load_list("yara_hits.json"),
        filters={"q": q, "technique": tech, "level": level, "file": src},
    )


@app.route("/detection/<int:rid>")
def detection(rid):
    rows = load_detections()
    if rid < 0 or rid >= len(rows):
        abort(404)
    r = rows[rid]
    cols = [c for c in DETAIL_FIELDS if any(c in m for m in r["matches"])]
    return render_template("detail.html", r=r, cols=cols, matches=r["matches"][:200])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
