# DFIR Threat Hunting and Incident Response Framework

Lab framework that chains **attack simulation, detection engineering, hunting and reporting**:

```
Atomic Red Team (Victim VM) -> Sysmon logs (.evtx) -> Sigma rules + Zircolite -> JSON detections
                                                                              -> Flask dashboard (ATT&CK mapping, IOCs, YARA)
KAPE (triage) / Velociraptor (remote hunting, VQL) / YARA (file scanning) complete the toolset.
```

| Folder | Content |
|---|---|
| `sigma/` | 5 Sigma rules for T1059.001, T1547.001, T1053.005, T1003.001 |
| `yara/` | YARA rules mapped to the same techniques |
| `scripts/` | Atomic run + log export, Zircolite runner, YARA scan, IOC enrichment, KAPE triage |
| `velociraptor/` | VQL hunts and a custom artifact |
| `dashboard/` | Flask app: detections table, filters, ATT&CK coverage, IOC and YARA panels |
| `docs/RUNBOOK.md` | Step-by-step procedure |

Techniques covered: T1059.001 PowerShell, T1547.001 Registry Run Keys, T1053.005 Scheduled Task, T1003.001 LSASS Memory.
T1055 (process injection) and MISP/OpenCTI enrichment are listed as future work.

Quick start: see `docs/RUNBOOK.md`.

Lab use only. Run simulations on an isolated Host-only VM.
