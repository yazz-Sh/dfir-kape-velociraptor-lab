#Requires -RunAsAdministrator
<#
  Run on the VICTIM VM (elevated PowerShell). Takes a snapshot BEFORE running it.
  For each technique: clear the Sysmon log, run the Atomic test(s), clean up, export the log.
  Output: C:\logs\<technique>.evtx and C:\logs\hashes.txt (SHA256 of each export = evidence integrity).

  Test numbers differ between Atomic Red Team versions. List them first, then edit $Plan below:
    Invoke-AtomicTest T1053.005 -ShowDetailsBrief
#>

$LogDir = "C:\logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$Atomics = "C:\AtomicRedTeam\atomics"

# Technique -> Atomic test numbers (edit after -ShowDetailsBrief)
$Plan = [ordered]@{
    "T1059.001" = @(4)
    "T1547.001" = @(1)
    "T1053.005" = @(1, 2)
    "T1003.001" = @(2)      # comsvcs.dll MiniDump; Defender may block it, the Sysmon events still exist
}

function Invoke-Technique {
    param([string]$Id, [int[]]$Tests)

    Write-Host "`n=== $Id ===" -ForegroundColor Cyan
    wevtutil cl Microsoft-Windows-Sysmon/Operational      # one technique per file
    Start-Sleep -Seconds 2

    foreach ($n in $Tests) {
        try {
            Invoke-AtomicTest $Id -TestNumbers $n -PathToAtomicsFolder $Atomics -GetPrereqs -ErrorAction Stop
            Invoke-AtomicTest $Id -TestNumbers $n -PathToAtomicsFolder $Atomics -ErrorAction Stop
        } catch {
            Write-Warning "Test $Id #$n failed: $($_.Exception.Message)  (screenshot this for the Difficulties section)"
        }
        Start-Sleep -Seconds 3
        try { Invoke-AtomicTest $Id -TestNumbers $n -PathToAtomicsFolder $Atomics -Cleanup -ErrorAction Stop } catch { }
    }

    # Benign fallbacks so every rule has guaranteed telemetry to hit
    switch ($Id) {
        "T1059.001" {
            $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'dfir-lab-test'"))
            powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $b64
        }
        "T1053.005" {
            schtasks /Create /SC ONCE /TN "dfir_lab_task" /TR "C:\Windows\System32\cmd.exe" /ST 23:59 /F
            schtasks /Delete /TN "dfir_lab_task" /F
        }
    }

    Start-Sleep -Seconds 3
    $out = Join-Path $LogDir "$Id.evtx"
    if (Test-Path $out) { Remove-Item $out -Force }
    wevtutil epl Microsoft-Windows-Sysmon/Operational $out
    Write-Host "Exported $out" -ForegroundColor Green
}

foreach ($id in $Plan.Keys) { Invoke-Technique -Id $id -Tests $Plan[$id] }

Get-ChildItem $LogDir\*.evtx | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $(Split-Path $_.Path -Leaf)" } | Tee-Object -FilePath "$LogDir\hashes.txt"

Write-Host "`nDone. Copy C:\logs\*.evtx to the analyst machine (project folder: logs\)." -ForegroundColor Green
