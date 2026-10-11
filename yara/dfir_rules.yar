/*
  DFIR project YARA rules - file-based detections mapped to the same ATT&CK techniques
  as the Sigma rules. Scan a test folder, e.g. C:\AtomicRedTeam\atomics or C:\yara_test.
*/

rule PS_Download_Cradle
{
    meta:
        description = "PowerShell download cradle / in-memory execution"
        mitre = "T1059.001"
        severity = "medium"
    strings:
        $d1 = "DownloadString" nocase ascii wide
        $d2 = "Net.WebClient" nocase ascii wide
        $d3 = "Invoke-WebRequest" nocase ascii wide
        $e1 = "Invoke-Expression" nocase ascii wide
        $e2 = /IEX[ \(]/ nocase
    condition:
        1 of ($d*) and 1 of ($e*)
}

rule Persistence_RunKey_Script
{
    meta:
        description = "Script or .reg content writing a Run/RunOnce autostart value"
        mitre = "T1547.001"
        severity = "medium"
    strings:
        $k1 = "CurrentVersion\\Run" nocase ascii wide
        $c1 = "reg add" nocase ascii wide
        $c2 = "New-ItemProperty" nocase ascii wide
        $c3 = "Set-ItemProperty" nocase ascii wide
        $c4 = "[HKEY_" nocase ascii wide
    condition:
        $k1 and 1 of ($c*)
}

rule Persistence_ScheduledTask_Script
{
    meta:
        description = "Script creating a scheduled task"
        mitre = "T1053.005"
        severity = "medium"
    strings:
        $a = "schtasks" nocase ascii wide
        $b = "/create" nocase ascii wide
        $c = "Register-ScheduledTask" nocase ascii wide
    condition:
        ($a and $b) or $c
}

rule LSASS_Dump_Tooling
{
    meta:
        description = "References to LSASS dumping techniques"
        mitre = "T1003.001"
        severity = "high"
    strings:
        $a = "comsvcs.dll" nocase ascii wide
        $b = "MiniDump" nocase ascii wide
        $c = "procdump" nocase ascii wide
        $d = "lsass" nocase ascii wide
    condition:
        ($a and $b) or ($c and $d)
}

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz-related strings"
        mitre = "T1003.001"
        severity = "high"
    strings:
        $a = "sekurlsa::logonpasswords" nocase ascii wide
        $b = "gentilkiwi" nocase ascii wide
        $c = "mimikatz" nocase ascii wide
        $d = "Invoke-Mimikatz" nocase ascii wide
    condition:
        2 of them
}

rule Atomic_Red_Team_Marker
{
    meta:
        description = "Artifacts created by Atomic Red Team tests"
        mitre = "multiple"
        severity = "info"
    strings:
        $a = "Atomic Red Team" nocase ascii wide
        $b = "AtomicRedTeam" nocase ascii wide
    condition:
        any of them
}
