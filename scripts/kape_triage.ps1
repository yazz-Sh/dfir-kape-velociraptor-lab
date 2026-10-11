#Requires -RunAsAdministrator
<#
  KAPE triage collection on the Victim VM. Adjust $Kape to where kape.exe lives.
  Optional second stage parses the artifacts with EZ Tools (needs the modules downloaded:
  run .\Get-KAPEUpdate.ps1 once, with internet access).
#>
$Kape = "C:\Tools\KAPE"
$Dest = "C:\kape_out"
$Ts   = Get-Date -Format "yyyyMMdd_HHmmss"

New-Item -ItemType Directory -Path "$Dest\target_$Ts" -Force | Out-Null

# Stage 1: collection (SANS triage target = event logs, registry hives, prefetch, browser, etc.)
& "$Kape\kape.exe" --tsource C: --tdest "$Dest\target_$Ts" --target '!SANS_Triage' --tflush

# Stage 2 (optional): parse with EZ Tools
# & "$Kape\kape.exe" --msource "$Dest\target_$Ts" --mdest "$Dest\module_$Ts" --module '!EZParser' --mflush

Write-Host "Collection stored in $Dest\target_$Ts  (screenshot the command and the output folder)" -ForegroundColor Green
