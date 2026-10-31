<#
.SYNOPSIS
    CCDC Master Blue Team Deployment & Orchestration Engine
.DESCRIPTION
    Compatible across Windows Server 2012 through 2025. Pure ASCII.
    Downloads all 8 repository scripts, backs them up locally,
    and provides a priority-ordered execution menu.
#>

$ErrorActionPreference = "SilentlyContinue"

# 1. Enforce TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2. Directories
$ScriptsDir = "C:\CCDC\Scripts"
$BackupDir  = "C:\CCDC\Scripts\Backup"

if (-not (Test-Path $ScriptsDir)) { New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null }
if (-not (Test-Path $BackupDir))  { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

Write-Output "================================================================="
Write-Output "          CCDC MASTER BLUE TEAM SCRIPT ORCHESTRATOR              "
Write-Output "================================================================="
Write-Output ("[*] Primary Directory : " + $ScriptsDir)
Write-Output ("[*] Backup Directory  : " + $BackupDir)

# 3. Target Script Manifest
$BaseUrl = "https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main"
$ScriptList = @(
    "inv.ps1",
    "pw.ps1",
    "fw.ps1",
    "harden.ps1",
    "secpol.ps1",
    "tools.ps1",
    "thrunt.ps1",
    "auditpost.ps1"
)

function Sync-ScriptsFromGitHub {
    Write-Output "`n[*] Downloading latest scripts from GitHub..."
    $webClient = New-Object System.Net.WebClient

    foreach ($scriptName in $ScriptList) {
        $sourceUrl = $BaseUrl + "/" + $scriptName + "?nocache=" + (Get-Random)
        $destPath  = Join-Path -Path $ScriptsDir -ChildPath $scriptName
        $bakPath   = Join-Path -Path $BackupDir -ChildPath $scriptName

        try {
            Write-Output ("  [>] Fetching: " + $scriptName.PadRight(16) + "...")
            $webClient.DownloadFile($sourceUrl, $destPath)
            
            if (Test-Path $destPath) {
                # Create duplicate safety backup
                Copy-Item -Path $destPath -Destination $bakPath -Force | Out-Null
                Write-Output ("      -> [OK] Saved & Backed up.")
            } else {
                Write-Output ("      -> [FAIL] File not found on disk.")
            }
        } catch {
            Write-Output ("      -> [FAIL] " + $_.Exception.Message)
        }
    }
    Write-Output "[+] Script synchronization pass completed."
}

# Run initial download on launch
Sync-ScriptsFromGitHub

# ====================================================================
# PRIORITY EXECUTION MENU
# ====================================================================

while ($true) {
    Write-Output "`n========================================================"
    Write-Output "        CCDC DEFENSIVE OPERATIONS MENU (BY PRIORITY)    "
    Write-Output "========================================================"
    Write-Output "[1] PRIORITY 1: Inventory & Baseline        (inv.ps1)"
    Write-Output "[2] PRIORITY 2: Credential Rotation         (pw.ps1)"
    Write-Output "[3] PRIORITY 3: Firewall & Port Lockdown    (fw.ps1)"
    Write-Output "[4] PRIORITY 4: AD & Exploit Hardening      (harden.ps1)"
    Write-Output "[5] PRIORITY 5: Host Policies & Telemetry   (secpol.ps1)"
    Write-Output "[6] PRIORITY 6: Post-Hardening Verification (auditpost.ps1)"
    Write-Output "--------------------------------------------------------"
    Write-Output "[7] UTILITY: Download Sysinternals Suite    (tools.ps1)"
    Write-Output "[8] UTILITY: Threat Hunting Engine          (thrunt.ps1)"
    Write-Output "[R] RE-SYNC: Refresh All Scripts from GitHub"
    Write-Output "[Q] QUIT"
    Write-Output "--------------------------------------------------------"

    $choice = Read-Host "Select a priority phase to execute [1-8, R, Q]"

    switch ($choice.ToUpper()) {
        "1" {
            if (Test-Path "$ScriptsDir\inv.ps1") { & "$ScriptsDir\inv.ps1" }
            else { Write-Output "[-] Script inv.ps1 missing." }
        }
        "2" {
            if (Test-Path "$ScriptsDir\pw.ps1") { & "$ScriptsDir\pw.ps1" }
            else { Write-Output "[-] Script pw.ps1 missing." }
        }
        "3" {
            if (Test-Path "$ScriptsDir\fw.ps1") { & "$ScriptsDir\fw.ps1" }
            else { Write-Output "[-] Script fw.ps1 missing." }
        }
        "4" {
            if (Test-Path "$ScriptsDir\harden.ps1") { & "$ScriptsDir\harden.ps1" }
            else { Write-Output "[-] Script harden.ps1 missing." }
        }
        "5" {
            if (Test-Path "$ScriptsDir\secpol.ps1") { & "$ScriptsDir\secpol.ps1" }
            else { Write-Output "[-] Script secpol.ps1 missing." }
        }
        "6" {
            if (Test-Path "$ScriptsDir\auditpost.ps1") { & "$ScriptsDir\auditpost.ps1" }
            else { Write-Output "[-] Script auditpost.ps1 missing." }
        }
        "7" {
            if (Test-Path "$ScriptsDir\tools.ps1") { & "$ScriptsDir\tools.ps1" }
            else { Write-Output "[-] Script tools.ps1 missing." }
        }
        "8" {
            if (Test-Path "$ScriptsDir\thrunt.ps1") { & "$ScriptsDir\thrunt.ps1" }
            else { Write-Output "[-] Script thrunt.ps1 missing." }
        }
        "R" {
            Sync-ScriptsFromGitHub
        }
        "Q" {
            Write-Output "Exiting Master Orchestrator."
            return
        }
        Default {
            Write-Output "[!] Invalid selection. Please enter 1-8, R, or Q."
        }
    }
}
