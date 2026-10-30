# 0. Ensure script is run with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please Run as Administrator."
    exit 1
}

# Enforce TLS 1.2 for all downloads
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

function Write-Log([string]$msg, [string]$color = "Cyan") {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

# 1. Verify DC & Architecture
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$build  = [System.Environment]::OSVersion.Version.Build

Write-Log "Target: $($osInfo.Caption) (Build: $build)"
if ($osInfo.ProductType -eq 2) {
    Write-Log "Active Directory Domain Controller confirmed." "Green"
} else {
    Write-Log "Notice: Host is running as Member Server/Standalone (ProductType: $($osInfo.ProductType))." "Yellow"
}

# =========================================================================
# STEP 1: Audit Backup (Preserve existing configs & keys for triage)
# =========================================================================
$hasDataToBackup = (Test-Path "$env:ProgramData\ssh") -or (Test-Path "$env:ProgramFiles\OpenSSH")

if ($hasDataToBackup) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = "C:\SSH_Audit_Backup_$timestamp"
    Write-Log "Existing SSH files found. Creating audit backup at: $backupDir..." "Yellow"

    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    # Copy files safely without stopping anything prematurely
    if (Test-Path "$env:ProgramData\ssh") {
        Copy-Item -Path "$env:ProgramData\ssh" -Destination "$backupDir\ProgramData_ssh" -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "$env:ProgramFiles\OpenSSH") {
        Copy-Item -Path "$env:ProgramFiles\OpenSSH" -Destination "$backupDir\ProgramFiles_OpenSSH" -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Audit backup preserved successfully." "Green"
}

# =========================================================================
# STEP 2: Install OpenSSH
# =========================================================================
if ($build -ge 17763) {
    # -------------------------------------------------------------
    # Windows Server 2019 / 2022 / 2025 (Native Feature-on-Demand)
    # -------------------------------------------------------------
    Write-Log "Checking OpenSSH Server capability..."
    $capability = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }

    if ($capability.State -ne 'Installed') {
        Write-Log "Installing $($capability.Name)..."
        try {
            Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop
        } catch {
            Write-Log "Add-WindowsCapability blocked (likely WSUS GPO). Falling back to DISM..." "Yellow"
            dism /Online /Add-Capability /CapabilityName:$($capability.Name) /LimitAccess
        }
    } else {
        Write-Log "OpenSSH Server capability is already installed." "Green"
    }

} else {
    # -------------------------------------------------------------
    # Windows Server 2012 / 2012 R2 / 2016 (Win32-OpenSSH Release)
    # -------------------------------------------------------------
    Write-Log "Installing Win32-OpenSSH package for legacy server..."
    $installDir = "$env:ProgramFiles\OpenSSH"
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    $zipPath = "$env:TEMP\OpenSSH-Win64.zip"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"

    Write-Log "Downloading latest release..."
    (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $zipPath)

    Write-Log "Extracting binaries..."
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    
    foreach ($entry in $archive.Entries) {
        $relPath = ($entry.FullName -split '/', 2)[1]
        if (-not [string]::IsNullOrEmpty($relPath)) {
            $targetPath = Join-Path $installDir $relPath
            if ($entry.FullName.EndsWith('/')) {
                if (-not (Test-Path $targetPath)) { New-Item -ItemType Directory -Path $targetPath -Force | Out-Null }
            } else {
                $parentDir = Split-Path $targetPath -Parent
                if (-not (Test-Path $parentDir)) { New-Item -ItemType Directory -Path $parentDir -Force | Out-Null }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetPath, $true)
            }
        }
    }
    $archive.Dispose()
    Remove-Item -Path $zipPath -Force

    # Run official setup script
    Set-Location -Path $installDir
    powershell.exe -ExecutionPolicy Bypass -File "$installDir\install-sshd.ps1"
}

# =========================================================================
# STEP 3: Permanently Disable ssh-agent (Reduces Attack Surface)
# =========================================================================
Write-Log "Ensuring ssh-agent is disabled..."
if (Get-Service -Name "ssh-agent" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "ssh-agent" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "ssh-agent" -StartupType Disabled
}

# =========================================================================
# STEP 4: Initial Start (Seeds Native Config & Host Keys)
# =========================================================================
Write-Log "Initializing sshd service..."
Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"

# =========================================================================
# STEP 5: Open Firewall Port 22
# =========================================================================
Write-Log "Opening Firewall Port 22..."
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

# =========================================================================
# STEP 6: Apply In-Place Edits to sshd_config (Password Auth + Hardening)
# =========================================================================
Write-Log "Configuring sshd_config for Password-Only & Hardening..."
$configPath = "$env:ProgramData\ssh\sshd_config"

# Wait briefly for sshd to finish writing files
Start-Sleep -Seconds 2

if (Test-Path $configPath) {
    $content = Get-Content $configPath

    # 1. Force Password Authentication ON, Public Keys OFF
    $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    $content = $content -replace '#?KbdInteractiveAuthentication\s+(yes|no)', 'KbdInteractiveAuthentication yes'
    $content = $content -replace '#?PubkeyAuthentication\s+(yes|no)', 'PubkeyAuthentication no'

    # 2. Comment out the Match Group administrators authorized_keys directive
    $joined = $content -join "`n"
    $joined = $joined -replace 'Match Group administrators', '#Match Group administrators'
    $joined = $joined -replace 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys', '#AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'

    # 3. Append Anti-Red Team Hardening
    $hardenedBlock = @"

# --- Security Hardening ---
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no
MaxSessions 1
ClientAliveInterval 300
ClientAliveCountMax 0
MaxAuthTries 3
"@

    # Remove duplicates if re-run, then append
    $joined = $joined -replace '(?s)# --- Security Hardening ---.*', ''
    $joined += $hardenedBlock

    Set-Content -Path $configPath -Value $joined
}

# =========================================================================
# STEP 7: Restart to Apply Changes
# =========================================================================
Write-Log "Restarting sshd to apply settings..."
Restart-Service -Name "sshd"
Write-Log "OpenSSH Server Setup Complete! Ready for password login." "Green"
