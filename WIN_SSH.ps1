# Enforce TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

function Write-Log([string]$msg, [string]$color = "Cyan") {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

# =========================================================================
# STEP 1: Audit Backup (Preserves previous files before touching anything)
# =========================================================================
if ((Test-Path "$env:ProgramData\ssh") -or (Test-Path "$env:ProgramFiles\OpenSSH")) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = "C:\SSH_Audit_Backup_$timestamp"
    Write-Log "Backing up existing SSH files to $backupDir..." "Yellow"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    if (Test-Path "$env:ProgramData\ssh") { Copy-Item -Path "$env:ProgramData\ssh" -Destination "$backupDir\ProgramData_ssh" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:ProgramFiles\OpenSSH") { Copy-Item -Path "$env:ProgramFiles\OpenSSH" -Destination "$backupDir\ProgramFiles_OpenSSH" -Recurse -Force -ErrorAction SilentlyContinue }
}

# =========================================================================
# STEP 2: Extract Clean OpenSSH Binaries
# =========================================================================
$installDir = "$env:ProgramFiles\OpenSSH"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$sshdBin = "$installDir\sshd.exe"

# If sshd.exe does not exist in Program Files, download and extract it
if (-not (Test-Path $sshdBin)) {
    Write-Log "Downloading clean OpenSSH package..." "Yellow"
    $zipPath = "$env:TEMP\OpenSSH-Win64.zip"
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip", $zipPath)

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
}

# =========================================================================
# STEP 3: Register sshd Service Directly (Bypasses Buggy install-sshd.ps1)
# =========================================================================
Write-Log "Registering sshd service directly via Service Manager..."
if (-not (Get-Service -Name "sshd" -ErrorAction SilentlyContinue)) {
    & sc.exe create sshd binPath= "`"$sshdBin`"" start= auto DisplayName= "OpenSSH SSH Server" | Out-Null
} else {
    & sc.exe config sshd binPath= "`"$sshdBin`"" start= auto | Out-Null
}

# Ensure ssh-agent is completely removed/disabled
if (Get-Service -Name "ssh-agent" -ErrorAction SilentlyContinue) {
    Stop-Service -Name "ssh-agent" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "ssh-agent" -StartupType Disabled
}

# =========================================================================
# STEP 4: Initialize Directory & Generate Host Keys
# =========================================================================
$programDataSSH = "$env:ProgramData\ssh"
$activeConfig   = "$programDataSSH\sshd_config"

if (-not (Test-Path $programDataSSH)) {
    New-Item -ItemType Directory -Path $programDataSSH -Force | Out-Null
}

$keygen = Join-Path $installDir "ssh-keygen.exe"
if (Test-Path $keygen) {
    Write-Log "Generating host keys..."
    & $keygen -A | Out-Null
}

# =========================================================================
# STEP 5: Write Hardened Configuration
# =========================================================================
Write-Log "Deploying hardened configuration..."
$hardenedConfig = @"
Port 22

# Host Keys
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# --- Authentication (Password Only) ---
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 1:100:1

# --- Account Whitelisting (Restricted to Administrators) ---
AllowGroups Administrators

# --- Anti-Pivoting / Forwarding Defense ---
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no

# --- Session Restrictions ---
MaxSessions 1
ClientAliveInterval 300
ClientAliveCountMax 0

# --- Logging ---
LogLevel VERBOSE
"@

Set-Content -Path $activeConfig -Value $hardenedConfig -Encoding UTF8

# =========================================================================
# STEP 6: Fix Permissions with Native icacls (Never Crashes on .NET Bug)
# =========================================================================
Write-Log "Applying strict permissions via native icacls..."
# Reset ProgramData\ssh permissions strictly to SYSTEM and BUILTIN\Administrators
& icacls.exe "$programDataSSH" /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" | Out-Null
& icacls.exe "$installDir" /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "BUILTIN\Users:(OI)(CI)RX" | Out-Null

# =========================================================================
# STEP 7: Firewall & Start Service
# =========================================================================
Write-Log "Configuring Windows Firewall..."
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

Write-Log "Starting sshd service..."
Set-Service -Name "sshd" -StartupType Automatic
Restart-Service -Name "sshd"

Write-Log "SUCCESS! OpenSSH is running and hardened." "Green"
Write-Log "Login Method: Password Only" "Yellow"
Write-Log "Allowed Group: BUILTIN\Administrators (Domain Admins)" "Yellow"
