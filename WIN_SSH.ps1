# Enforce TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

function Write-Log([string]$msg, [string]$color = "Cyan") {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

# --- Account Configuration ---
$domainName  = (Get-WmiObject Win32_ComputerSystem).Domain.Split('.')[0]
$allowedUser = "Administrator"
$allowDirective = "$domainName\$allowedUser $allowedUser"

$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$build  = [System.Environment]::OSVersion.Version.Build
Write-Log "Target: $($osInfo.Caption) (Build: $build) | Domain: $domainName"

# =========================================================================
# STEP 1: Audit Backup of Existing Installation & Clean Slate
# =========================================================================
$hasCapability = $false
if (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue) {
    $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed' }
    if ($cap) { $hasCapability = $true }
}
$hasService = [bool](Get-Service -Name "sshd" -ErrorAction SilentlyContinue)
$hasFiles   = (Test-Path "$env:ProgramData\ssh") -or (Test-Path "$env:ProgramFiles\OpenSSH")

if ($hasCapability -or $hasService -or $hasFiles) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupDir = "C:\SSH_Audit_Backup_$timestamp"
    Write-Log "Existing installation found. Backing up to $backupDir..." "Yellow"
    
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

    Stop-Service -Name "sshd" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "ssh-agent" -Force -ErrorAction SilentlyContinue
    Get-Process -Name sshd, ssh-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    if (Test-Path "$env:ProgramData\ssh") {
        Copy-Item -Path "$env:ProgramData\ssh" -Destination "$backupDir\ProgramData_ssh" -Recurse -Force
    }
    if (Test-Path "$env:ProgramFiles\OpenSSH") {
        Copy-Item -Path "$env:ProgramFiles\OpenSSH" -Destination "$backupDir\ProgramFiles_OpenSSH" -Recurse -Force
    }

    Write-Log "Purging old components..." "Yellow"
    if ($hasCapability) {
        & dism.exe /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /NoRestart | Out-Null
    }
    if (Test-Path "$env:ProgramFiles\OpenSSH\uninstall-sshd.ps1") {
        powershell.exe -ExecutionPolicy Bypass -File "$env:ProgramFiles\OpenSSH\uninstall-sshd.ps1" | Out-Null
    }

    & sc.exe delete sshd | Out-Null
    & sc.exe delete ssh-agent | Out-Null

    Remove-Item -Path "$env:ProgramData\ssh" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramFiles\OpenSSH" -Recurse -Force -ErrorAction SilentlyContinue
}

# =========================================================================
# STEP 2: Fast Direct Download (Bypasses Windows Update)
# =========================================================================
Write-Log "Downloading OpenSSH directly from GitHub..."
$installDir = "$env:ProgramFiles\OpenSSH"
New-Item -ItemType Directory -Path $installDir -Force | Out-Null

$zipPath = "$env:TEMP\OpenSSH-Win64.zip"
$downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"
(New-Object System.Net.WebClient).DownloadFile($downloadUrl, $zipPath)

Write-Log "Extracting package..."
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

Write-Log "Registering SSH Service..."
Set-Location -Path $installDir
powershell.exe -ExecutionPolicy Bypass -File "$installDir\install-sshd.ps1"

# =========================================================================
# STEP 3: Setup Directory and Host Keys
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
# STEP 4: Write Hardened sshd_config (Protocol line removed)
# =========================================================================
Write-Log "Deploying hardened configuration..."
$hardenedConfig = @"
Port 22

HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# --- Cryptographic Hardening ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# --- Password-Only Authentication ---
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 1:100:1

# --- User Whitelisting ---
AllowUsers $allowDirective

# --- Anti-Pivoting / No Forwarding ---
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
# STEP 5: Apply Permissions to Keys & Config
# =========================================================================
Write-Log "Setting strict permissions on host keys and config..."
if (Test-Path "$installDir\FixHostFilePermissions.ps1") {
    powershell.exe -ExecutionPolicy Bypass -File "$installDir\FixHostFilePermissions.ps1" -Confirm:$false | Out-Null
}

# =========================================================================
# STEP 6: Firewall & Start
# =========================================================================
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"

Write-Log "SUCCESS! OpenSSH is running and fully hardened." "Green"
Write-Log "Allowed Account: $allowDirective" "Yellow"
