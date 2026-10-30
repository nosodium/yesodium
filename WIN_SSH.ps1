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
# STEP 1: Audit Backup of Old Installation
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
    Start-Sleep -Seconds 2

    if (Test-Path "$env:ProgramData\ssh") {
        Copy-Item -Path "$env:ProgramData\ssh" -Destination "$backupDir\ProgramData_ssh" -Recurse -Force
    }
    if (Test-Path "$env:ProgramFiles\OpenSSH") {
        Copy-Item -Path "$env:ProgramFiles\OpenSSH" -Destination "$backupDir\ProgramFiles_OpenSSH" -Recurse -Force
    }

    Write-Log "Purging old OpenSSH components..." "Yellow"
    if ($hasCapability) {
        Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue | Out-Null
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
# STEP 2: Clean Slate Install
# =========================================================================
$sshBinPath = ""

if ($build -ge 17763) {
    # Windows Server 2019, 2022, 2025
    Write-Log "Installing native OpenSSH Capability..."
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
    } catch {
        dism /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /LimitAccess
    }
    $sshBinPath = "$env:SystemRoot\System32\OpenSSH"
} else {
    # Windows Server 2012, 2012 R2, 2016
    Write-Log "Deploying Win32-OpenSSH package..."
    $installDir = "$env:ProgramFiles\OpenSSH"
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null

    $zipPath = "$env:TEMP\OpenSSH-Win64.zip"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"
    (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $zipPath)

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

    Set-Location -Path $installDir
    powershell.exe -ExecutionPolicy Bypass -File "$installDir\install-sshd.ps1"
    $sshBinPath = $installDir
}

# =========================================================================
# STEP 3: Setup Directory and Host Keys
# =========================================================================
$programDataSSH = "$env:ProgramData\ssh"
$activeConfig   = "$programDataSSH\sshd_config"

if (-not (Test-Path $programDataSSH)) {
    New-Item -ItemType Directory -Path $programDataSSH -Force | Out-Null
}

$keygen = Join-Path $sshBinPath "ssh-keygen.exe"
if (Test-Path $keygen) {
    Write-Log "Generating fresh host keys..."
    & $keygen -A | Out-Null
}

# =========================================================================
# STEP 4: Write Hardened sshd_config (Anti-Red Team)
# =========================================================================
Write-Log "Deploying hardened configuration to $activeConfig..."

$hardenedConfig = @"
# =====================================================
# HARDENED OPENSSH SERVER CONFIGURATION (DOMAIN CONTROLLER)
# =====================================================
Port 22
Protocol 2

# Host Key algorithms
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# --- Cryptographic Hardening (Modern Ciphers Only) ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# --- Anti-Brute Force & Authentication Controls ---
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 1:100:1

# --- User Whitelisting (Deny all except designated Admin) ---
AllowUsers $allowDirective

# --- Anti-Pivoting & Tunneling Defense ---
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no

# --- Anti-Persistence & Inactive Session Termination ---
# Single session channel per network connection
MaxSessions 1
# Drop idle sessions after 5 minutes of inactivity (300 seconds)
ClientAliveInterval 300
ClientAliveCountMax 0

# --- Forensics & Event Logging ---
LogLevel VERBOSE

# --- Payload Dropping Defense ---
# SFTP disabled to stop red teams from staging payloads/exfiltrating data
# Subsystem sftp sftp-server.exe
"@

Set-Content -Path $activeConfig -Value $hardenedConfig -Encoding UTF8

# =========================================================================
# STEP 5: Lock Down File ACLs (System & Builtin Admins Only)
# =========================================================================
Write-Log "Securing file permissions on $activeConfig..."
$acl = Get-Acl $activeConfig
$acl.SetAccessRuleProtection($true, $false) # Strip all inherited AD domain permissions

$systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18") # SYSTEM
$adminSid  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # BUILTIN\Administrators

$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")
$adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, "FullControl", "Allow")

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
Set-Acl -Path $activeConfig -AclObject $acl

# =========================================================================
# STEP 6: Firewall & Service Start
# =========================================================================
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

Set-Service -Name "sshd" -StartupType Automatic
Restart-Service -Name "sshd"

Write-Log "HARDENED SETUP COMPLETE!" "Green"
Write-Log "Allowed Account    : $allowDirective" "Yellow"
Write-Log "Port Forwarding    : BLOCKED (No pivoting/SOCKS tunnels)" "Yellow"
Write-Log "SFTP File Transfer : BLOCKED (No payload staging)" "Yellow"
Write-Log "Idle Session Drop  : 5 minutes" "Yellow"
Write-Log "Max Auth Attempts  : 3" "Yellow"
