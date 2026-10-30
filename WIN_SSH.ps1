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
# STEP 1: Audit Backup of Old Installation & Full Purge
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

    # Stop and kill any lingering processes
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

    Write-Log "Purging old components and removing ssh-agent..." "Yellow"
    if ($hasCapability) {
        & dism.exe /Online /Remove-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /NoRestart | Out-Null
    }
    if (Test-Path "$env:ProgramFiles\OpenSSH\uninstall-sshd.ps1") {
        powershell.exe -ExecutionPolicy Bypass -File "$env:ProgramFiles\OpenSSH\uninstall-sshd.ps1" | Out-Null
    }

    # Delete both services from Service Manager
    & sc.exe delete sshd | Out-Null
    & sc.exe delete ssh-agent | Out-Null

    Remove-Item -Path "$env:ProgramData\ssh" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramFiles\OpenSSH" -Recurse -Force -ErrorAction SilentlyContinue
}

# =========================================================================
# STEP 2: Version-Specific Native Installation
# =========================================================================
$sshBinDir = ""

if ($build -ge 17763) {
    # -------------------------------------------------------------
    # Windows Server 2019 / 2022 / 2025: Native Windows Capability
    # -------------------------------------------------------------
    Write-Log "Installing native Windows OpenSSH Capability via DISM..."
    # /LimitAccess prevents hanging on WSUS/Windows Update servers
    $dismOutput = & dism.exe /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /LimitAccess
    
    # If local staging was empty, fall back to online fetch without /LimitAccess
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Local staging empty. Fetching capability online..." "Yellow"
        & dism.exe /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }

    $sshBinDir = "$env:SystemRoot\System32\OpenSSH"

    # Permanently delete ssh-agent service if created by the capability
    & sc.exe stop ssh-agent | Out-Null
    & sc.exe delete ssh-agent | Out-Null

} else {
    # -------------------------------------------------------------
    # Windows Server 2012 / 2012 R2 / 2016: Standalone Engine
    # -------------------------------------------------------------
    Write-Log "Legacy OS detected ($build). Deploying Win32-OpenSSH package..."
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

    # Register only sshd (DO NOT register ssh-agent)
    & sc.exe create sshd binPath= "$installDir\sshd.exe" start= auto DisplayName= "OpenSSH SSH Server" | Out-Null
    $sshBinDir = $installDir
}

# =========================================================================
# STEP 3: Generate Host Keys & Initialize ProgramData
# =========================================================================
$programDataSSH = "$env:ProgramData\ssh"
$activeConfig   = "$programDataSSH\sshd_config"

if (-not (Test-Path $programDataSSH)) {
    New-Item -ItemType Directory -Path $programDataSSH -Force | Out-Null
}

$keygen = Join-Path $sshBinDir "ssh-keygen.exe"
if (Test-Path $keygen) {
    Write-Log "Generating default host keys..."
    & $keygen -A | Out-Null
}

# =========================================================================
# STEP 4: Write Clean Hardened sshd_config
# =========================================================================
Write-Log "Writing clean hardened configuration to $activeConfig..."
$hardenedConfig = @"
Port 22

# Host Keys
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

# --- Cryptographic Hardening ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# --- Authentication Controls ---
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 1:100:1

# --- User Whitelist (Only Domain Admin) ---
AllowUsers $allowDirective

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
# STEP 5: Lock Down ACL Permissions
# =========================================================================
Write-Log "Securing file ACLs on keys and configuration..."
$systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18") # SYSTEM
$adminSid  = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # BUILTIN\Administrators

# Lock down all files in C:\ProgramData\ssh
Get-ChildItem -Path $programDataSSH | ForEach-Object {
    $acl = Get-Acl $_.FullName
    $acl.SetAccessRuleProtection($true, $false) # Strip inherited domain rules
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, "FullControl", "Allow")))
    Set-Acl -Path $_.FullName -AclObject $acl
}

# =========================================================================
# STEP 6: Firewall & Start Service
# =========================================================================
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"

Write-Log "SUCCESS! OpenSSH is running." "Green"
Write-Log "ssh-agent Status: COMPLETELY REMOVED (Attack surface reduced)" "Green"
Write-Log "Allowed Account : $allowDirective" "Yellow"
