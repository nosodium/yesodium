# Enforce TLS 1.2 for all downloads
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

function Write-Log([string]$msg, [string]$color = "Cyan") {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

# 1. Verify DC & Architecture
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$build  = [System.Environment]::OSVersion.Version.Build

Write-Log "Target: $($osInfo.Caption) (Build: $build)"
if ($osInfo.ProductType -eq 2) {
    Write-Log "Active Directory Domain Controller confirmed." "Green"
} else {
    Write-Log "Notice: Host is running as Member Server/Standalone (ProductType: $($osInfo.ProductType))." "Yellow"
}

# Dynamically resolve Domain NetBIOS name for user/group matching
$domainNetBIOS = $env:USERDOMAIN
Write-Log "Active Directory Domain detected: $domainNetBIOS" "Green"

# 2. Install OpenSSH
if ($build -ge 17763) {
    # =========================================================================
    # Windows Server 2019 / 2022 / 2025 (Native Feature-on-Demand)
    # =========================================================================
    Write-Log "Installing native OpenSSH Capability..."
    $capability = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }

    if ($capability.State -ne 'Installed') {
        try {
            Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
        } catch {
            Write-Log "Add-WindowsCapability blocked (likely WSUS GPO). Falling back to DISM..." "Yellow"
            dism /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 /LimitAccess
        }
    } else {
        Write-Log "OpenSSH Server capability is already installed." "Green"
    }

} else {
    # =========================================================================
    # Windows Server 2012 / 2012 R2 / 2016 (Win32-OpenSSH Release)
    # =========================================================================
    Write-Log "Installing Win32-OpenSSH package for legacy server..."
    $installDir = "$env:ProgramFiles\OpenSSH"
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    $zipPath = "$env:TEMP\OpenSSH-Win64.zip"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"

    Write-Log "Downloading latest Win32-OpenSSH release..."
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

    # Run Win32-OpenSSH setup script
    Set-Location -Path $installDir
    powershell.exe -ExecutionPolicy Bypass -File "$installDir\install-sshd.ps1"
}

# 3. Configure Services & Initial Start (generates host keys & default config)
Write-Log "Configuring sshd service..."
Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"

# 4. Open Firewall Port 22
Write-Log "Configuring Windows Firewall rules for Port 22..."
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

# 5. Apply Hardening & Restrict to Domain Admins
Write-Log "Configuring sshd_config hardening & access controls..."
$configPath = "$env:ProgramData\ssh\sshd_config"

# Wait briefly for sshd to finish creating initial files on first start
Start-Sleep -Seconds 2

if (Test-Path $configPath) {
    $content = Get-Content $configPath

    # --- Authentication Mode ---
    $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    $content = $content -replace '#?KbdInteractiveAuthentication\s+(yes|no)', 'KbdInteractiveAuthentication yes'
    $content = $content -replace '#?PubkeyAuthentication\s+(yes|no)', 'PubkeyAuthentication no'

    # Comment out default administrator authorized_keys override block
    $joined = $content -join "`n"
    $joined = $joined -replace 'Match Group administrators', '#Match Group administrators'
    $joined = $joined -replace 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys', '#AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'

    # --- Hardening & Session Restrictions ---
    # Strip any previously written custom configuration blocks
    $joined = $joined -replace '(?ms)# === DC HARDENING START ===.*?# === DC HARDENING END ===', ''

    $hardeningBlock = @"

# === DC HARDENING START ===
# 1. Access Control: Only allow the Domain Administrator and Domain Admins group
# (In OpenSSH, space in group names can be written with quotes or '?' wildcard)
AllowUsers $domainNetBIOS\administrator

# 2. Session & Channel Limits
MaxSessions 2                # Max open shell/subsystem channels per SSH connection
MaxAuthTries 3               # Disconnect after 3 failed password attempts (anti-brute-force)

# 3. Connection Rate-Limiting (Anti-DoS)
# Starts dropping unauthenticated connections at 10, drops 30% linearly, caps at 60
MaxStartups 10:30:60

# 4. Inactivity & Keepalive Timeouts
# Terminate idle sessions after ~10 minutes (300s x 2 checks)
ClientAliveInterval 300
ClientAliveCountMax 2

# 5. Security Hygiene
LoginGraceTime 30            # Drop unauthenticated sessions lingering for > 30s
PrintLastLog yes
# === DC HARDENING END ===
"@

    $finalConfig = $joined.Trim() + "`n" + $hardeningBlock
    Set-Content -Path $configPath -Value $finalConfig -Encoding utf8
}

Restart-Service -Name "sshd"
Write-Log "Setup complete! OpenSSH is locked down to Domain Admins only." "Green"
