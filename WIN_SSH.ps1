# 0. Ensure script is run with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please Run as Administrator."
    exit 1
}

Write-Host "--- Starting OpenSSH Server Setup ---" -ForegroundColor Cyan

# 1. Query and install the OpenSSH Server capability
Write-Host "Checking OpenSSH Server capability..." -ForegroundColor Yellow
$capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
# Enforce TLS 1.2 for all downloads
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "Stop"

if (-not $capability) {
    Write-Error "OpenSSH Server capability was not found on this system."
    exit 1
function Write-Log([string]$msg, [string]$color = "Cyan") {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

if ($capability.State -ne 'Installed') {
    Write-Host "Installing $($capability.Name)..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name $capability.Name
    Write-Host "OpenSSH Server installed successfully." -ForegroundColor Green
# 1. Verify DC & Architecture
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
$build  = [System.Environment]::OSVersion.Version.Build

Write-Log "Target: $($osInfo.Caption) (Build: $build)"
if ($osInfo.ProductType -eq 2) {
    Write-Log "Active Directory Domain Controller confirmed." "Green"
} else {
    Write-Host "OpenSSH Server is already installed." -ForegroundColor Green
    Write-Log "Notice: Host is running as Member Server/Standalone (ProductType: $($osInfo.ProductType))." "Yellow"
}

# 2. Configure and start the sshd service
Write-Host "Configuring 'sshd' service..." -ForegroundColor Yellow
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service -Name sshd
Write-Host "'sshd' service set to Automatic and started." -ForegroundColor Green

# 3. Check and configure the firewall rule
Write-Host "Configuring firewall rule..." -ForegroundColor Yellow
$ruleName = "OpenSSH-Server-In-TCP"

if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    Write-Host "Firewall Rule '$ruleName' does not exist, creating it..." -ForegroundColor Yellow
    New-NetFirewallRule -Name $ruleName `
                        -DisplayName 'OpenSSH Server (sshd)' `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 `
                        -Profile Any | Out-Null
    Write-Host "Firewall rule created successfully." -ForegroundColor Green
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
    Write-Host "Firewall rule '$ruleName' has been created and exists." -ForegroundColor Green
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

    Write-Log "Downloading latest release..."
    (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $zipPath)

    Write-Log "Extracting binaries..."
    # .NET 4.5+ zip extraction (natively available on Server 2012+)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    
    foreach ($entry in $archive.Entries) {
        # Strip the root directory (OpenSSH-Win64/) so files extract directly into $installDir
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

# Ensure profile is applied to Any
Set-NetFirewallRule -Name $ruleName -Profile Any
Write-Host "Firewall rule profile set to 'Any'." -ForegroundColor Green
# 3. Configure Services & Initial Start
Write-Log "Configuring sshd service..."
Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"

# 4. Open Firewall Port 22
Write-Log "Adding Port 22 to Windows Firewall..."
& netsh advfirewall firewall delete rule name="OpenSSH-Server (TCP-In)" protocol=TCP localport=22 | Out-Null
& netsh advfirewall firewall add rule name="OpenSSH-Server (TCP-In)" dir=in action=allow protocol=TCP localport=22 profile=any

# 5. Lock Down sshd_config strictly for PASSWORD authentication
Write-Log "Configuring sshd_config for password-only authentication..."
$configPath = "$env:ProgramData\ssh\sshd_config"

# Wait briefly for sshd to initialize files on first run
Start-Sleep -Seconds 2

if (Test-Path $configPath) {
    $content = Get-Content $configPath

    # Force Password Authentication on
    $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    $content = $content -replace '#?KbdInteractiveAuthentication\s+(yes|no)', 'KbdInteractiveAuthentication yes'

    # Turn off public key demand so it immediately presents the password prompt
    $content = $content -replace '#?PubkeyAuthentication\s+(yes|no)', 'PubkeyAuthentication no'

    # Disable the Match Group administrators authorized_keys directive
    $joined = $content -join "`n"
    $joined = $joined -replace 'Match Group administrators', '#Match Group administrators'
    $joined = $joined -replace 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys', '#AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'

    Set-Content -Path $configPath -Value $joined
}

Write-Host "--- OpenSSH Server Setup Complete! ---" -ForegroundColor Cyan
Restart-Service -Name "sshd"
Write-Log "Setup complete! Domain Controller is ready for password SSH login." "Green"
