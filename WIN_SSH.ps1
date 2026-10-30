<#
.SYNOPSIS
    Installs and configures OpenSSH Server on Windows / Windows Server without modifying SSH keys.
#>

# -------------------------------------------------------------------------
# 0. Environment Setup & Pre-flight Checks
# -------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("Cyan", "Green", "Yellow", "Red", "White")]
        [string]$Color = "Cyan"
    )
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

# Ensure script is run with Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {
    Write-Error "Please run this script as an Administrator."
    exit 1
}

Write-Log "--- Starting OpenSSH Server Setup ---" "Cyan"

# -------------------------------------------------------------------------
# 1. OS & Architecture Detection
# -------------------------------------------------------------------------
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$build  = [System.Environment]::OSVersion.Version.Build

Write-Log "Target OS: $($osInfo.Caption) (Build: $build)"

if ($osInfo.ProductType -eq 2) {
    Write-Log "Active Directory Domain Controller detected." "Green"
} else {
    Write-Log "Host role: Member Server / Standalone (ProductType: $($osInfo.ProductType))." "Yellow"
}

# -------------------------------------------------------------------------
# 2. OpenSSH Installation
# -------------------------------------------------------------------------
if ($build -ge 17763) {
    # Windows 10 (1809+), Windows 11, Windows Server 2019 / 2022 / 2025
    Write-Log "Checking native OpenSSH capability..." "Yellow"
    $capability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }

    if (-not $capability) {
        Write-Error "OpenSSH Server capability was not found for this system."
        exit 1
    }

    if ($capability.State -ne "Installed") {
        Write-Log "Installing native OpenSSH Capability..." "Yellow"
        try {
            Add-WindowsCapability -Online -Name $capability.Name -ErrorAction Stop
        } catch {
            Write-Log "Add-WindowsCapability blocked (WSUS/GPO restriction). Falling back to DISM with /LimitAccess..." "Yellow"
            dism /Online /Add-Capability /CapabilityName:$($capability.Name) /LimitAccess
        }
        Write-Log "OpenSSH Server installed successfully." "Green"
    } else {
        Write-Log "OpenSSH Server capability is already installed." "Green"
    }

} else {
    # Legacy Windows Server (2012 / 2012 R2 / 2016) - Win32-OpenSSH Release
    Write-Log "Legacy Windows build detected. Installing Win32-OpenSSH package..." "Yellow"

    $installDir  = "$env:ProgramFiles\OpenSSH"
    $zipPath     = "$env:TEMP\OpenSSH-Win64.zip"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip"

    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    Write-Log "Downloading latest release package from GitHub..."
    (New-Object System.Net.WebClient).DownloadFile($downloadUrl, $zipPath)

    Write-Log "Extracting binaries into $installDir..."
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

    # Run the packaged setup script
    Set-Location -Path $installDir
    powershell.exe -ExecutionPolicy Bypass -File "$installDir\install-sshd.ps1"
}

# -------------------------------------------------------------------------
# 3. Configure and Start Services
# -------------------------------------------------------------------------
Write-Log "Configuring 'sshd' service..." "Yellow"
Set-Service -Name "sshd" -StartupType Automatic
Start-Service -Name "sshd"
Write-Log "'sshd' service set to Automatic and started." "Green"

# -------------------------------------------------------------------------
# 4. Firewall Rule Configuration (Port 22)
# -------------------------------------------------------------------------
Write-Log "Configuring firewall rule for Port 22..." "Yellow"
$ruleName = "OpenSSH-Server-In-TCP"

if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name $ruleName `
                        -DisplayName "OpenSSH Server (sshd)" `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 `
                        -Profile Any | Out-Null
    Write-Log "Firewall rule created successfully." "Green"
} else {
    Set-NetFirewallRule -Name $ruleName -Profile Any -Enabled True
    Write-Log "Existing firewall rule profile updated to 'Any'." "Green"
}

# -------------------------------------------------------------------------
# 5. Enable Password Authentication in sshd_config
# -------------------------------------------------------------------------
Write-Log "Verifying password authentication settings..." "Yellow"
$configPath = "$env:ProgramData\ssh\sshd_config"

# Wait briefly for sshd to generate initial default configuration files
Start-Sleep -Seconds 2

if (Test-Path $configPath) {
    $content = Get-Content -Path $configPath

    # Ensure password and interactive logins are permitted
    $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    $content = $content -replace '#?KbdInteractiveAuthentication\s+(yes|no)', 'KbdInteractiveAuthentication yes'

    Set-Content -Path $configPath -Value $content -Encoding UTF8
    Write-Log "sshd_config updated." "Green"
} else {
    Write-Log "Notice: sshd_config not found at $configPath (default settings in use)." "Yellow"
}

# -------------------------------------------------------------------------
# 6. Apply Changes
# -------------------------------------------------------------------------
Write-Log "Restarting 'sshd' service to apply configuration changes..." "Yellow"
Restart-Service -Name "sshd"

Write-Log "--- OpenSSH Server Setup Complete! ---" "Green"
