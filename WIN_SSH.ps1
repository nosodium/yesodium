<#
.SYNOPSIS
    Universal OpenSSH Server Installer for Windows Server (2012 R2, 2016, 2019, 2022, 2025).
.NOTES
    Must be run as an Administrator / Domain Admin.
#>

# 1. Require Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Please run this script as an Administrator."
    Exit
}

# 2. Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = 3072

# 3. Detect Operating System Version and Build
$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = $osInfo.Caption
$buildNumber = [int]$osInfo.BuildNumber

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Detected OS: $osCaption (Build: $buildNumber)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 4. Helper Function: Install via GitHub Zip (Server 2016 / 2012 R2 / Offline)
function Install-OpenSSHFromZip {
    Write-Host "[*] Installing OpenSSH via Microsoft Win32-OpenSSH package..." -ForegroundColor Yellow
    $targetDir   = "C:\Program Files\OpenSSH"
    $tempZip     = "$env:TEMP\OpenSSH-Win64.zip"
    $tempFolder  = "$env:TEMP\OpenSSH-Extract"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64.zip"

    try {
        Write-Host "    -> Downloading package..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing

        Write-Host "    -> Extracting to $targetDir..."
        if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force }
        Expand-Archive -Path $tempZip -DestinationPath $tempFolder -Force

        if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
        Copy-Item -Path "$tempFolder\OpenSSH-Win64\*" -Destination $targetDir -Recurse -Force

        Write-Host "    -> Registering services..."
        powershell.exe -ExecutionPolicy Bypass -File "$targetDir\install-sshd.ps1"

        # Add to PATH
        $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($machinePath -notlike "*$targetDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$machinePath;$targetDir", "Machine")
            $env:Path += ";$targetDir"
        }

        # Cleanup
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Write-Error "[-] Failed to install via ZIP: $_"
        return $false
    }
}

# 5. Determine Installation Route
$installedSuccessfully = $false

# Check if sshd service is already present
if (Get-Service sshd -ErrorAction SilentlyContinue) {
    Write-Host "[+] sshd service is already installed on this machine." -ForegroundColor Green
    $installedSuccessfully = $true
}
# Windows Server 2019 / 2022 / 2025 (Build 17763 or higher)
elseif ($buildNumber -ge 17763) {
    Write-Host "[*] Modern OS detected. Trying Add-WindowsCapability..." -ForegroundColor Cyan
    try {
        # Temporarily bypass WSUS if present
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 0 -ErrorAction SilentlyContinue
        Restart-Service wuauserv -ErrorAction SilentlyContinue

        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop | Out-Null
        $installedSuccessfully = $true
        Write-Host "[+] Installed successfully via Windows Capability." -ForegroundColor Green
    }
    catch {
        Write-Warning "[!] Windows Capability install failed (WSUS or offline issue). Falling back to ZIP package..."
        $installedSuccessfully = Install-OpenSSHFromZip
    }
}
# Windows Server 2016 / 2012 R2 (Build below 17763)
else {
    Write-Host "[*] Legacy OS detected (Server 2016 or earlier). Capability not supported." -ForegroundColor Yellow
    $installedSuccessfully = Install-OpenSSHFromZip
}

if (-not $installedSuccessfully) {
    Write-Error "[-] OpenSSH installation could not be completed."
    Exit
}

# ==============================================================================
# COMMON POST-INSTALL CONFIGURATION (All Server Versions)
# ==============================================================================

# 6. Windows Defender Firewall (Port 22)
Write-Host "`n[*] Configuring Windows Firewall..." -ForegroundColor Cyan
$fwRule = Get-NetFirewallRule -Name "*OpenSSH*Server*" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
                        -DisplayName "OpenSSH Server (sshd)" `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 | Out-Null
    Write-Host "[+] Created inbound firewall rule for TCP port 22." -ForegroundColor Green
} else {
    Enable-NetFirewallRule -Name $fwRule.Name | Out-Null
    Write-Host "[+] OpenSSH firewall rule is active." -ForegroundColor Green
}

# 7. Default Shell: PowerShell (instead of cmd.exe)
Write-Host "[*] Setting default shell to PowerShell..." -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\OpenSSH"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

# 8. Start & Configure Services
Write-Host "[*] Configuring and starting services..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Set-Service -Name "ssh-agent" -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue
Start-Service "ssh-agent" -ErrorAction SilentlyContinue

# 9. Configure Domain Controller Admin Key File & Permissions
Write-Host "[*] Setting up administrators_authorized_keys with strict DC ACLs..." -ForegroundColor Cyan
$sshDataDir = "$env:ProgramData\ssh"
$adminKeysFile = "$sshDataDir\administrators_authorized_keys"

if (-not (Test-Path $sshDataDir)) { New-Item -ItemType Directory -Path $sshDataDir -Force | Out-Null }
if (-not (Test-Path $adminKeysFile)) { New-Item -ItemType File -Path $adminKeysFile -Force | Out-Null }

$acl = Get-Acl $adminKeysFile
$acl.SetAccessRuleProtection($true, $false)
$adminGroup    = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # BUILTIN\Administrators
$systemAccount = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")    # NT AUTHORITY\SYSTEM
$acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, "FullControl", "Allow")))
$acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemAccount, "FullControl", "Allow")))
Set-Acl -Path $adminKeysFile -AclObject $acl

# Restart sshd to apply changes
Restart-Service sshd

Write-Host "`n================ SETUP COMPLETED ================" -ForegroundColor Green
Write-Host "[+] Service status: $((Get-Service sshd).Status)" -ForegroundColor Green
Write-Host "[+] Listening Port: 22" -ForegroundColor Green
Write-Host "[+] Default Shell:  PowerShell" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
