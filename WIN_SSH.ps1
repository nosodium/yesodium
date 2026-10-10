<#
.SYNOPSIS
    Universal OpenSSH Server Installer configured for PASSWORD-ONLY authentication.
.NOTES
    Must be run as Administrator / Domain Admin on any Windows Server (2012 R2 - 2025).
#>

# 1. Require Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Please run this script as an Administrator."
    Exit
}

# 2. Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = 3072

$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = $osInfo.Caption
$buildNumber = [int]$osInfo.BuildNumber

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] Target OS: $osCaption (Build: $buildNumber)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$targetDir  = "C:\Program Files\OpenSSH"
$sshDataDir = "$env:ProgramData\ssh"

# Ensure directories exist
if (-not (Test-Path $targetDir))  { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
if (-not (Test-Path $sshDataDir)) { New-Item -ItemType Directory -Path $sshDataDir -Force | Out-Null }

# 3. Installation logic
if ($buildNumber -ge 17763) {
    # Windows Server 2019 / 2022 / 2025
    Write-Host "[*] Modern OS detected. Installing via Windows Capability..." -ForegroundColor Cyan
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 0 -ErrorAction SilentlyContinue
        Restart-Service wuauserv -ErrorAction SilentlyContinue
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop | Out-Null
        Write-Host "[+] Installed via Windows Capability." -ForegroundColor Green
    }
    catch {
        Write-Warning "[!] Capability install failed. Falling back to direct binary installation..."
        $buildNumber = 0
    }
}

if ($buildNumber -lt 17763) {
    # Windows Server 2016 / 2012 R2
    Write-Host "[*] Windows Server 2016 detected. Installing OpenSSH binaries directly..." -ForegroundColor Yellow
    $tempZip    = "$env:TEMP\OpenSSH-Win64.zip"
    $tempFolder = "$env:TEMP\OpenSSH-Extract"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64.zip"

    Write-Host "    -> Downloading OpenSSH binary package..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing

    Write-Host "    -> Extracting archive..."
    if (Test-Path $tempFolder) { Remove-Item $tempFolder -Recurse -Force }
    Expand-Archive -Path $tempZip -DestinationPath $tempFolder -Force

    $sourceFiles = Get-ChildItem -Path $tempFolder -Filter "sshd.exe" -Recurse | Select-Object -First 1
    if ($sourceFiles) {
        $binDir = $sourceFiles.DirectoryName
        Copy-Item -Path "$binDir\*" -Destination $targetDir -Recurse -Force
    } else {
        Write-Error "[-] Could not locate extracted OpenSSH binaries."
        Exit
    }

    # Add to system PATH
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$targetDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$targetDir", "Machine")
        $env:Path += ";$targetDir"
    }

    # Clean up temp files
    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
    Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue

    # Directly create Windows Services
    Write-Host "    -> Registering sshd and ssh-agent services..." -ForegroundColor Cyan
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        New-Service -Name sshd -BinaryPathName "`"$targetDir\sshd.exe`"" -DisplayName "OpenSSH SSH Server" -StartupType Automatic | Out-Null
    }
    if (-not (Get-Service "ssh-agent" -ErrorAction SilentlyContinue)) {
        New-Service -Name "ssh-agent" -BinaryPathName "`"$targetDir\ssh-agent.exe`"" -DisplayName "OpenSSH Authentication Agent" -StartupType Automatic | Out-Null
    }
}

# 4. Generate SSH Host Keys
Write-Host "[*] Generating SSH Host Keys..." -ForegroundColor Cyan
$keygenPath = if (Test-Path "$targetDir\ssh-keygen.exe") { "$targetDir\ssh-keygen.exe" } else { "ssh-keygen.exe" }
& $keygenPath -A

# 5. Enable Password Authentication in sshd_config
Write-Host "[*] Configuring sshd_config for Password Authentication..." -ForegroundColor Cyan
$configFile = "$sshDataDir\sshd_config"

# If sshd_config doesn't exist yet, copy default template
if (-not (Test-Path $configFile) -and (Test-Path "$targetDir\sshd_config_default")) {
    Copy-Item "$targetDir\sshd_config_default" -Destination $configFile -Force
}

if (Test-Path $configFile) {
    $content = Get-Content $configFile
    # Ensure PasswordAuthentication is enabled
    if ($content -match 'PasswordAuthentication') {
        $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    } else {
        $content += "`nPasswordAuthentication yes"
    }
    $content | Set-Content $configFile -Encoding ascii
}

# 6. Default Shell: PowerShell
Write-Host "[*] Setting default shell to PowerShell..." -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\OpenSSH"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

# 7. Firewall Rule (Port 22)
Write-Host "[*] Ensuring Firewall allows TCP 22..." -ForegroundColor Cyan
$fwRule = Get-NetFirewallRule -Name "*OpenSSH*Server*" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
                        -DisplayName "OpenSSH Server (sshd)" `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 | Out-Null
} else {
    Enable-NetFirewallRule -Name $fwRule.Name | Out-Null
}

# 8. Start Services
Write-Host "[*] Starting OpenSSH services..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Set-Service -Name "ssh-agent" -StartupType Automatic
Start-Service "ssh-agent" -ErrorAction SilentlyContinue
Restart-Service sshd -ErrorAction SilentlyContinue

Write-Host "`n================ SETUP COMPLETED ================" -ForegroundColor Green
Write-Host "[+] Service sshd:      $((Get-Service sshd).Status)" -ForegroundColor Green
Write-Host "[+] Authentication:    PASSWORD (No SSH keys required)" -ForegroundColor Green
Write-Host "[+] Default Shell:     PowerShell" -ForegroundColor Green
Write-Host "[+] Listening Port:    22" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
