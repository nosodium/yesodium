<#
.SYNOPSIS
    Universal OpenSSH Server Installer for Windows Server.
    No reliance on buggy OpenSSHUtils.psm1 / install-sshd.ps1.
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Please run as Administrator."
    Exit
}

[Net.ServicePointManager]::SecurityProtocol = 3072

$targetDir  = "C:\Program Files\OpenSSH"
$sshDataDir = "$env:ProgramData\ssh"

if (-not (Test-Path $targetDir))  { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
if (-not (Test-Path $sshDataDir)) { New-Item -ItemType Directory -Path $sshDataDir -Force | Out-Null }

# 1. Download and Extract binaries if not already present
if (-not (Test-Path "$targetDir\sshd.exe")) {
    $tempZip     = "$env:TEMP\OpenSSH-Win64.zip"
    $tempFolder  = "$env:TEMP\OpenSSH-Extract"
    $downloadUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.9.1.0p1-Beta/OpenSSH-Win64.zip"

    Write-Host "[*] Downloading OpenSSH binaries..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
    Expand-Archive -Path $tempZip -DestinationPath $tempFolder -Force

    $binSource = (Get-ChildItem -Path $tempFolder -Filter "sshd.exe" -Recurse | Select-Object -First 1).DirectoryName
    Copy-Item -Path "$binSource\*" -Destination $targetDir -Recurse -Force

    Remove-Item $tempZip, $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
}

# 2. Add to Machine PATH
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$targetDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$targetDir", "Machine")
    $env:Path += ";$targetDir"
}

# 3. Register Windows Services natively (Bypasses install-sshd.ps1)
Write-Host "[*] Registering services via sc.exe..." -ForegroundColor Cyan
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    sc.exe create sshd binPath= "`"$targetDir\sshd.exe`"" start= auto DisplayName= "OpenSSH SSH Server" | Out-Null
}
if (-not (Get-Service "ssh-agent" -ErrorAction SilentlyContinue)) {
    sc.exe create "ssh-agent" binPath= "`"$targetDir\ssh-agent.exe`"" start= auto DisplayName= "OpenSSH Authentication Agent" | Out-Null
}

# 4. DC Configuration: Run as LocalSystem with required privileges
sc.exe config sshd obj= "LocalSystem" | Out-Null
sc.exe privs sshd "SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege" | Out-Null
sc.exe sidtype sshd unrestricted | Out-Null

# 5. Generate Host Keys
Write-Host "[*] Generating SSH Host Keys..." -ForegroundColor Cyan
& "$targetDir\ssh-keygen.exe" -A

# 6. Enable Password Authentication in sshd_config
$configFile = "$sshDataDir\sshd_config"
if (-not (Test-Path $configFile) -and (Test-Path "$targetDir\sshd_config_default")) {
    Copy-Item "$targetDir\sshd_config_default" -Destination $configFile -Force
}

if (Test-Path $configFile) {
    $content = Get-Content $configFile
    if ($content -match 'PasswordAuthentication') {
        $content = $content -replace '#?PasswordAuthentication\s+(yes|no)', 'PasswordAuthentication yes'
    } else {
        $content += "`nPasswordAuthentication yes"
    }
    $content | Set-Content $configFile -Encoding ascii
}

# 7. Native ACL Permissions via icacls (Bypasses FixHostFilePermissions.ps1)
Write-Host "[*] Applying secure file permissions..." -ForegroundColor Cyan
if (Test-Path "$sshDataDir\logs") { Remove-Item "$sshDataDir\logs" -Recurse -Force }
icacls "$sshDataDir" /inheritance:r /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" /Q | Out-Null
icacls "$sshDataDir\*" /inheritance:r /grant "NT AUTHORITY\SYSTEM:F" /grant "BUILTIN\Administrators:F" /Q | Out-Null
icacls "$targetDir" /inheritance:r /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /grant "BUILTIN\Administrators:(OI)(CI)F" /grant "BUILTIN\Users:(OI)(CI)RX" /Q | Out-Null

# 8. Set Default Shell to PowerShell
$regPath = "HKLM:\SOFTWARE\OpenSSH"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

# 9. Firewall Rule (Port 22)
if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" `
                        -DisplayName "OpenSSH Server (sshd)" `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 | Out-Null
}

# 10. Start Services
Write-Host "[*] Starting OpenSSH services..." -ForegroundColor Cyan
Set-Service -Name "ssh-agent" -StartupType Automatic
Set-Service -Name sshd -StartupType Automatic
Start-Service "ssh-agent" -ErrorAction SilentlyContinue
Restart-Service sshd -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

Write-Host "`n================ VERIFICATION ================" -ForegroundColor Green
Get-Service sshd, "ssh-agent" | Format-Table -AutoSize
Get-NetTCPConnection -LocalPort 22 -ErrorAction SilentlyContinue | Format-Table LocalAddress, LocalPort, State, OwningProcess -AutoSize
Write-Host "[+] Complete! Connect with: ssh Administrator@<DC_IP>" -ForegroundColor Green
