<#
.SYNOPSIS
    Installs and configures OpenSSH Server on a Windows Domain Controller.
.NOTES
    Must be run as an Administrator / Domain Admin.
#>

# 1. Verify Elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Please run this script as an Administrator."
    Exit
}

Write-Host "[*] Checking OpenSSH Server capability..." -ForegroundColor Cyan

# 2. Check and Install OpenSSH Capability
$sshCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }

if ($sshCapability.State -ne "Installed") {
    Write-Host "[*] Installing OpenSSH Server capability (this may take 1-2 minutes)..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name $sshCapability.Name | Out-Null
    Write-Host "[+] OpenSSH Server installed successfully." -ForegroundColor Green
} else {
    Write-Host "[+] OpenSSH Server is already installed." -ForegroundColor Green
}

# 3. Configure and Start Services
Write-Host "[*] Configuring sshd and ssh-agent services..." -ForegroundColor Cyan
Set-Service -Name sshd -StartupType Automatic
Set-Service -Name "ssh-agent" -StartupType Automatic

Start-Service sshd
Start-Service "ssh-agent"

# 4. Ensure Firewall Rule is Active
Write-Host "[*] Verifying Windows Defender Firewall rule for Port 22..." -ForegroundColor Cyan
$fwRule = Get-NetFirewallRule -Name "*OpenSSH-Server*" -ErrorAction SilentlyContinue

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
    Write-Host "[+] OpenSSH inbound firewall rule is enabled." -ForegroundColor Green
}

# 5. Set Default Shell to PowerShell (instead of cmd.exe)
Write-Host "[*] Configuring default shell to PowerShell..." -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\OpenSSH"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
New-ItemProperty -Path $regPath -Name "DefaultShell" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

# 6. Prepare Admin Key Directory & Ensure Correct ACLs
$sshDataDir = "$env:ProgramData\ssh"
$adminKeysFile = "$sshDataDir\administrators_authorized_keys"

if (-not (Test-Path $adminKeysFile)) {
    New-Item -ItemType File -Path $adminKeysFile -Force | Out-Null
}

# Windows OpenSSH requires strict ACLs: ONLY SYSTEM and BUILTIN\Administrators
Write-Host "[*] Applying strict ACL permissions to administrators_authorized_keys..." -ForegroundColor Cyan
$acl = Get-Acl $adminKeysFile
$acl.SetAccessRuleProtection($true, $false) # Disable inheritance and remove inherited rules

$adminGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # BUILTIN\Administrators
$systemAccount = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18") # NT AUTHORITY\SYSTEM

$ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule($adminGroup, "FullControl", "Allow")
$ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule($systemAccount, "FullControl", "Allow")

$acl.SetAccessRule($ruleAdmin)
$acl.SetAccessRule($ruleSystem)
Set-Acl -Path $adminKeysFile -AclObject $acl

# 7. Restart sshd to apply changes
Restart-Service sshd

Write-Host "`n================ SETUP COMPLETE ================" -ForegroundColor Green
Write-Host "[+] SSH listening on: port 22"
Write-Host "[+] Default Shell: PowerShell"
Write-Host "[+] Admin Key Location: $adminKeysFile"
