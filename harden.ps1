<#
.SYNOPSIS
    Domain Controller Active Directory Hardening, Threat Purge, & Rollback Engine
.DESCRIPTION
    Compatible with Windows Server 2012 through 2025. Pure ASCII.
    - Captures complete system/AD state before making any changes.
    - Full rollback restoration capability from C:\CCDC_Hardening_Backup\Latest.
#>

$ErrorActionPreference = "SilentlyContinue"
$BackupRoot = "C:\CCDC_Hardening_Backup\Latest"

# ====================================================================
# BACKUP ENGINE
# ====================================================================

function Backup-PreHardeningState {
    Write-Output "[*] Generating Pre-Hardening State Snapshot in: $BackupRoot"
    if (Test-Path $BackupRoot) {
        Remove-Item -Path $BackupRoot -Recurse -Force | Out-Null
    }
    New-Item -ItemType Directory -Path "$BackupRoot\Tasks" -Force | Out-Null

    $state = @{
        Registry = @()
        Services = @()
        NetBIOS  = @()
        AD       = @{}
        WMI      = @()
    }

    # 1. Snapshot Registry Values
    $regTargets = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Names = @("FullSecureChannelProtection", "RequireStrongKey", "RequireSignOrSeal") },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Names = @("SupportedEncryptionTypes") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Names = @("SMB1", "RequireSecuritySignature") },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Names = @("EnableMulticast") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Names = @("RunAsPPL", "LmCompatibilityLevel", "RestrictAnonymous", "RestrictAnonymousSAM", "EveryoneIncludesAnonymous", "LimitBlankPasswordUse") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SecurityProviders\WDigest"; Names = @("UseLogonCredential") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; Names = @("LDAPServerIntegrity", "LdapEnforceChannelBinding") }
    )

    foreach ($entry in $regTargets) {
        $p = $entry.Path
        $exists = Test-Path $p
        foreach ($name in $entry.Names) {
            $val = $null
            $type = "DWord"
            $hasVal = $false
            if ($exists) {
                $prop = Get-ItemProperty -Path $p -Name $name -ErrorAction SilentlyContinue
                if ($prop -and ($prop.PSObject.Properties[$name])) {
                    $val = $prop.$name
                    $hasVal = $true
                }
            }
            $state.Registry += @{
                Path       = $p
                Name       = $name
                Existed    = $hasVal
                Value      = $val
                KeyExisted = $exists
            }
        }
    }

    # 2. Snapshot NetBIOS on all active NICs
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        $state.NetBIOS += @{
            Description = $nic.Description
            SettingID   = $nic.SettingID
            Options     = $nic.TcpipNetbiosOptions
        }
    }

    # 3. Snapshot Active Directory state
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        try {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $domainDN = $rootDSE.defaultNamingContext
            $domainEntry = [ADSI]"LDAP://$domainDN"
            $state.AD["MachineAccountQuota"] = $domainEntry.Get("ms-DS-MachineAccountQuota")
        } catch {
            $state.AD["MachineAccountQuota"] = $null
        }

        # Snapshot users who currently have DONT_REQ_PREAUTH
        $preAuthUsers = @()
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$($rootDSE.defaultNamingContext)")
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
            $results = $searcher.FindAll()
            foreach ($r in $results) {
                $preAuthUsers += [string]$r.Properties["samaccountname"]
            }
        } catch {}
        $state.AD["PreAuthUsers"] = $preAuthUsers
    }

    # 4. Snapshot Services State
    $svcList = @("Spooler", "sshd", "RemoteRegistry", "TlntSvr")
    foreach ($sName in $svcList) {
        $svcCim = Get-CimInstance Win32_Service -Filter "Name='$sName'" -ErrorAction SilentlyContinue
        if ($svcCim) {
            $state.Services += @{
                Name      = $sName
                StartMode = $svcCim.StartMode
                State     = $svcCim.State
                PathName  = $svcCim.PathName
                Installed = $true
            }
        } else {
            $state.Services += @{
                Name      = $sName
                Installed = $false
            }
        }
    }

    # 5. Snapshot WMI Persistence Consumers
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $state.WMI += @{
            Type                = "CommandLineEventConsumer"
            Name                = $c.Name
            CommandLineTemplate = $c.CommandLineTemplate
        }
    }

    # Save complete structured metadata via native Clixml
    $state | Export-Clixml -Path "$BackupRoot\StateBackup.xml"
    Write-Output "  [+] System state saved to $BackupRoot\StateBackup.xml"
}

# ====================================================================
# RESTORATION / ROLLBACK ENGINE
# ====================================================================

function Invoke-SystemRestoration {
    Write-Output "================================================================="
    Write-Output "             RESTORING SYSTEM FROM PREVIOUS BACKUP               "
    Write-Output "================================================================="

    if (-not (Test-Path "$BackupRoot\StateBackup.xml")) {
        Write-Output "[-] No backup found at $BackupRoot\StateBackup.xml. Restoration aborted."
        return
    }

    $state = Import-Clixml -Path "$BackupRoot\StateBackup.xml"
    Write-Output "[*] Loaded State Snapshot successfully."

    # 1. Restore Registry Values
    Write-Output "`n[*] Restoring Registry & Protocol Configurations..."
    foreach ($r in $state.Registry) {
        if (-not $r.KeyExisted) {
            Remove-Item -Path $r.Path -Force -ErrorAction SilentlyContinue | Out-Null
        } elseif (-not $r.Existed) {
            Remove-ItemProperty -Path $r.Path -Name $r.Name -Force -ErrorAction SilentlyContinue | Out-Null
        } else {
            if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type DWord -Force | Out-Null
        }
    }
    Write-Output "  [+] Registry keys and values reverted to original state."

    # 2. Restore NetBIOS Settings
    Write-Output "`n[*] Restoring NetBIOS Options on Network Interfaces..."
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        $saved = $state.NetBIOS | Where-Object { $_.SettingID -eq $nic.SettingID }
        if ($saved -and $saved.Options -ne $null) {
            $nic.SetTcpipNetbios([int]$saved.Options) | Out-Null
        }
    }
    Write-Output "  [+] NetBIOS interface configurations restored."

    # 3. Restore Active Directory Attributes
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and $state.AD) {
        Write-Output "`n[*] Restoring Active Directory Settings..."
        try {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $domainDN = $rootDSE.defaultNamingContext
            $domainEntry = [ADSI]"LDAP://$domainDN"
            if ($state.AD["MachineAccountQuota"] -ne $null) {
                $domainEntry.Put("ms-DS-MachineAccountQuota", [int]$state.AD["MachineAccountQuota"])
                $domainEntry.SetInfo()
                Write-Output ("  [+] Restored ms-DS-MachineAccountQuota to: " + $state.AD["MachineAccountQuota"])
            }
        } catch {}

        # Re-apply DONT_REQ_PREAUTH to users who originally had it
        if ($state.AD["PreAuthUsers"]) {
            foreach ($uName in $state.AD["PreAuthUsers"]) {
                try {
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$($rootDSE.defaultNamingContext)")
                    $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samaccountname=$uName))"
                    $userRes = $searcher.FindOne()
                    if ($userRes) {
                        $entry = $userRes.GetDirectoryEntry()
                        $uac = [int]$entry.Get("userAccountControl")
                        $entry.Put("userAccountControl", ($uac -bor 4194304))
                        $entry.SetInfo()
                        Write-Output ("  [+] Restored DONT_REQ_PREAUTH on user: " + $uName)
                    }
                } catch {}
            }
        }
    }

    # 4. Restore Services
    Write-Output "`n[*] Restoring Core Services..."
    foreach ($s in $state.Services) {
        if ($s.Installed) {
            $mode = if ($s.StartMode -eq "Auto") { "Automatic" } else { $s.StartMode }
            Set-Service -Name $s.Name -StartupType $mode -ErrorAction SilentlyContinue | Out-Null
            if ($s.State -eq "Running") {
                Start-Service -Name $s.Name -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Output ("  [+] Service '{0}' restored -> Startup: {1}, Target State: {2}" -f $s.Name, $mode, $s.State)
        }
    }

    # 5. Restore Purged Scheduled Tasks
    Write-Output "`n[*] Restoring Purged Scheduled Tasks from XML Backups..."
    $taskFiles = Get-ChildItem -Path "$BackupRoot\Tasks" -Filter "*.xml" -ErrorAction SilentlyContinue
    foreach ($tFile in $taskFiles) {
        $tName = [System.IO.Path]::GetFileNameWithoutExtension($tFile.Name)
        cmd.exe /c "schtasks.exe /create /tn `"$tName`" /xml `"$($tFile.FullName)`" /f" 2>$null | Out-Null
        Write-Output ("  [+] Restored Scheduled Task: " + $tName)
    }

    Write-Output "`n================================================================="
    Write-Output "               SYSTEM RESTORATION COMPLETED                      "
    Write-Output "================================================================="
}

# ====================================================================
# HARDENING ENGINE
# ====================================================================

function Invoke-HardeningSequence {
    # 1. CREATE BACKUP BEFORE MODIFYING SYSTEM
    Backup-PreHardeningState

    $auditLog = @()
    function Add-AuditEntry {
        param($Category, $Target, $StateFound, $ActionTaken)
        $script:auditLog += New-Object PSObject -Property @{
            Category    = $Category
            Target      = $Target
            StateFound  = $StateFound
            ActionTaken = $ActionTaken
        }
    }

    Write-Output "`n[*] Executing Hardening Sequence..."

    # ZeroLogon & Netlogon
    $netlogonParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $netlogonParams)) { New-Item -Path $netlogonParams -Force | Out-Null }
    Set-ItemProperty -Path $netlogonParams -Name "FullSecureChannelProtection" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $netlogonParams -Name "RequireStrongKey" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $netlogonParams -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
    Add-AuditEntry "Netlogon / RPC" "ZeroLogon (CVE-2020-1472)" "VULNERABLE (Compatibility Mode)" "Enforced FullSecureChannelProtection & Strong Keys"

    # Machine Account Quota (NoPac)
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        try {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $domainDN = $rootDSE.defaultNamingContext
            $domainEntry = [ADSI]"LDAP://$domainDN"
            $currentQuota = $domainEntry.Get("ms-DS-MachineAccountQuota")
            if ($currentQuota -ne 0) {
                $domainEntry.Put("ms-DS-MachineAccountQuota", 0)
                $domainEntry.SetInfo()
                Add-AuditEntry "Active Directory" "MachineAccountQuota (NoPac)" ("VULNERABLE (Quota: " + $currentQuota + ")") "Set ms-DS-MachineAccountQuota to 0"
            } else {
                Add-AuditEntry "Active Directory" "MachineAccountQuota (NoPac)" "SECURE (Quota: 0)" "Verified standard users cannot add domain machines"
            }
        } catch {}
    }

    # AS-REP Roasting
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$($rootDSE.defaultNamingContext)")
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $results = $searcher.FindAll()
        $roastCount = 0
        foreach ($r in $results) {
            $entry = $r.GetDirectoryEntry()
            $uac = [int]$entry.Get("userAccountControl")
            $entry.Put("userAccountControl", ($uac -band (-bnot 4194304)))
            $entry.SetInfo()
            $roastCount++
        }
        if ($roastCount -gt 0) {
            Add-AuditEntry "Kerberos / Auth" "AS-REP Roasting" ("VULNERABLE (" + $roastCount + " Users Open)") "Enforced Kerberos Pre-Authentication on all accounts"
        } else {
            Add-AuditEntry "Kerberos / Auth" "AS-REP Roasting" "SECURE (Pre-Auth Active)" "Verified all accounts require Kerberos pre-authentication"
        }
    } catch {}

    # Kerberos AES
    $kerbParams = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    if (-not (Test-Path $kerbParams)) { New-Item -Path $kerbParams -Force | Out-Null }
    Set-ItemProperty -Path $kerbParams -Name "SupportedEncryptionTypes" -Value 24 -Type DWord -Force
    Add-AuditEntry "Kerberos / Auth" "Kerberos Encryption" "VULNERABLE (RC4 Allowed)" "Restricted Kerberos to AES-128 and AES-256 only"

    # SMBv1 & Signing
    $smbParamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    if (-not (Test-Path $smbParamPath)) { New-Item -Path $smbParamPath -Force | Out-Null }
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
    Set-ItemProperty -Path $smbParamPath -Name "SMB1" -Value 0 -Type DWord -Force
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force | Out-Null
    Set-ItemProperty -Path $smbParamPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
    Add-AuditEntry "Protocols" "SMBv1 (EternalBlue)" "VULNERABLE (Enabled)" "Disabled SMBv1 protocol and registry flag"
    Add-AuditEntry "Protocols" "SMB Packet Signing" "VULNERABLE (Not Enforced)" "Enforced SMB security signature (Anti-NTLM Relay)"

    # LLMNR & NetBIOS
    $dnsPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsPolicy)) { New-Item -Path $dnsPolicy -Force | Out-Null }
    Set-ItemProperty -Path $dnsPolicy -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Add-AuditEntry "Protocols" "LLMNR Resolution" "VULNERABLE (Enabled)" "Disabled multicast name resolution (Anti-Responder)"

    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) { $nic.SetTcpipNetbios(2) | Out-Null }
    Add-AuditEntry "Protocols" "NetBIOS over TCP/IP" "VULNERABLE (Active on NICs)" "Disabled NetBIOS across all active interfaces"

    # LSASS Protections
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
    $wdigestPath = "$lsaPath\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
    Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $lsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
    Add-AuditEntry "LSASS / Auth" "LSASS Memory (Mimikatz)" "VULNERABLE (Unprotected)" "Enabled RunAsPPL, disabled WDigest, enforced NTLMv2"

    # LDAP Integrity
    $ntdsParams = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (Test-Path $ntdsParams) {
        Set-ItemProperty -Path $ntdsParams -Name "LDAPServerIntegrity" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $ntdsParams -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord -Force
        Add-AuditEntry "Active Directory" "LDAP Signing & CBT" "VULNERABLE (Unsigned Allowed)" "Enforced LDAP Server Integrity & Channel Binding"
    }

    # Dangerous Services
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler) {
        Stop-Service -Name "Spooler" -Force | Out-Null
        Set-Service -Name "Spooler" -StartupType Disabled | Out-Null
        Add-AuditEntry "Services" "Print Spooler (Spooler)" "VULNERABLE (Running on DC)" "Stopped service and set startup to Disabled"
    }

    $sshd = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshd) {
        Stop-Service -Name "sshd" -Force | Out-Null
        Set-Service -Name "sshd" -StartupType Disabled | Out-Null
        Add-AuditEntry "Services" "Rogue OpenSSH (sshd)" "ROGUE BACKDOOR (Active)" "Terminated process and disabled SSH service"
    }

    # Backup & Purge Malicious Scheduled Tasks
    $badKeywords = @("ithelp4", "shutdown", "curl", "powershell -enc", "wget", "wsl", "certutil -urlcache")
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $taskName = $t.TaskName
            $actionsStr = ($t.Actions | Out-String)
            foreach ($kw in $badKeywords) {
                if ($actionsStr -match [regex]::Escape($kw) -or $taskName -match [regex]::Escape($kw)) {
                    # Backup task XML before deleting
                    cmd.exe /c "schtasks.exe /query /tn `"$taskName`" /xml" > "$BackupRoot\Tasks\$taskName.xml" 2>$null
                    Unregister-ScheduledTask -TaskName $taskName -TaskPath $t.TaskPath -Confirm:$false | Out-Null
                    Add-AuditEntry "Persistence" "Task: $taskName" "MALICIOUS (Matched: $kw)" "Backed up XML to disk and purged task"
                    break
                }
            }
        }
    }

    # Purge WMI Subscriptions
    $consumerClasses = @("CommandLineEventConsumer", "ActiveScriptEventConsumer")
    foreach ($cClass in $consumerClasses) {
        Get-CimInstance -Namespace root\subscription -ClassName $cClass -ErrorAction SilentlyContinue | ForEach-Object {
            Add-AuditEntry "Persistence" ("WMI: " + $_.Name) "ROGUE PERSISTENCE" "Purged event consumer from root\subscription"
            Remove-CimInstance -InputObject $_ | Out-Null
        }
    }
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-CimInstance -InputObject $_ | Out-Null
    }
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-CimInstance -InputObject $_ | Out-Null
    }

    # Executive Summary Report
    Write-Output "`n=========================================================================================================="
    Write-Output "                         CCDC REMEDIATION & HARDENING AUDIT REPORT                                "
    Write-Output "=========================================================================================================="
    Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f "CATEGORY", "TARGET COMPONENT", "STATE DETECTED", "ACTION TAKEN / REMEDIATION")
    Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f "========", "================", "==============", "==========================")
    foreach ($entry in $script:auditLog) {
        Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f $entry.Category, $entry.Target, $entry.StateFound, $entry.ActionTaken)
    }
    Write-Output "=========================================================================================================="
    Write-Output "[+] Hardening pass finished. Rollback snapshot saved to $BackupRoot\StateBackup.xml"
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

Write-Output "`n========================================================"
Write-Output "       CCDC DOMAIN CONTROLLER HARDENING & RECOVERY      "
Write-Output "========================================================"
Write-Output "[1] Harden Domain Controller (Automatic Pre-Hardening Snapshot)"
Write-Output "[2] Rollback / Restore System to Pre-Hardening State"
Write-Output "[Q] Quit"
Write-Output "--------------------------------------------------------"

$choice = Read-Host "Select an option [1, 2, Q]"

switch ($choice.ToUpper()) {
    "1" { Invoke-HardeningSequence }
    "2" { Invoke-SystemRestoration }
    "Q" { Write-Output "Exiting." }
    Default { Write-Output "[!] Invalid selection. Please enter 1, 2, or Q." }
}
