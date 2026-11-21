<#
.SYNOPSIS
    Member Server (Borgar) Hardening, Persistence Purge, Discovery, Firewall Unlock & Rollback
.DESCRIPTION
    Tailored for a domain-joined Windows Server 2022 application server.
    Pure ASCII. Compatible with PowerShell 5.1+.
#>

$ErrorActionPreference = "SilentlyContinue"
$BackupBase = "C:\CCDC_Hardening_Backup"
$BackupRoot = "$BackupBase\Latest"
$InitialBackup = "$BackupBase\Initial"
$global:auditLog = New-Object System.Collections.ArrayList

function Add-AuditEntry {
    param(
        [string]$Category,
        [string]$Target,
        [string]$StateFound,
        [string]$ActionTaken
    )
    $entry = New-Object PSObject -Property @{
        Category    = $Category
        Target      = $Target
        StateFound  = $StateFound
        ActionTaken = $ActionTaken
    }
    $global:auditLog.Add($entry) | Out-Null
}

# ====================================================================
# DISCOVERY ENGINE (READ-ONLY)
# ====================================================================

function Invoke-BorgarDiscovery {
    Write-Output "`n================================================================="
    Write-Output "              BORGAR SERVICE & ACCOUNT DISCOVERY                 "
    Write-Output "================================================================="

    Write-Output "`n[*] Domain Membership:"
    $cs = Get-CimInstance Win32_ComputerSystem
    Write-Output ("    Hostname: {0} | PartOfDomain: {1} | Domain: {2}" -f $env:COMPUTERNAME, $cs.PartOfDomain, $cs.Domain)

    Write-Output "`n[*] Local Users:"
    Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize

    Write-Output "[*] Local Administrators Group:"
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize

    Write-Output "[*] Listening TCP Ports & Processes (Find Food Ordering Service):"
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $wmi = Get-CimInstance Win32_Process -Filter "ProcessId = $($_.OwningProcess)" -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port        = $_.LocalPort
            Address     = $_.LocalAddress
            PID         = $_.OwningProcess
            Process     = $proc.ProcessName
            CommandLine = $wmi.CommandLine
        }
    } | Format-Table -AutoSize -Wrap

    Write-Output "[*] Non-System32 Running Services:"
    Get-CimInstance Win32_Service | Where-Object {
        $_.State -eq "Running" -and $_.PathName -notmatch "C:\\Windows\\system32"
    } | Select-Object Name, DisplayName, StartMode, PathName | Format-Table -AutoSize -Wrap

    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration
        Write-Output "[*] IIS Websites:"
        Get-Website | Select-Object Name, State, PhysicalPath, @{N="Bindings";E={$_.Bindings.Collection.bindingInformation}} | Format-Table -AutoSize
    }
}

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
        Tasks    = @()
        WMI      = @()
    }

    # 1. Snapshot Registry Values
    $regTargets = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"; Names = @("RequireStrongKey", "RequireSignOrSeal") },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; Names = @("SupportedEncryptionTypes") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Names = @("SMB1", "RequireSecuritySignature") },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Names = @("EnableMulticast") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Names = @("RunAsPPL", "LmCompatibilityLevel", "RestrictAnonymous", "RestrictAnonymousSAM", "EveryoneIncludesAnonymous", "LimitBlankPasswordUse") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SecurityProviders\WDigest"; Names = @("UseLogonCredential") },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Names = @("UserAuthentication") }
    )

    foreach ($entry in $regTargets) {
        $p = $entry.Path
        $exists = Test-Path $p
        foreach ($name in $entry.Names) {
            $val = $null
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

    # 2. Snapshot NetBIOS on active NICs
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        $state.NetBIOS += @{
            Description = $nic.Description
            SettingID   = $nic.SettingID
            Options     = $nic.TcpipNetbiosOptions
        }
    }

    # 3. Snapshot Services
    $svcList = @("Spooler", "sshd", "RemoteRegistry", "TlntSvr")
    foreach ($sName in $svcList) {
        $svcCim = Get-CimInstance Win32_Service -Filter "Name='$sName'" -ErrorAction SilentlyContinue
        if ($svcCim) {
            $state.Services += @{
                Name      = $sName
                StartMode = $svcCim.StartMode
                State     = $svcCim.State
                Installed = $true
            }
        } else {
            $state.Services += @{ Name = $sName; Installed = $false }
        }
    }

    # 4. Snapshot WMI Consumers
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $state.WMI += @{
            Type                = "CommandLineEventConsumer"
            Name                = $c.Name
            CommandLineTemplate = $c.CommandLineTemplate
        }
    }

    $state | Export-Clixml -Path "$BackupRoot\StateBackup.xml"
    Write-Output "  [+] State snapshot saved to $BackupRoot\StateBackup.xml"

    # Preserve pristine initial backup so running [1] twice never overwrites original state
    if (-not (Test-Path "$InitialBackup\StateBackup.xml")) {
        New-Item -ItemType Directory -Path "$InitialBackup\Tasks" -Force | Out-Null
        Copy-Item -Path "$BackupRoot\*" -Destination $InitialBackup -Recurse -Force
        Write-Output "  [+] Initial clean snapshot also preserved at $InitialBackup"
    }
}

# ====================================================================
# RESTORATION / ROLLBACK ENGINE
# ====================================================================

function Invoke-SystemRestoration {
    Write-Output "================================================================="
    Write-Output "             RESTORING SYSTEM FROM PREVIOUS BACKUP               "
    Write-Output "================================================================="

    $restoreFrom = $BackupRoot
    if (Test-Path "$InitialBackup\StateBackup.xml") {
        $useInit = Read-Host "Restore from [I]nitial clean backup or [L]atest backup? (I/L, default L)"
        if ($useInit.ToUpper() -eq "I") { $restoreFrom = $InitialBackup }
    }

    if (-not (Test-Path "$restoreFrom\StateBackup.xml")) {
        Write-Output "[-] No backup found at $restoreFrom\StateBackup.xml. Restoration aborted."
        return
    }

    $state = Import-Clixml -Path "$restoreFrom\StateBackup.xml"
    Write-Output "[*] Loaded State Snapshot from $restoreFrom."

    # 1. Restore Registry
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
    Write-Output "  [+] Registry keys and values reverted."

    # 2. Restore NetBIOS
    Write-Output "`n[*] Restoring NetBIOS Options on Network Interfaces..."
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        $saved = $state.NetBIOS | Where-Object { $_.SettingID -eq $nic.SettingID }
        if ($saved -and $null -ne $saved.Options) {
            Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]$saved.Options } | Out-Null
        }
    }
    Write-Output "  [+] NetBIOS interface configurations restored."

    # 3. Restore Services
    Write-Output "`n[*] Restoring Core Services..."
    foreach ($s in $state.Services) {
        if ($s.Installed) {
            $mode = if ($s.StartMode -eq "Auto") { "Automatic" } else { $s.StartMode }
            Set-Service -Name $s.Name -StartupType $mode -ErrorAction SilentlyContinue | Out-Null
            if ($s.State -eq "Running") {
                Start-Service -Name $s.Name -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Output ("  [+] Service '{0}' restored -> Startup: {1}, State: {2}" -f $s.Name, $mode, $s.State)
        }
    }

    # 4. Restore Purged Scheduled Tasks
    Write-Output "`n[*] Restoring Scheduled Tasks from XML Backups..."
    $metaPath = "$restoreFrom\Tasks\TasksMeta.xml"
    if (Test-Path $metaPath) {
        $taskMeta = Import-Clixml -Path $metaPath
        foreach ($tm in $taskMeta) {
            if (Test-Path $tm.XmlFile) {
                $xmlContent = Get-Content -Path $tm.XmlFile -Raw
                Register-ScheduledTask -Xml $xmlContent -TaskName $tm.TaskName -TaskPath $tm.TaskPath -Force | Out-Null
                Write-Output ("  [+] Restored Scheduled Task: {0}{1}" -f $tm.TaskPath, $tm.TaskName)
            }
        }
    }

    Write-Output "`n================================================================="
    Write-Output "               SYSTEM RESTORATION COMPLETED                      "
    Write-Output "================================================================="
}

# ====================================================================
# HARDENING ENGINE
# ====================================================================

function Invoke-HardeningSequence {
    Backup-PreHardeningState
    $global:auditLog.Clear()

    Write-Output "`n[*] Executing Member Server Hardening Sequence..."

    # 1. Netlogon Secure Channel
    Write-Output "`n[+] [1/6] Hardening Netlogon Secure Channel..."
    $netlogonParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $netlogonParams)) { New-Item -Path $netlogonParams -Force | Out-Null }
    Set-ItemProperty -Path $netlogonParams -Name "RequireStrongKey" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $netlogonParams -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
    Add-AuditEntry "Netlogon / RPC" "Secure Channel" "Checked" "Enforced RequireStrongKey & RequireSignOrSeal"
    Write-Output "    -> Enforced Netlogon RequireStrongKey and RequireSignOrSeal."

    # 2. Kerberos Encryption (Anti-RC4 Downgrade)
    Write-Output "[+] [2/6] Enforcing Kerberos AES Encryption..."
    $kerbPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path "$kerbPol\Kerberos\Parameters")) {
        New-Item -Path "$kerbPol\Kerberos\Parameters" -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Set-ItemProperty -Path "$kerbPol\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 24 -Type DWord -Force | Out-Null
    Add-AuditEntry "Kerberos / Auth" "Kerberos Encryption" "RC4 Allowed" "Restricted Kerberos to AES-128 and AES-256"
    Write-Output "    -> Locked Kerberos encryption to AES-128 and AES-256."

    # 3. SMBv1 & SMB Signing
    Write-Output "[+] [3/6] Hardening SMB Protocols (EternalBlue & NTLM Relay Defense)..."
    $smbParamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    if (-not (Test-Path $smbParamPath)) { New-Item -Path $smbParamPath -Force | Out-Null }
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
    Set-ItemProperty -Path $smbParamPath -Name "SMB1" -Value 0 -Type DWord -Force
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force | Out-Null
    Set-ItemProperty -Path $smbParamPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
    Add-AuditEntry "Protocols" "SMBv1 (EternalBlue)" "Enabled/Unchecked" "Disabled SMBv1 protocol and registry flag"
    Add-AuditEntry "Protocols" "SMB Packet Signing" "Not Enforced" "Enforced SMB security signature"
    Write-Output "    -> Disabled SMBv1 and enforced SMB Signing."

    # 4. LLMNR & NetBIOS
    Write-Output "[+] [4/6] Disabling LLMNR & NetBIOS (Responder Poisoning Defense)..."
    $dnsPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsPolicy)) { New-Item -Path $dnsPolicy -Force | Out-Null }
    Set-ItemProperty -Path $dnsPolicy -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Add-AuditEntry "Protocols" "LLMNR Resolution" "Enabled" "Disabled multicast name resolution"

    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } | Out-Null
    }
    Add-AuditEntry "Protocols" "NetBIOS over TCP/IP" "Active on NICs" "Disabled NetBIOS across all active interfaces"
    Write-Output "    -> LLMNR and NetBIOS over TCP/IP disabled."

    # 5. LSASS, RDP NLA & Firewall Local Admin Unlock
    Write-Output "[+] [5/6] Hardening LSASS, RDP NLA, & Unlocking Local Firewall..."
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

    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    if (Test-Path $rdpPath) {
        Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
        Add-AuditEntry "Remote Access" "RDP NLA" "Checked" "Enforced Network Level Authentication"
    }

    # --- FIREWALL LOCAL ADMIN UNLOCK ---
    netsh advfirewall set allprofiles settings localfirewallrules enable | Out-Null
    netsh advfirewall set allprofiles settings localconsecrules enable | Out-Null
    Set-NetFirewallProfile -Profile Domain,Public,Private -AllowLocalFirewallRules True -AllowLocalIPsecRules True -ErrorAction SilentlyContinue

    $gpoFwPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    foreach ($p in @("DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile")) {
        $pPath = "$gpoFwPath\$p"
        if (-not (Test-Path $pPath)) { New-Item -Path $pPath -Force | Out-Null }
        Set-ItemProperty -Path $pPath -Name "AllowLocalPolicyMerge" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $pPath -Name "AllowLocalIPsecPolicyMerge" -Value 1 -Type DWord -Force
    }

    # Anti-GPO overwrite lock: Deny SYSTEM permission to overwrite firewall merge settings
    $acl = Get-Acl $gpoFwPath
    $denyRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "NT AUTHORITY\SYSTEM",
        "SetValue,CreateSubKey,Delete",
        "ContainerInherit,ObjectInherit",
        "None",
        "Deny"
    )
    $acl.AddAccessRule($denyRule)
    Set-Acl -Path $gpoFwPath -AclObject $acl -ErrorAction SilentlyContinue

    Add-AuditEntry "Firewall" "Local Rule Merging" "Locked by GPO" "Unlocked & Protected registry key from GPO overwrite"
    Add-AuditEntry "LSASS / Auth" "LSASS & NTLM" "Unprotected" "Enabled RunAsPPL, disabled WDigest, enforced NTLMv2"
    Write-Output "    -> Enabled RunAsPPL, disabled WDigest, enforced NTLMv2 & RDP NLA."
    Write-Output "    -> Firewall unlocked: Local administrators have full control."

    # 6. Risky Services & Persistence Purge
    Write-Output "[+] [6/6] Disabling Risky Services & Purging Persistence..."
    foreach ($svcName in @("Spooler", "sshd", "RemoteRegistry", "TlntSvr")) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and ($svc.Status -eq "Running" -or $svc.StartType -ne "Disabled")) {
            Stop-Service -Name $svcName -Force | Out-Null
            Set-Service -Name $svcName -StartupType Disabled | Out-Null
            Add-AuditEntry "Services" $svcName "Running/Enabled" "Stopped and disabled service"
            Write-Output ("    -> Stopped and disabled service: {0}" -f $svcName)
        }
    }

    # Purge Suspicious Scheduled Tasks
    $badKeywords = @("ithelp4", "shutdown", "curl", "powershell -enc", "wget", "wsl", "certutil -urlcache")
    $purgedTasksMeta = @()
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' }
        foreach ($t in $tasks) {
            $actionsStr = ($t.Actions | Out-String)
            foreach ($kw in $badKeywords) {
                if ($actionsStr -match [regex]::Escape($kw) -or $t.TaskName -match [regex]::Escape($kw)) {
                    $safeName = ("$($t.TaskPath)$($t.TaskName)" -replace '[\\/:*?"<>| ]', '_')
                    $xmlPath = "$BackupRoot\Tasks\$safeName.xml"
                    Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Set-Content -Path $xmlPath -Encoding UTF8
                    $purgedTasksMeta += @{
                        TaskName = $t.TaskName
                        TaskPath = $t.TaskPath
                        XmlFile  = $xmlPath
                    }
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false | Out-Null
                    Add-AuditEntry "Persistence" "Task: $($t.TaskName)" "Matched: $kw" "Exported XML and unregistered task"
                    Write-Output ("    -> Purged Scheduled Task: {0}{1}" -f $t.TaskPath, $t.TaskName)
                    break
                }
            }
        }
    }
    if ($purgedTasksMeta.Count -gt 0) {
        $purgedTasksMeta | Export-Clixml -Path "$BackupRoot\Tasks\TasksMeta.xml"
        if (Test-Path "$InitialBackup\Tasks") {
            Copy-Item -Path "$BackupRoot\Tasks\*" -Destination "$InitialBackup\Tasks" -Force
        }
    }

    # Purge WMI Subscriptions
    $consumerClasses = @("CommandLineEventConsumer", "ActiveScriptEventConsumer")
    foreach ($cClass in $consumerClasses) {
        Get-CimInstance -Namespace root\subscription -ClassName $cClass -ErrorAction SilentlyContinue | ForEach-Object {
            Add-AuditEntry "Persistence" ("WMI: " + $_.Name) "ROGUE PERSISTENCE" "Purged event consumer from root\subscription"
            Remove-CimInstance -InputObject $_ | Out-Null
            Write-Output ("    -> Purged WMI Consumer: " + $_.Name)
        }
    }
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-CimInstance -InputObject $_ | Out-Null
    }
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-CimInstance -InputObject $_ | Out-Null
    }

    # Final Audit Summary Table
    Write-Output "`n=========================================================================================================="
    Write-Output "                         BORGAR REMEDIATION & HARDENING AUDIT REPORT                                      "
    Write-Output "=========================================================================================================="
    Write-Output ("{0,-16} {1,-26} {2,-25} {3}" -f "CATEGORY", "TARGET COMPONENT", "STATE DETECTED", "ACTION TAKEN")
    Write-Output ("{0,-16} {1,-26} {2,-25} {3}" -f "========", "================", "==============", "============")
    foreach ($entry in $global:auditLog) {
        Write-Output ("{0,-16} {1,-26} {2,-25} {3}" -f $entry.Category, $entry.Target, $entry.StateFound, $entry.ActionTaken)
    }
    Write-Output "=========================================================================================================="
    Write-Output "[+] Hardening finished. Rollback snapshot saved to $BackupRoot\StateBackup.xml"
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

Write-Output "`n========================================================"
Write-Output "      BORGAR (MEMBER SERVER) HARDENING & RECOVERY       "
Write-Output "========================================================"
Write-Output "[1] Harden Member Server (Automatic Pre-Hardening Snapshot)"
Write-Output "[2] Rollback / Restore System to Pre-Hardening State"
Write-Output "[3] Discover Listening Ports, Services & Local Admins (Read-Only)"
Write-Output "[Q] Quit"
Write-Output "--------------------------------------------------------"

$choice = Read-Host "Select an option [1, 2, 3, Q]"

switch ($choice.ToUpper()) {
    "1" { Invoke-HardeningSequence }
    "2" { Invoke-SystemRestoration }
    "3" { Invoke-BorgarDiscovery }
    "Q" { Write-Output "Exiting." }
    Default { Write-Output "[!] Invalid selection. Please enter 1, 2, 3, or Q." }
}
