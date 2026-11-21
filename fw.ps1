<#
.SYNOPSIS
    CCDC Universal Firewall Engine (v6 - T1562 Defense, Generic Mode & AD Modes)
.DESCRIPTION
    Compatible across Windows Server 2012 through 2025. Pure ASCII.
    - [T1562 Repair]: Strips registry DENY locks, re-registers DLLs, repairs BFE/MpsSvc
    - [Generic Mode]: Inbound BLOCK / Outbound ALLOW (NO AD Rules - Best for Borgar)
    - [Standard DC Mode]: Inbound BLOCK / Outbound ALLOW + Active Directory Rules
    - [Strict DC Mode]: Inbound BLOCK / Outbound BLOCK + Mirrored AD Rules
    - Interactive custom rule opener with optional outbound mirroring
    - Tabular active rule inspection and atomic .wfw backup/restore
#>

$ErrorActionPreference = "SilentlyContinue"
$BackupDir = "C:\CCDC_Firewall_Backup"
$PreBackupFile = "$BackupDir\PreHardening_Firewall.wfw"
$HardenedBackupFile = "$BackupDir\Hardened_Firewall.wfw"

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

function Get-PortServiceDescription {
    param([string]$Port, [string]$RuleName)
    
    $portMap = @{
        "53"          = "DNS (Domain Name System)"
        "88"          = "Kerberos Authentication"
        "123"         = "Windows Time (NTP)"
        "135"         = "RPC Endpoint Mapper"
        "389"         = "LDAP Directory Service"
        "445"         = "SMB / AD SYSVOL & File Shares"
        "464"         = "Kerberos Password Change (kpasswd)"
        "636"         = "LDAPS (Secure LDAP)"
        "3268"        = "Active Directory Global Catalog"
        "3269"        = "Active Directory Global Catalog SSL"
        "3389"        = "RDP (Remote Desktop Management)"
        "5985"        = "WinRM (PowerShell Remoting HTTP)"
        "5986"        = "WinRM (PowerShell Remoting HTTPS)"
        "49152-65535" = "RPC Dynamic High Ports (AD Replication)"
        "80"          = "HTTP (Web Service)"
        "443"         = "HTTPS (Secure Web Service)"
        "80,443"      = "Web Browsing / GitHub (HTTP & HTTPS)"
        "1433"        = "Microsoft SQL Server"
        "3306"        = "MySQL Database"
    }

    if ($portMap.ContainsKey($Port)) {
        return $portMap[$Port]
    }

    if ($RuleName -match "CCDC_Custom_(.*)_(In|Out)") {
        return "Custom Service (" + $matches[1] + ")"
    }

    return "Custom Port ($Port)"
}

function Show-FirewallProfileStatus {
    Write-Output "`n================================================================="
    Write-Output "               CURRENT FIREWALL PROFILE STATUS                   "
    Write-Output "================================================================="
    
    $profiles = @("domainprofile", "privateprofile", "publicprofile")
    foreach ($p in $profiles) {
        $stateOut = cmd.exe /c "netsh advfirewall show $p state" 2>$null | Select-String "State"
        $policyOut = cmd.exe /c "netsh advfirewall show $p firewallpolicy" 2>$null | Select-String "Firewall Policy"
        
        $pName = $p.ToUpper().Replace("PROFILE", "")
        $state = if ($stateOut -match "ON") { "ON" } else { "OFF" }
        $policy = if ($policyOut) { ($policyOut.ToString() -split '\s+', 3)[-1] } else { "Unknown" }
        
        Write-Output ("Profile: {0,-10} | State: {1,-5} | Policy: {2}" -f $pName, $state, $policy)
    }
}

function Backup-FirewallConfiguration {
    param([string]$FilePath, [string]$Description)
    Write-Output ("[*] Creating " + $Description + " in: " + $FilePath)
    cmd.exe /c "netsh advfirewall export `"$FilePath`"" 2>$null | Out-Null
    if (Test-Path $FilePath) {
        Write-Output ("  [+] Snapshot successfully saved (" + (Get-Item $FilePath).Length + " bytes).")
    } else {
        Write-Output "  [-] Failed to create firewall snapshot."
    }
}

function Restore-FirewallConfiguration {
    param([string]$FilePath, [string]$Description)
    Write-Output "`n================================================================="
    Write-Output ("               RESTORE: " + $Description.ToUpper())
    Write-Output "================================================================="
    
    if (-not (Test-Path $FilePath)) {
        Write-Output ("[-] Backup file not found: " + $FilePath)
        return
    }

    Write-Output ("[*] Importing firewall snapshot from: " + $FilePath)
    cmd.exe /c "netsh advfirewall import `"$FilePath`"" 2>$null | Out-Null
    Write-Output "  [+] Firewall rules and profile states restored successfully."
    Show-FirewallProfileStatus
}

# ====================================================================
# T1562 REMEDIATION: REPAIR & UNBREAK FIREWALL SUBSYSTEM
# ====================================================================

function Repair-FirewallSubsystem {
    Write-Output "`n================================================================="
    Write-Output "       REPAIRING FIREWALL SUBSYSTEM (T1562 ANTI-TAMPER FIX)      "
    Write-Output "================================================================="
    Write-Output "[*] Resolving Registry Locks, Service Sabotage, & DLL Tampering..."

    # 1. Strip Deny ACLs & Grant Administrators/SYSTEM Full Control on Firewall Registry
    $regTargets = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
        "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall",
        "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc",
        "HKLM:\SYSTEM\CurrentControlSet\Services\BFE"
    )

    foreach ($regPath in $regTargets) {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        try {
            $acl = Get-Acl -Path $regPath
            $denyRules = $acl.Access | Where-Object { $_.AccessControlType -eq "Deny" }
            foreach ($dr in $denyRules) {
                $acl.RemoveAccessRule($dr) | Out-Null
            }
            $adminSec = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
            $sysSec   = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
            $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule($adminSec, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $sysRule   = New-Object System.Security.AccessControl.RegistryAccessRule($sysSec, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($adminRule)
            $acl.SetAccessRule($sysRule)
            Set-Acl -Path $regPath -AclObject $acl -ErrorAction SilentlyContinue
            Write-Output ("  [+] Restored Full Control permissions on: " + ($regPath -split "\\")[-1])
        } catch {
            Write-Output ("  [-] Could not modify ACL on {0}: {1}" -f $regPath, $_.Exception.Message)
        }
    }

    # 2. Re-register Core Firewall DLLs
    Write-Output "`n[*] Re-registering Firewall COM components and DLLs..."
    cmd.exe /c "regsvr32.exe /s %SystemRoot%\System32\firewallapi.dll" 2>$null | Out-Null
    cmd.exe /c "regsvr32.exe /s %SystemRoot%\System32\bfe.dll" 2>$null | Out-Null
    Write-Output "  [+] firewallapi.dll and bfe.dll re-registered."

    # 3. Repair & Force Start Services (BFE & MpsSvc)
    Write-Output "`n[*] Repairing Base Filtering Engine (BFE) & Firewall (MpsSvc) Services..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BFE" -Name "Start" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc" -Name "Start" -Value 2 -Type DWord -Force

    cmd.exe /c "sc.exe config bfe start= auto" 2>$null | Out-Null
    cmd.exe /c "sc.exe start bfe" 2>$null | Out-Null
    Start-Sleep -Seconds 1

    cmd.exe /c "sc.exe config mpssvc start= auto" 2>$null | Out-Null
    cmd.exe /c "sc.exe start mpssvc" 2>$null | Out-Null
    Start-Sleep -Seconds 1

    $bfeStatus = (Get-Service -Name "BFE" -ErrorAction SilentlyContinue).Status
    $mpsStatus = (Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue).Status
    Write-Output ("  [+] BFE Service Status   : " + $bfeStatus)
    Write-Output ("  [+] MpsSvc Service Status: " + $mpsStatus)

    # 4. Factory Reset the Firewall Engine
    Write-Output "`n[*] Running Factory Reset on Firewall Database..."
    cmd.exe /c "netsh advfirewall reset" 2>$null | Out-Null
    Write-Output "  [+] Firewall rules database reset to clean default state."

    # 5. Enable Local Rule Merging
    $profiles = @("DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile")
    foreach ($p in $profiles) {
        $pPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p"
        if (-not (Test-Path $pPath)) { New-Item -Path $pPath -Force | Out-Null }
        Set-ItemProperty -Path $pPath -Name "AllowLocalPolicyMerge" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $pPath -Name "AllowLocalIPsecPolicyMerge" -Value 1 -Type DWord -Force
    }
    netsh advfirewall set allprofiles settings localfirewallrules enable | Out-Null
    Write-Output "  [+] Local Admin Rule Merging enabled."

    Write-Output "`n================================================================="
    Write-Output "               T1562 REPAIR SEQUENCE FINISHED                    "
    Write-Output "================================================================="
    Show-FirewallProfileStatus
}

# ====================================================================
# GENERIC / MEMBER SERVER MODE: BLOCK INBOUND / ALLOW OUTBOUND (NO AD RULES)
# ====================================================================

function Invoke-GenericFirewallMode {
    Show-FirewallProfileStatus
    Backup-FirewallConfiguration -FilePath $PreBackupFile -Description "Pre-Generic Baseline"

    Write-Output "`n[*] REMOTE ACCESS SAFEGUARD:"
    Write-Output "[!] Inbound traffic will be BLOCKED by default."
    $allowRDP = Read-Host "Allow RDP (TCP 3389) to prevent lockout? ([Y]es / [N]o - Default: Y)"
    $allowWinRM = Read-Host "Allow WinRM (TCP 5985)? ([Y]es / [N]o - Default: N)"

    Write-Output "`n[*] [1/3] Enabling Firewall on all profiles (Domain, Private, Public)..."
    cmd.exe /c "netsh advfirewall set allprofiles state on" 2>$null | Out-Null

    Write-Output "[*] [2/3] Setting Policies: Inbound = BLOCK, Outbound = ALLOW..."
    cmd.exe /c "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound" 2>$null | Out-Null

    Write-Output "[*] [3/3] Disabling pre-existing inbound rules to eliminate backdoors..."
    cmd.exe /c "netsh advfirewall firewall set rule name=all dir=in new enable=no" 2>$null | Out-Null

    if ($allowRDP -ne 'N' -and $allowRDP -ne 'n') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_RDP_In`" dir=in action=allow protocol=TCP localport=3389 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_RDP_In (TCP 3389 - Remote Desktop)"
    }
    if ($allowWinRM -eq 'Y' -or $allowWinRM -eq 'y') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_WinRM_In`" dir=in action=allow protocol=TCP localport=5985 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_WinRM_In (TCP 5985 - WinRM Remoting)"
    }

    Backup-FirewallConfiguration -FilePath $HardenedBackupFile -Description "Generic Baseline (Inbound Block / Outbound Allow, No AD)"
    Write-Output "`n[+] Generic Firewall Mode Active!"
    Write-Output "    -> All profiles ON"
    Write-Output "    -> Default Inbound: BLOCKED"
    Write-Output "    -> Default Outbound: ALLOWED"
    Write-Output "    -> NO Active Directory rules added."
    Write-Output "    (Use Option [5] to add ports for the Food Ordering Service)"
    Show-FirewallProfileStatus
}

# ====================================================================
# STANDARD DC MODE: BLOCK INBOUND / ALLOW OUTBOUND + AD RULES
# ====================================================================

function Invoke-StandardFirewallMode {
    Show-FirewallProfileStatus
    Backup-FirewallConfiguration -FilePath $PreBackupFile -Description "Pre-Standard Mode Baseline"

    Write-Output "`n[*] REMOTE ACCESS SAFEGUARD:"
    $allowRDP = Read-Host "Allow RDP (TCP 3389)? ([Y]es / [N]o - Default: Y)"
    $allowWinRM = Read-Host "Allow WinRM (TCP 5985)? ([Y]es / [N]o - Default: N)"

    Write-Output "`n[*] [1/4] Turning Firewall ON across all profiles..."
    cmd.exe /c "netsh advfirewall set allprofiles state on" 2>$null | Out-Null

    Write-Output "[*] [2/4] Setting Policy: Inbound = BLOCK, Outbound = ALLOW..."
    cmd.exe /c "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound" 2>$null | Out-Null

    Write-Output "[*] [3/4] Disabling pre-existing inbound rules to eliminate backdoors..."
    cmd.exe /c "netsh advfirewall firewall set rule name=all dir=in new enable=no" 2>$null | Out-Null

    Write-Output "[*] [4/4] Injecting Core Inbound Rules (AD + Management)..."
    $adRules = @(
        @{ Name = "CCDC_AD_DNS_UDP"; Proto = "UDP"; Port = "53" },
        @{ Name = "CCDC_AD_DNS_TCP"; Proto = "TCP"; Port = "53" },
        @{ Name = "CCDC_AD_Kerberos_UDP"; Proto = "UDP"; Port = "88" },
        @{ Name = "CCDC_AD_Kerberos_TCP"; Proto = "TCP"; Port = "88" },
        @{ Name = "CCDC_AD_Kerberos_kpasswd_UDP"; Proto = "UDP"; Port = "464" },
        @{ Name = "CCDC_AD_Kerberos_kpasswd_TCP"; Proto = "TCP"; Port = "464" },
        @{ Name = "CCDC_AD_LDAP_TCP"; Proto = "TCP"; Port = "389" },
        @{ Name = "CCDC_AD_LDAP_UDP"; Proto = "UDP"; Port = "389" },
        @{ Name = "CCDC_AD_LDAPS_TCP"; Proto = "TCP"; Port = "636" },
        @{ Name = "CCDC_AD_GlobalCatalog_TCP"; Proto = "TCP"; Port = "3268" },
        @{ Name = "CCDC_AD_GlobalCatalog_SSL_TCP"; Proto = "TCP"; Port = "3269" },
        @{ Name = "CCDC_AD_SMB_TCP"; Proto = "TCP"; Port = "445" },
        @{ Name = "CCDC_AD_RPC_EndpointMapper_TCP"; Proto = "TCP"; Port = "135" },
        @{ Name = "CCDC_AD_RPC_DynamicHighPorts_TCP"; Proto = "TCP"; Port = "49152-65535" },
        @{ Name = "CCDC_AD_W32Time_NTP_UDP"; Proto = "UDP"; Port = "123" }
    )

    foreach ($r in $adRules) {
        $inName = $r.Name + "_In"
        $desc = Get-PortServiceDescription -Port $r.Port -RuleName $inName
        cmd.exe /c "netsh advfirewall firewall delete rule name=`"$inName`"" 2>$null | Out-Null
        cmd.exe /c "netsh advfirewall firewall add rule name=`"$inName`" dir=in action=allow protocol=$($r.Proto) localport=$($r.Port) enable=yes profile=any" 2>$null | Out-Null
        Write-Output ("  [+] Inbound Allowed: " + $inName.PadRight(35) + " (" + $r.Proto + " Port: " + $r.Port + " - " + $desc + ")")
    }

    if ($allowRDP -ne 'N' -and $allowRDP -ne 'n') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_RDP_In`" dir=in action=allow protocol=TCP localport=3389 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_RDP_In (TCP 3389 - Remote Desktop)"
    }
    if ($allowWinRM -eq 'Y' -or $allowWinRM -eq 'y') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_WinRM_In`" dir=in action=allow protocol=TCP localport=5985 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_WinRM_In (TCP 5985 - WinRM Remoting)"
    }

    Backup-FirewallConfiguration -FilePath $HardenedBackupFile -Description "Standard Baseline (Inbound Block / Outbound Allow)"
    Write-Output "`n[+] Standard Mode Active. All outbound traffic is permitted."
    Show-FirewallProfileStatus
}

# ====================================================================
# STRICT DC MODE: BLOCK INBOUND / BLOCK OUTBOUND + AD RULES
# ====================================================================

function Invoke-StrictFirewallMode {
    Show-FirewallProfileStatus
    Backup-FirewallConfiguration -FilePath $PreBackupFile -Description "Pre-Strict Baseline"

    Write-Output "`n[*] REMOTE ACCESS SAFEGUARD:"
    $allowRDP = Read-Host "Allow RDP (TCP 3389)? ([Y]es / [N]o - Default: Y)"
    $allowWinRM = Read-Host "Allow WinRM (TCP 5985)? ([Y]es / [N]o - Default: N)"

    Write-Output "`n[*] [1/6] Enabling Firewall on all profiles..."
    cmd.exe /c "netsh advfirewall set allprofiles state on" 2>$null | Out-Null

    Write-Output "[*] [2/6] Enforcing Strict Default Policies: Inbound = BLOCK, Outbound = BLOCK..."
    cmd.exe /c "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound" 2>$null | Out-Null

    Write-Output "[*] [3/6] Disabling all pre-existing Inbound and Outbound rules..."
    cmd.exe /c "netsh advfirewall firewall set rule name=all dir=in new enable=no" 2>$null | Out-Null
    cmd.exe /c "netsh advfirewall firewall set rule name=all dir=out new enable=no" 2>$null | Out-Null

    Write-Output "[*] [4/6] Injecting Core Active Directory Inbound Rules..."
    $adRules = @(
        @{ Name = "CCDC_AD_DNS_UDP"; Proto = "UDP"; Port = "53" },
        @{ Name = "CCDC_AD_DNS_TCP"; Proto = "TCP"; Port = "53" },
        @{ Name = "CCDC_AD_Kerberos_UDP"; Proto = "UDP"; Port = "88" },
        @{ Name = "CCDC_AD_Kerberos_TCP"; Proto = "TCP"; Port = "88" },
        @{ Name = "CCDC_AD_Kerberos_kpasswd_UDP"; Proto = "UDP"; Port = "464" },
        @{ Name = "CCDC_AD_Kerberos_kpasswd_TCP"; Proto = "TCP"; Port = "464" },
        @{ Name = "CCDC_AD_LDAP_TCP"; Proto = "TCP"; Port = "389" },
        @{ Name = "CCDC_AD_LDAP_UDP"; Proto = "UDP"; Port = "389" },
        @{ Name = "CCDC_AD_LDAPS_TCP"; Proto = "TCP"; Port = "636" },
        @{ Name = "CCDC_AD_GlobalCatalog_TCP"; Proto = "TCP"; Port = "3268" },
        @{ Name = "CCDC_AD_GlobalCatalog_SSL_TCP"; Proto = "TCP"; Port = "3269" },
        @{ Name = "CCDC_AD_SMB_TCP"; Proto = "TCP"; Port = "445" },
        @{ Name = "CCDC_AD_RPC_EndpointMapper_TCP"; Proto = "TCP"; Port = "135" },
        @{ Name = "CCDC_AD_RPC_DynamicHighPorts_TCP"; Proto = "TCP"; Port = "49152-65535" },
        @{ Name = "CCDC_AD_W32Time_NTP_UDP"; Proto = "UDP"; Port = "123" }
    )

    foreach ($r in $adRules) {
        $inName = $r.Name + "_In"
        $desc = Get-PortServiceDescription -Port $r.Port -RuleName $inName
        cmd.exe /c "netsh advfirewall firewall delete rule name=`"$inName`"" 2>$null | Out-Null
        cmd.exe /c "netsh advfirewall firewall add rule name=`"$inName`" dir=in action=allow protocol=$($r.Proto) localport=$($r.Port) enable=yes profile=any" 2>$null | Out-Null
        Write-Output ("  [+] Inbound Allowed  : " + $inName.PadRight(35) + " (" + $r.Proto + " Port: " + $r.Port + " - " + $desc + ")")
    }

    Write-Output "`n[*] [5/6] Injecting Mirrored Outbound Rules for AD Operation..."
    foreach ($r in $adRules) {
        $outName = $r.Name + "_Out"
        $desc = Get-PortServiceDescription -Port $r.Port -RuleName $outName
        cmd.exe /c "netsh advfirewall firewall delete rule name=`"$outName`"" 2>$null | Out-Null
        cmd.exe /c "netsh advfirewall firewall add rule name=`"$outName`" dir=out action=allow protocol=$($r.Proto) remoteport=$($r.Port) enable=yes profile=any" 2>$null | Out-Null
        Write-Output ("  [+] Outbound Allowed : " + $outName.PadRight(35) + " (" + $r.Proto + " Port: " + $r.Port + " - " + $desc + ")")
    }

    if ($allowRDP -ne 'N' -and $allowRDP -ne 'n') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_RDP_In`" dir=in action=allow protocol=TCP localport=3389 enable=yes profile=any" 2>$null | Out-Null
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_RDP_Out`" dir=out action=allow protocol=TCP remoteport=3389 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_RDP (In & Out TCP 3389 - Remote Desktop)"
    }
    if ($allowWinRM -eq 'Y' -or $allowWinRM -eq 'y') {
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_WinRM_In`" dir=in action=allow protocol=TCP localport=5985 enable=yes profile=any" 2>$null | Out-Null
        cmd.exe /c "netsh advfirewall firewall add rule name=`"CCDC_Mgmt_WinRM_Out`" dir=out action=allow protocol=TCP remoteport=5985 enable=yes profile=any" 2>$null | Out-Null
        Write-Output "  [+] Management Allowed : CCDC_Mgmt_WinRM (In & Out TCP 5985 - WinRM Remoting)"
    }

    Write-Output "`n[*] [6/6] Creating Hardened Baseline Backup..."
    Backup-FirewallConfiguration -FilePath $HardenedBackupFile -Description "Strict Baseline (Inbound Block / Outbound Block)"
    Show-FirewallProfileStatus
}

function Add-CustomRule {
    Write-Output "`n================================================================="
    Write-Output "               ADD CUSTOM FIREWALL RULE                          "
    Write-Output "================================================================="
    $rName = Read-Host "Enter rule name (e.g. FoodOrderingService)"
    if ([string]::IsNullOrWhiteSpace($rName)) {
        Write-Output "[-] Rule name cannot be empty."
        return
    }

    $proto = Read-Host "Enter protocol ([T]CP / [U]DP - Default: TCP)"
    $protocol = if ($proto -match "^[uU]") { "UDP" } else { "TCP" }

    $port = Read-Host "Enter port number(s) (e.g. 80 or 80,443 or 8080)"
    if ([string]::IsNullOrWhiteSpace($port)) {
        Write-Output "[-] Port cannot be empty."
        return
    }

    $mirrorOut = Read-Host "Mirror this rule for Outbound traffic? ([Y]es / [N]o - Default: N)"

    # Add Inbound Rule (localport)
    $inName = "CCDC_Custom_" + $rName + "_In"
    Write-Output ("[*] Creating Inbound Rule: " + $inName + " (" + $protocol + " LocalPort: " + $port + ")...")
    cmd.exe /c "netsh advfirewall firewall add rule name=`"$inName`" dir=in action=allow protocol=$protocol localport=$port enable=yes profile=any" 2>$null | Out-Null
    Write-Output ("  [+] Inbound rule '" + $inName + "' active.")

    # Add Mirrored Outbound Rule if requested
    if ($mirrorOut -eq 'Y' -or $mirrorOut -eq 'y') {
        $outName = "CCDC_Custom_" + $rName + "_Out"
        Write-Output ("[*] Creating Mirrored Outbound Rule: " + $outName + " (" + $protocol + " RemotePort: " + $port + ")...")
        cmd.exe /c "netsh advfirewall firewall add rule name=`"$outName`" dir=out action=allow protocol=$protocol remoteport=$port enable=yes profile=any" 2>$null | Out-Null
        Write-Output ("  [+] Mirrored outbound rule '" + $outName + "' active.")
    }
}

function Show-ActiveRules {
    Write-Output "`n========================================================================================================================"
    Write-Output "                                           ACTIVE CCDC FIREWALL ALLOW RULES                                             "
    Write-Output "========================================================================================================================"

    $rules = @()

    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        $netRules = Get-NetFirewallRule -DisplayName "CCDC_*" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' }
        foreach ($nr in $netRules) {
            $pf = $nr | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $dir = $nr.Direction.ToString().ToUpper()
            $proto = if ($pf.Protocol) { $pf.Protocol.ToString().ToUpper() } else { "ANY" }
            $port = if ($dir -eq "INBOUND") { $pf.LocalPort } else { $pf.RemotePort }
            if ([string]::IsNullOrWhiteSpace($port)) { $port = "Any" }

            $rules += New-Object PSObject -Property @{
                Name        = $nr.DisplayName
                Direction   = $dir
                Protocol    = $proto
                Port        = $port
                Description = (Get-PortServiceDescription -Port $port -RuleName $nr.DisplayName)
            }
        }
    }

    # Table 1: Inbound Rules
    Write-Output "`n[+] INBOUND ALLOWED RULES (LOCAL PORTS LISTENING)"
    Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f "PROTO", "PORT", "SERVICE / ROLE", "RULE NAME")
    Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f "-----", "----", "--------------", "---------")
    $inRules = $rules | Where-Object { $_.Direction -eq "INBOUND" } | Sort-Object Protocol, Port
    if ($inRules) {
        foreach ($r in $inRules) {
            Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f $r.Protocol, $r.Port, $r.Description, $r.Name)
        }
    } else {
        Write-Output "No active CCDC inbound allow rules."
    }

    # Table 2: Outbound Rules
    Write-Output "`n[+] OUTBOUND ALLOWED RULES (REMOTE DESTINATION PORTS)"
    Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f "PROTO", "PORT", "SERVICE / ROLE", "RULE NAME")
    Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f "-----", "----", "--------------", "---------")
    $outRules = $rules | Where-Object { $_.Direction -eq "OUTBOUND" } | Sort-Object Protocol, Port
    if ($outRules) {
        foreach ($r in $outRules) {
            Write-Output ("{0,-6} {1,-14} {2,-38} {3}" -f $r.Protocol, $r.Port, $r.Description, $r.Name)
        }
    } else {
        Write-Output "Outbound is default ALLOW (or no custom rules active)."
    }
    Write-Output "`n========================================================================================================================"
}

# ====================================================================
# MAIN MENU
# ====================================================================

while ($true) {
    Write-Output "`n========================================================"
    Write-Output "          CCDC FIREWALL MANAGEMENT & REPAIR             "
    Write-Output "========================================================"
    Write-Output "[1] Repair / Reinstall Firewall Subsystem (Fix T1562 Locks)"
    Write-Output "[2] Generic Mode  : BLOCK Inbound & ALLOW Outbound (NO AD Rules)"
    Write-Output "[3] Standard DC   : BLOCK Inbound & ALLOW Outbound + AD Rules"
    Write-Output "[4] Strict DC     : BLOCK Inbound & BLOCK Outbound + AD Rules"
    Write-Output "[5] Add Custom Port Rule (e.g. Food Ordering Service)"
    Write-Output "[6] Restore Pre-Hardening Baseline Snapshot"
    Write-Output "[7] Restore Hardened CCDC Baseline Snapshot"
    Write-Output "[8] View Current Firewall Status & Active Rules"
    Write-Output "[Q] Quit"
    Write-Output "--------------------------------------------------------"

    $choice = Read-Host "Select an option [1-8, Q]"

    switch ($choice.ToUpper()) {
        "1" { Repair-FirewallSubsystem }
        "2" { Invoke-GenericFirewallMode }
        "3" { Invoke-StandardFirewallMode }
        "4" { Invoke-StrictFirewallMode }
        "5" { Add-CustomRule }
        "6" { Restore-FirewallConfiguration -FilePath $PreBackupFile -Description "Pre-Hardening Configuration" }
        "7" { Restore-FirewallConfiguration -FilePath $HardenedBackupFile -Description "Hardened CCDC Baseline" }
        "8" { 
            Show-FirewallProfileStatus 
            Show-ActiveRules
        }
        "Q" { Write-Output "Exiting firewall engine."; return }
        Default { Write-Output "[!] Invalid choice. Please enter 1-8, or Q." }
    }
}
