<#
.SYNOPSIS
    Domain Controller Group Policy Hardening, Deployment, & Rollback Engine
.DESCRIPTION
    Designed for Windows Server 2019/2022 Active Directory Domain Controllers.
    - Full backup and rollback of all existing GPOs, MachineAccountQuota, and Password Policy.
    - Sets ms-DS-MachineAccountQuota to 0 (Prevents standard users from adding domain machines).
    - Creates a baseline GPO ('CCDC_Hardened_Baseline') and links it to the domain root.
    - Hardens RDP (1 session limit, NLA), LSASS (RunAsPPL, WDigest), SMB, and LLMNR.
    - Explicitly allows local member servers (borgar) to manage their local firewalls.
    - Pushes GPO updates to all domain computers via Invoke-GPUpdate.
#>

$ErrorActionPreference = "SilentlyContinue"
$BackupRoot = "C:\CCDC_Hardening_Backup\GPO"
$GpoName = "CCDC_Hardened_Baseline"
$global:auditLog = New-Object System.Collections.ArrayList

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

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

function Get-DomainDN {
    try {
        return ([ADSI]"LDAP://RootDSE").defaultNamingContext
    } catch {
        return $null
    }
}

# ====================================================================
# BACKUP ENGINE
# ====================================================================

function Backup-AllGPOs {
    Write-Output "`n[*] Initiating Full GPO, Quota, & Domain Password Policy Backup..."
    if (-not (Test-Path "$BackupRoot\GPO_Backups")) {
        New-Item -ItemType Directory -Path "$BackupRoot\GPO_Backups" -Force | Out-Null
    }

    # 1. Backup Domain Password Policy
    try {
        $domain = (Get-ADDomain).DistinguishedName
        $currPassPol = Get-ADDefaultDomainPasswordPolicy -Identity $domain
        $currPassPol | Export-Clixml -Path "$BackupRoot\DefaultDomainPasswordPolicy_Backup.xml"
        Write-Output "  [+] Backed up Default Domain Password Policy."
    } catch {
        Write-Output "  [-] Failed to backup domain password policy: $_"
    }

    # 2. Backup Machine Account Quota
    try {
        $domainDN = Get-DomainDN
        $domainEntry = [ADSI]"LDAP://$domainDN"
        $currentQuota = $domainEntry.Properties["ms-DS-MachineAccountQuota"].Value
        if ($null -eq $currentQuota) { $currentQuota = 10 }
        @{ MachineAccountQuota = [int]$currentQuota } | Export-Clixml -Path "$BackupRoot\MachineAccountQuota_Backup.xml"
        Write-Output ("  [+] Backed up ms-DS-MachineAccountQuota (Current: {0})." -f $currentQuota)
    } catch {
        Write-Output "  [-] Failed to backup MachineAccountQuota: $_"
    }

    # 3. Backup all active GPOs in the domain
    try {
        $backupResult = Backup-Gpo -All -Path "$BackupRoot\GPO_Backups"
        Write-Output ("  [+] Successfully backed up {0} Group Policy Object(s) to {1}\GPO_Backups" -f $backupResult.Count, $BackupRoot)
    } catch {
        Write-Output "  [-] GPO backup error: $_"
    }
}

# ====================================================================
# ROLLBACK ENGINE
# ====================================================================

function Invoke-GPORestoration {
    Write-Output "================================================================="
    Write-Output "          RESTORING GPOs, QUOTA & PASSWORD POLICY                "
    Write-Output "================================================================="

    $domainDN = Get-DomainDN
    if (-not $domainDN) {
        Write-Output "[-] Cannot contact Active Directory. Restoration aborted."
        return
    }

    # 1. Unlink and remove the hardening GPO
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Output ("[*] Unlinking and removing '{0}'..." -f $GpoName)
        Remove-GPLink -Name $GpoName -Target $domainDN -ErrorAction SilentlyContinue | Out-Null
        Remove-GPO -Name $GpoName -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Output ("  [+] Removed GPO: {0}" -f $GpoName)
    }

    # 2. Restore Machine Account Quota
    $quotaFile = "$BackupRoot\MachineAccountQuota_Backup.xml"
    if (Test-Path $quotaFile) {
        Write-Output "[*] Restoring ms-DS-MachineAccountQuota from backup..."
        try {
            $savedQuota = (Import-Clixml -Path $quotaFile).MachineAccountQuota
            $domainEntry = [ADSI]"LDAP://$domainDN"
            $domainEntry.Put("ms-DS-MachineAccountQuota", [int]$savedQuota)
            $domainEntry.SetInfo()
            Write-Output ("  [+] Restored ms-DS-MachineAccountQuota to: {0}" -f $savedQuota)
        } catch {
            Write-Output "  [-] Failed to restore MachineAccountQuota: $_"
        }
    }

    # 3. Restore Original Domain Password Policy
    $passFile = "$BackupRoot\DefaultDomainPasswordPolicy_Backup.xml"
    if (Test-Path $passFile) {
        Write-Output "[*] Restoring Default Domain Password Policy from backup..."
        try {
            $savedPol = Import-Clixml -Path $passFile
            Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
                -MinPasswordLength $savedPol.MinPasswordLength `
                -ComplexityEnabled $savedPol.ComplexityEnabled `
                -MinPasswordAge $savedPol.MinPasswordAge `
                -MaxPasswordAge $savedPol.MaxPasswordAge `
                -PasswordHistoryCount $savedPol.PasswordHistoryCount `
                -LockoutThreshold $savedPol.LockoutThreshold `
                -ErrorAction Stop
            Write-Output "  [+] Restored Original Password Policy settings."
        } catch {
            Write-Output "  [-] Failed to restore password policy: $_"
        }
    }

    # 4. Restore all original GPOs from backup
    if (Test-Path "$BackupRoot\GPO_Backups") {
        Write-Output "[*] Restoring GPOs from backup directory..."
        try {
            Restore-Gpo -All -Path "$BackupRoot\GPO_Backups" -ErrorAction SilentlyContinue | Out-Null
            Write-Output "  [+] Restored original GPOs."
        } catch {
            Write-Output "  [-] Failed to restore GPOs from backup: $_"
        }
    }

    Write-Output "`n[*] Triggering local policy refresh..."
    gpupdate /force | Out-Null
    Write-Output "[+] GPO Restoration sequence completed."
}

# ====================================================================
# HARDENING ENGINE
# ====================================================================

function Invoke-GPOHardening {
    $domainDN = Get-DomainDN
    if (-not $domainDN) {
        Write-Output "[-] Error: Active Directory unavailable. Run this script on the DC (vattar)."
        return
    }

    Backup-AllGPOs
    $global:auditLog.Clear()

    Write-Output "`n================================================================="
    Write-Output "       CREATING & APPLYING HARDENED BASELINE GROUP POLICY        "
    Write-Output "================================================================="

    # 1. Machine Account Quota (NoPac Defense)
    Write-Output "`n[+] [1/5] Hardening Machine Account Quota (NoPac Defense)..."
    try {
        Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{"ms-DS-MachineAccountQuota" = "0"} -ErrorAction Stop | Out-Null
        Add-AuditEntry "Active Directory" "MachineAccountQuota" "Vulnerable (Default: 10)" "Set ms-DS-MachineAccountQuota to 0"
        Write-Output "    -> ms-DS-MachineAccountQuota set to 0 (Standard users cannot add domain computers)."
    } catch {
        try {
            $domainEntry = [ADSI]"LDAP://$domainDN"
            $domainEntry.Put("ms-DS-MachineAccountQuota", 0)
            $domainEntry.SetInfo()
            Add-AuditEntry "Active Directory" "MachineAccountQuota" "Vulnerable (Default: 10)" "Set ms-DS-MachineAccountQuota to 0 (via ADSI)"
            Write-Output "    -> ms-DS-MachineAccountQuota set to 0 (via ADSI)."
        } catch {
            Write-Output "    [-] Failed setting MachineAccountQuota: $_"
        }
    }

    # 2. Harden Domain Password Policy (Safe for CCDC Scoring)
    Write-Output "`n[+] [2/5] Applying Scoring-Safe Domain Password Policy..."
    try {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
            -MinPasswordLength 14 `
            -ComplexityEnabled $true `
            -MinPasswordAge "00:00:00" `
            -PasswordHistoryCount 10 `
            -LockoutThreshold 0 `
            -ErrorAction Stop

        Add-AuditEntry "Password Policy" "Domain Policy" "Vulnerable/Default" "Min Length: 14, Complexity: On, Lockout: 0 (Anti-DoS), Min Age: 0"
        Write-Output "    -> Min Password Length: 14"
        Write-Output "    -> Complexity: Enabled"
        Write-Output "    -> Min Password Age: 0 (Allows immediate password changes)"
        Write-Output "    -> Lockout Threshold: 0 (Disabled to prevent Red Team SLA DoS)"
    } catch {
        Write-Output "    [-] Error setting domain password policy: $_"
    }

    # 3. Create or Reset Hardened Baseline GPO
    Write-Output "`n[+] [3/5] Initializing Baseline GPO: '$GpoName'..."
    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $GpoName -Comment "CCDC Baseline Hardening Policy"
        Write-Output ("    -> Created new GPO: " + $GpoName)
    } else {
        Write-Output ("    -> Existing GPO found: " + $GpoName)
    }

    # 4. Configure Safe Hardening Registry Entries inside the GPO
    Write-Output "`n[+] [4/5] Writing Hardened Registry Policies to GPO..."

    $regSettings = @(
        # --- RDP Hardening (Single Session, NLA) ---
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            Name = "fSingleSessionPerUser"; Type = "DWord"; Value = 1
            Target = "RDP Sessions"; Desc = "Limit each user to 1 active session"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            Name = "MaxInstanceCount"; Type = "DWord"; Value = 1
            Target = "RDP Connections"; Desc = "Limit max concurrent connections to 1"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            Name = "UserAuthentication"; Type = "DWord"; Value = 1
            Target = "RDP NLA"; Desc = "Enforce Network Level Authentication"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            Name = "fDenyTSConnections"; Type = "DWord"; Value = 0
            Target = "RDP Status"; Desc = "Ensure RDP remains enabled for admin access"
        },

        # --- Allow Member Servers (Borgar) to Edit Their Local Firewalls ---
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
            Name = "AllowLocalPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local admin firewall rules (Domain Profile)"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
            Name = "AllowLocalIPsecPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local IPsec rules (Domain Profile)"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
            Name = "AllowLocalPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local admin firewall rules (Private Profile)"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
            Name = "AllowLocalIPsecPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local IPsec rules (Private Profile)"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            Name = "AllowLocalPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local admin firewall rules (Public Profile)"
        },
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
            Name = "AllowLocalIPsecPolicyMerge"; Type = "DWord"; Value = 1
            Target = "Firewall GPO"; Desc = "Allow local IPsec rules (Public Profile)"
        },

        # --- Responder / LLMNR Defense ---
        @{
            Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
            Name = "EnableMulticast"; Type = "DWord"; Value = 0
            Target = "Protocols"; Desc = "Disable LLMNR Multicast Resolution"
        },

        # --- LSASS & Credential Protection ---
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RunAsPPL"; Type = "DWord"; Value = 1
            Target = "LSASS"; Desc = "Enable LSA Protected Process Light (Anti-Mimikatz)"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "LimitBlankPasswordUse"; Type = "DWord"; Value = 1
            Target = "Auth"; Desc = "Prevent network logons using blank passwords"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RestrictAnonymousSAM"; Type = "DWord"; Value = 1
            Target = "Recon"; Desc = "Restrict anonymous enumeration of SAM accounts"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RestrictAnonymous"; Type = "DWord"; Value = 1
            Target = "Recon"; Desc = "Restrict anonymous enumeration of shares"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "EveryoneIncludesAnonymous"; Type = "DWord"; Value = 0
            Target = "Permissions"; Desc = "Exclude Anonymous users from Everyone permissions"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            Name = "UseLogonCredential"; Type = "DWord"; Value = 0
            Target = "Credentials"; Desc = "Disable WDigest plaintext credential caching"
        },

        # --- SMB Hardening ---
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Name = "SMB1"; Type = "DWord"; Value = 0
            Target = "Protocols"; Desc = "Disable SMBv1 (Anti-EternalBlue)"
        },
        @{
            Key = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            Name = "RequireSecuritySignature"; Type = "DWord"; Value = 1
            Target = "SMB Signing"; Desc = "Enforce SMB packet signing (Anti-NTLM Relay)"
        },

        # --- Process Auditing ---
        @{
            Key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            Name = "ProcessCreationIncludeCmdLine_Enabled"; Type = "DWord"; Value = 1
            Target = "Auditing"; Desc = "Log full command line in Process Creation events"
        }
    )

    foreach ($s in $regSettings) {
        try {
            Set-GPRegistryValue -Name $GpoName -Key $s.Key -ValueName $s.Name -Type $s.Type -Value $s.Value | Out-Null
            Add-AuditEntry $s.Target $s.Name "Configured in GPO" $s.Desc
            Write-Output ("    -> [OK] {0}: {1}" -f $s.Name, $s.Desc)
        } catch {
            Write-Output ("    [-] Error applying registry setting {0}: {1}" -f $s.Name, $_.Exception.Message)
        }
    }

    # 5. Link & Enforce GPO at Domain Root
    Write-Output "`n[+] [5/5] Linking GPO to Domain Root ($domainDN)..."
    try {
        New-GPLink -Name $GpoName -Target $domainDN -Enforced Yes -ErrorAction SilentlyContinue | Out-Null
        Set-GPLink -Name $GpoName -Target $domainDN -Enforced Yes -Order 1 -ErrorAction SilentlyContinue | Out-Null
        Write-Output "    -> GPO linked and set to ENFORCED at domain root."
        Add-AuditEntry "GPO Link" $GpoName "Linked to Root" "Set to Enforced (Precedence 1)"
    } catch {
        Write-Output "    [-] Error linking GPO: $_"
    }

    Write-Output "`n[*] Triggering local GPO update on DC..."
    gpupdate /force | Out-Null

    # Final Audit Summary Table
    Write-Output "`n=========================================================================================================="
    Write-Output "                         GPO HARDENING AUDIT REPORT                                                       "
    Write-Output "=========================================================================================================="
    Write-Output ("{0,-16} {1,-30} {2,-20} {3}" -f "CATEGORY", "SETTING / COMPONENT", "STATUS", "DESCRIPTION")
    Write-Output ("{0,-16} {1,-30} {2,-20} {3}" -f "========", "===================", "======", "===========")
    foreach ($entry in $global:auditLog) {
        Write-Output ("{0,-16} {1,-30} {2,-20} {3}" -f $entry.Category, $entry.Target, $entry.StateFound, $entry.ActionTaken)
    }
    Write-Output "=========================================================================================================="
    Write-Output "[+] GPO Hardening completed. Select Option [2] to push to all member servers (e.g. borgar)."
}

# ====================================================================
# PUSH ENGINE (GPUPDATE TO MEMBER SERVERS)
# ====================================================================

function Invoke-PushGPO {
    Write-Output "`n================================================================="
    Write-Output "       PUSHING GROUP POLICY TO ALL DOMAIN WINDOWS COMPUTERS      "
    Write-Output "================================================================="

    $computers = Get-ADComputer -Filter * | Where-Object { $_.Name -ne $env:COMPUTERNAME }
    if (-not $computers -or $computers.Count -eq 0) {
        Write-Output "[-] No remote domain computers discovered in Active Directory."
        return
    }

    Write-Output ("[*] Found {0} remote domain computer(s). Dispatching Invoke-GPUpdate..." -f $computers.Count)

    foreach ($comp in $computers) {
        $cName = $comp.Name
        Write-Output ("`n[*] Pushing GPO to: {0}..." -f $cName)
        try {
            Invoke-GPUpdate -Computer $cName -RandomDelayInMinutes 0 -Force -ErrorAction Stop
            Write-Output ("  [+] Successfully triggered GPUpdate on {0}." -f $cName)
        } catch {
            Write-Output ("  [-] Failed to push GPUpdate to {0}: {1}" -f $cName, $_.Exception.Message)
            Write-Output ("      (Note: Remote RPC/Firewall may block direct push. Run 'gpupdate /force' locally on {0} if needed)" -f $cName)
        }
    }
    Write-Output "`n[+] Policy push sequence completed."
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

Write-Output "`n========================================================"
Write-Output "       CCDC ACTIVE DIRECTORY GPO HARDENING & PUSH       "
Write-Output "========================================================"
Write-Output "[1] Create & Apply Hardened Baseline GPO (Auto-Backs Up GPOs)"
Write-Output "[2] Push GPO Update to All Member Servers (Invoke-GPUpdate)"
Write-Output "[3] Rollback / Restore Original GPOs and Password Policy"
Write-Output "[4] Backup All Existing GPOs Only"
Write-Output "[Q] Quit"
Write-Output "--------------------------------------------------------"

$choice = Read-Host "Select an option [1, 2, 3, 4, Q]"

switch ($choice.ToUpper()) {
    "1" { Invoke-GPOHardening }
    "2" { Invoke-PushGPO }
    "3" { Invoke-GPORestoration }
    "4" { Backup-AllGPOs }
    "Q" { Write-Output "Exiting." }
    Default { Write-Output "[!] Invalid selection. Please enter 1, 2, 3, 4, or Q." }
}
