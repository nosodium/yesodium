<#
.SYNOPSIS
    Active Directory Comprehensive Group & User Auditor, Stripper, & Rollback Engine
.DESCRIPTION
    Compatible with Windows Server 2012 through 2025 (Pure ASCII, ADSI Native).
    - Lists EVERY group in the domain and its members (including hidden/delegated groups).
    - Interactively loops through users to strip excess group memberships.
    - Automatic snapshot and rollback of group memberships via XML.
#>

$ErrorActionPreference = "SilentlyContinue"
$BackupRoot = "C:\CCDC_Hardening_Backup\AD_Groups"
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

function Get-DomainRootDSE {
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        return $rootDSE.defaultNamingContext
    } catch {
        Write-Output "[-] Error: Unable to contact Active Directory. Is this machine domain-joined?"
        return $null
    }
}

# ====================================================================
# BACKUP & ROLLBACK ENGINE
# ====================================================================

function Backup-ADGroupMemberships {
    $domainDN = Get-DomainRootDSE
    if (-not $domainDN) { return $false }

    Write-Output "[*] Generating Pre-Hardening Group Membership Snapshot in: $BackupRoot"
    if (-not (Test-Path $BackupRoot)) {
        New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN")
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "memberof"))
    $results = $searcher.FindAll()

    $userBackups = @()
    foreach ($r in $results) {
        $uProps = $r.Properties
        $groups = @()
        if ($uProps["memberof"]) {
            foreach ($g in $uProps["memberof"]) { $groups += [string]$g }
        }
        $userBackups += [PSCustomObject]@{
            SamAccountName    = [string]$uProps["samaccountname"]
            DistinguishedName = [string]$uProps["distinguishedname"]
            MemberOf          = $groups
        }
    }

    $snapshotFile = "$BackupRoot\GroupMemberships_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    $userBackups | Export-Clixml -Path $snapshotFile
    $userBackups | Export-Clixml -Path "$BackupRoot\LatestGroupBackup.xml"
    Write-Output ("  [+] Snapshot saved to: " + $snapshotFile)
    return $true
}

function Invoke-GroupRestoration {
    Write-Output "================================================================="
    Write-Output "         RESTORING USER GROUP MEMBERSHIPS FROM BACKUP            "
    Write-Output "================================================================="

    $backupFile = "$BackupRoot\LatestGroupBackup.xml"
    if (-not (Test-Path $backupFile)) {
        Write-Output "[-] No backup found at $backupFile. Restoration aborted."
        return
    }

    $backupData = Import-Clixml -Path $backupFile
    Write-Output ("[*] Loaded backup containing {0} users." -f $backupData.Count)

    $restoredCount = 0
    foreach ($item in $backupData) {
        if ($item.MemberOf -and $item.MemberOf.Count -gt 0) {
            foreach ($grpDN in $item.MemberOf) {
                try {
                    $grpEntry = [ADSI]"LDAP://$grpDN"
                    $grpEntry.Add("LDAP://" + $item.DistinguishedName)
                    $grpEntry.SetInfo()
                    $restoredCount++
                    Write-Output ("  [+] Restored {0} -> {1}" -f $item.SamAccountName, ($grpDN -split ",*..=")[1])
                } catch {}
            }
        }
    }
    Write-Output "`n================================================================="
    Write-Output ("  [+] Restoration complete. Restored {0} group associations." -f $restoredCount)
    Write-Output "================================================================="
}

# ====================================================================
# AUDIT ENGINE: ALL GROUPS & ALL MEMBERS
# ====================================================================

function Invoke-AuditAllGroups {
    $domainDN = Get-DomainRootDSE
    if (-not $domainDN) { return }

    Write-Output "`n================================================================="
    Write-Output "            ACTIVE DIRECTORY COMPLETE GROUP & MEMBER AUDIT       "
    Write-Output "================================================================="

    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN")
    $searcher.Filter = "(objectCategory=group)"
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "admincount", "description", "member"))
    $groups = $searcher.FindAll()

    Write-Output ("[*] Discovered {0} total groups in Active Directory.`n" -f $groups.Count)

    # Sensitive/Privileged identifiers for tagging
    $sensitiveNames = @(
        "admin", "account operators", "backup operators", "server operators",
        "print operators", "dnsadmins", "group policy creator owners",
        "remote desktop", "remote management", "cryptographic", "hyper-v"
    )

    $groupIndex = 1
    foreach ($g in ($groups | Sort-Object { $_.Properties["samaccountname"][0] })) {
        $gProps = $g.Properties
        $sName = [string]$gProps["samaccountname"]
        $gDN = [string]$gProps["distinguishedname"]
        $desc = if ($gProps["description"]) { [string]$gProps["description"][0] } else { "No description" }
        $adminCount = if ($gProps["admincount"]) { [int]$gProps["admincount"][0] } else { 0 }

        # Determine privilege tag
        $isHighPriv = ($adminCount -eq 1)
        foreach ($pattern in $sensitiveNames) {
            if ($sName -match $pattern) { $isHighPriv = $true; break }
        }

        $privTag = if ($isHighPriv) { "[!!! HIGH PRIVILEGE !!!]" } else { "[STANDARD]" }

        Write-Output ("--------------------------------------------------------------------------------------------------")
        Write-Output ("[{0}/{1}] Group: {2,-30} {3}" -f $groupIndex, $groups.Count, $sName, $privTag)
        Write-Output ("      DN:          {0}" -f $gDN)
        Write-Output ("      Description: {0}" -f $desc)

        $members = @()
        if ($gProps["member"]) {
            foreach ($m in $gProps["member"]) { $members += [string]$m }
        }

        if ($members.Count -eq 0) {
            Write-Output "      Members:     (EMPTY GROUP)"
        } else {
            Write-Output ("      Members ({0}):" -f $members.Count)
            foreach ($mDN in $members) {
                # Extract CN for compact display
                $cn = ($mDN -split ",*..=")[1]
                Write-Output ("        -> {0,-25} ({1})" -f $cn, $mDN)
            }
        }
        $groupIndex++
    }
    Write-Output "=================================================================================================="
    Write-Output "[*] Group Audit completed."
}

# ====================================================================
# INTERACTIVE USER GROUP STRIPPER
# ====================================================================

function Invoke-InteractiveUserStrip {
    $domainDN = Get-DomainRootDSE
    if (-not $domainDN) { return }

    Write-Output "`n[*] Initiating Pre-Hardening Snapshot before modification..."
    $backedUp = Backup-ADGroupMemberships
    if (-not $backedUp) {
        Write-Output "[-] Backup failed. Aborting user strip for safety."
        return
    }

    $global:auditLog.Clear()

    Write-Output "`n================================================================="
    Write-Output "          INTERACTIVE ACTIVE DIRECTORY USER AUDIT & STRIP        "
    Write-Output "================================================================="
    Write-Output "NOTE: Primary group (e.g., Domain Users) is preserved by Windows."
    Write-Output "Only secondary group memberships (memberOf) will be stripped."
    Write-Output "=================================================================`n"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN")
    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "memberof", "useraccountcontrol", "admincount"))
    $allUsers = $searcher.FindAll() | Sort-Object { $_.Properties["samaccountname"][0] }

    $totalUsers = $allUsers.Count
    $currentUserIndex = 1

    foreach ($u in $allUsers) {
        $uProps = $u.Properties
        $sName = [string]$uProps["samaccountname"]
        $uDN = [string]$uProps["distinguishedname"]
        $uac = if ($uProps["useraccountcontrol"]) { [int]$uProps["useraccountcontrol"][0] } else { 0 }
        $isDisabled = ($uac -band 2) -ne 0
        $statusStr = if ($isDisabled) { "DISABLED" } else { "ACTIVE" }

        $groups = @()
        if ($uProps["memberof"]) {
            foreach ($g in $uProps["memberof"]) { $groups += [string]$g }
        }

        Write-Output ("`n==================================================================================================")
        Write-Output ("User [{0}/{1}]: {2,-25} [Status: {3}]" -f $currentUserIndex, $totalUsers, $sName, $statusStr)
        Write-Output ("DN: {0}" -f $uDN)

        # Safety warnings for user
        if ($sName.ToLower() -eq $env:USERNAME.ToLower()) {
            Write-Output "  [!] WARNING: THIS IS YOUR CURRENTLY LOGGED-IN ACCOUNT!"
        }
        if ($sName.ToLower() -eq "krbtgt") {
            Write-Output "  [*] System default account (krbtgt). Usually untouched."
        }

        if ($groups.Count -eq 0) {
            Write-Output "  -> Group Memberships: None (Only in Primary Group: Domain Users)"
            Write-Output "  -> Skipping prompt (Already clean)."
            Add-AuditEntry "User Audit" $sName "Clean (Only Primary Group)" "No Action Needed"
            $currentUserIndex++
            continue
        }

        Write-Output ("  -> Current Secondary Groups ({0}):" -f $groups.Count)
        foreach ($grpDN in $groups) {
            $cn = ($grpDN -split ",*..=")[1]
            Write-Output ("       - {0,-30} ({1})" -f $cn, $grpDN)
        }

        # Prompt
        $resp = Read-Host "`nStrip ALL ($($groups.Count)) secondary groups from '$sName'? [Y = Yes, N = Skip, Q = Quit to Menu]"
        
        if ($resp.ToUpper() -eq "Q") {
            Write-Output "[*] User requested exit. Returning to menu..."
            break
        } elseif ($resp.ToUpper() -eq "Y") {
            $strippedCount = 0
            foreach ($grpDN in $groups) {
                try {
                    $grpEntry = [ADSI]"LDAP://$grpDN"
                    $grpEntry.Remove("LDAP://$uDN")
                    $grpEntry.SetInfo()
                    $strippedCount++
                } catch {
                    Write-Output ("    [-] Failed removing from {0}: {1}" -f ($grpDN -split ",*..=")[1], $_.Exception.Message)
                }
            }
            Write-Output ("  [+] Removed {0}/{1} groups from {2}." -f $strippedCount, $groups.Count, $sName)
            Add-AuditEntry "Group Stripping" $sName ("Had " + $groups.Count + " groups") ("Successfully stripped " + $strippedCount + " groups")
        } else {
            Write-Output ("  [*] Skipped {0}. No groups changed." -f $sName)
            Add-AuditEntry "User Audit" $sName ("Retained " + $groups.Count + " groups") "User skipped by operator"
        }

        $currentUserIndex++
    }

    # Audit Summary
    Write-Output "`n=========================================================================================================="
    Write-Output "                               USER GROUP AUDIT SUMMARY REPORT                                            "
    Write-Output "=========================================================================================================="
    Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f "CATEGORY", "USER ACCOUNT", "STATE FOUND", "ACTION TAKEN")
    Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f "========", "============", "===========", "============")
    foreach ($entry in $global:auditLog) {
        Write-Output ("{0,-16} {1,-26} {2,-30} {3}" -f $entry.Category, $entry.Target, $entry.StateFound, $entry.ActionTaken)
    }
    Write-Output "=========================================================================================================="
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

Write-Output "`n========================================================"
Write-Output "       CCDC ACTIVE DIRECTORY GROUP AUDIT & STRIPPER     "
Write-Output "========================================================"
Write-Output "[1] Audit & List ALL AD Groups and Their Members"
Write-Output "[2] Interactively Audit Users & Strip Groups (with Auto-Backup)"
Write-Output "[3] Rollback / Restore User Group Memberships from Backup"
Write-Output "[Q] Quit"
Write-Output "--------------------------------------------------------"

$choice = Read-Host "Select an option [1, 2, 3, Q]"

switch ($choice.ToUpper()) {
    "1" { Invoke-AuditAllGroups }
    "2" { Invoke-InteractiveUserStrip }
    "3" { Invoke-GroupRestoration }
    "Q" { Write-Output "Exiting." }
    Default { Write-Output "[!] Invalid selection. Please enter 1, 2, 3, or Q." }
}
