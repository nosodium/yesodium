function Show-UsersAndGroups {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               USERS AND PRIVILEGED GROUPS                       " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    Write-Host "`n[+] LOCAL ACCOUNTS (MEMBER SERVERS / STANDALONE)" -ForegroundColor Yellow
    $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    if ($localUsers) {
        foreach ($user in $localUsers) {
            Write-Output ("Account: {0,-25} | Disabled: {1,-5} | PasswordChangeable: {2}" -f $user.Name, $user.Disabled, $user.PasswordChangeable)
        }
    } else {
        Write-Host "No local SAM accounts found (Standard behavior for Domain Controllers)." -ForegroundColor DarkGray
    }

    Write-Host "`n[+] LOCAL / BUILTIN ADMINISTRATORS" -ForegroundColor Yellow
    try {
        $adminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction Stop
        $admins = Get-CimInstance -Query "ASSOCIATORS OF {Win32_Group.Domain='$($env:COMPUTERNAME)',Name='$($adminGroup.Name)'} WHERE ResultClass=Win32_UserAccount"
        Write-Output ("Members: {0}" -f ($admins.Name -join ', '))
    } catch {
        $netAdmin = (net localgroup administrators | Select-Object -Skip 6) -notmatch "The command completed" | Where-Object { $_ -ne "" }
        Write-Output ("Members: {0}" -f ($netAdmin -join ', '))
    }

    # Domain Controller / Active Directory Queries
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Host "`n[+] ACTIVE DIRECTORY PRIVILEGED GROUPS" -ForegroundColor Yellow
        try {
            $da = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
            Write-Output ("Domain Admins     : {0}" -f ($da -join ', '))
        } catch {
            $netDA = (net group "Domain Admins" /domain 2>$null | Select-Object -Skip 6) -notmatch "The command completed" | Where-Object { $_ -ne "" }
            Write-Output ("Domain Admins     : {0}" -f ($netDA -join ', '))
        }

        try {
            $ea = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
            Write-Output ("Enterprise Admins : {0}" -f ($ea -join ', '))
        } catch {
            $netEA = (net group "Enterprise Admins" /domain 2>$null | Select-Object -Skip 6) -notmatch "The command completed" | Where-Object { $_ -ne "" }
            Write-Output ("Enterprise Admins : {0}" -f ($netEA -join ', '))
        }

        # ALL DOMAIN USERS ACROSS ALL OUs
        Write-Host "`n[+] ALL DOMAIN USERS (RECURSIVE SEARCH ACROSS ALL OUs)" -ForegroundColor Yellow
        $userObjects = @()

        # Method 1: ActiveDirectory module
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            $userObjects = Get-ADUser -Filter * -Properties DistinguishedName, Enabled -ErrorAction SilentlyContinue | ForEach-Object {
                # Extract parent OU / container path from DistinguishedName
                $ouPath = ($_.DistinguishedName -split ',', 2)[1]
                [PSCustomObject]@{
                    SamAccountName = $_.SamAccountName
                    Name           = $_.Name
                    Enabled        = $_.Enabled
                    OU             = $ouPath
                }
            }
        }
        
        # Method 2: ADSI Fallback (Strict human account filter across domain root)
        if (-not $userObjects -or $userObjects.Count -eq 0) {
            try {
                $rootDSE = [ADSI]"LDAP://RootDSE"
                $defaultNamingContext = $rootDSE.defaultNamingContext
                $searcher = [System.DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$defaultNamingContext")
                $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
                $searcher.PageSize = 1000
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                
                $results = $searcher.FindAll()
                foreach ($r in $results) {
                    $dn = [string]$r.Properties["distinguishedname"]
                    $ouPath = ($dn -split ',', 2)[1]
                    $userObjects += [PSCustomObject]@{
                        SamAccountName = [string]$r.Properties["samaccountname"]
                        Name           = [string]$r.Properties["name"]
                        Enabled        = (-not ([int]$r.Properties["useraccountcontrol"][0] -band 2))
                        OU             = $ouPath
                    }
                }
            } catch {}
        }

        if ($userObjects.Count -gt 0) {
            # 1. Comma-separated list for easy documentation copy-pasting
            $namesOnly = ($userObjects | Select-Object -ExpandProperty SamAccountName) -join ', '
            Write-Output ("Accounts List: " + $namesOnly)

            # 2. OU breakdown table to audit rogue accounts in hidden OUs
            Write-Host "`n{0,-25} {1,-8} {2}" -f "USER ACCOUNT", "ENABLED", "ORGANIZATIONAL UNIT / PATH" -ForegroundColor White
            Write-Host "{0,-25} {1,-8} {2}" -f "============", "=======", "===========================" -ForegroundColor Gray
            foreach ($u in ($userObjects | Sort-Object OU, SamAccountName)) {
                $color = if ($u.Enabled) { "White" } else { "DarkGray" }
                Write-Host ("{0,-25} {1,-8} {2}" -f $u.SamAccountName, $u.Enabled, $u.OU) -ForegroundColor $color
            }
        } else {
            Write-Host "Could not query Active Directory user accounts." -ForegroundColor Red
        }
    }
}
