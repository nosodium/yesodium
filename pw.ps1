<#
.SYNOPSIS
    Interactive Controlled Credential Rotation (Server 2012-2025 Compatible)
.DESCRIPTION
    Zero non-ASCII symbols. 100% pure ASCII text.
#>

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Set-UserCredentialPrompt {
    param(
        [string]$Username,
        [string]$Type
    )

    Write-Output "`nTarget Account [$Type]: $Username"
    $choice = Read-Host "Change password for this user? ([Y]es / [S]kip / [Q]uit)"
    
    if ($choice -eq 'Q' -or $choice -eq 'q') { return $false }
    if ($choice -ne 'Y' -and $choice -ne 'y') { 
        Write-Output "Skipped $Username."
        return $true 
    }

    $passSecure = Read-Host "Enter new password (masked)" -AsSecureString
    
    # PS 4.0 / Server 2012 R2 compatible conversion
    $passPlain = (New-Object System.Net.NetworkCredential('', $passSecure)).Password

    if ([string]::IsNullOrWhiteSpace($passPlain)) {
        Write-Output "Password cannot be empty. Skipping."
        return $true
    }

    try {
        if ($Type -eq "Local") {
            $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Username,user"
            $user.SetPassword($passPlain)
            $user.SetInfo()
            Write-Output "[+] Local account $Username password successfully updated."
        } elseif ($Type -eq "Domain") {
            Set-ADAccountPassword -Identity $Username -NewPassword $passSecure -Reset $true
            Set-ADUser -Identity $Username -PasswordNeverExpires $true -CannotChangePassword $true
            Write-Output "[+] Domain account $Username password successfully updated."
        }
    } catch {
        # Fixed: Isolated string variables to prevent colon scope errors
        Write-Output ("[-] Failed to set password for {0}: {1}" -f $Username, $_.Exception.Message)
    }
    return $true
}

Write-Output "=== CCDC INTERACTIVE CREDENTIAL ROTATION ==="

# 1. Local Accounts (Member servers and standalone hosts)
$localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
if ($localUsers) {
    foreach ($lUser in $localUsers) {
        $continue = Set-UserCredentialPrompt -Username $lUser -Type "Local"
        if (-not $continue) { break }
    }
}

# 2. Domain Admins (Domain Controllers)
if (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
    if ($domainAdmins) {
        foreach ($dAdmin in $domainAdmins) {
            $continue = Set-UserCredentialPrompt -Username $dAdmin -Type "Domain"
            if (-not $continue) { break }
        }
    }
}

Write-Output "`n[+] Credential rotation pass complete."
