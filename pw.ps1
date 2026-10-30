<#
.SYNOPSIS
    Interactive Controlled Credential Rotation (Server 2012-2025 Compatible)
.DESCRIPTION
    Zero pipeline delays, pure ASCII, no coloring parameters.
#>

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

function Set-UserCredentialPrompt {
    param(
        [string]$Username,
        [string]$Type
    )

    # Embed username and account type directly into the prompt to prevent buffer desync
    $promptMsg = "`nChange password for [" + $Type + "] '" + $Username + "'? ([Y]es / [S]kip / [Q]uit)"
    $choice = Read-Host $promptMsg
    
    if ($choice -eq 'Q' -or $choice -eq 'q') { return $false }
    if ($choice -ne 'Y' -and $choice -ne 'y') { 
        [Console]::WriteLine("Skipped " + $Username + ".")
        return $true 
    }

    $passSecure = Read-Host "Enter new password for '$Username' (masked)" -AsSecureString
    
    # PS 4.0 / Server 2012 R2 compatible credential conversion
    $passPlain = (New-Object System.Net.NetworkCredential('', $passSecure)).Password

    if ([string]::IsNullOrWhiteSpace($passPlain)) {
        [Console]::WriteLine("Password cannot be empty. Skipping.")
        return $true
    }

    try {
        if ($Type -eq "Local") {
            $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Username,user"
            $user.SetPassword($passPlain)
            $user.SetInfo()
            [Console]::WriteLine("[+] Local account " + $Username + " password successfully updated.")
        } elseif ($Type -eq "Domain") {
            Set-ADAccountPassword -Identity $Username -NewPassword $passSecure -Reset $true
            Set-ADUser -Identity $Username -PasswordNeverExpires $true -CannotChangePassword $true
            [Console]::WriteLine("[+] Domain account " + $Username + " password successfully updated.")
        }
    } catch {
        [Console]::WriteLine("[-] Failed to set password for " + $Username + " - " + $_.Exception.Message)
    }
    return $true
}

[Console]::WriteLine("=== CCDC INTERACTIVE CREDENTIAL ROTATION ===")

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

[Console]::WriteLine("`n[+] Credential rotation pass complete.")
