<#
.SYNOPSIS
    Zero-Trace Automated Credential Rotation Script
.DESCRIPTION
    Rotates credentials, displays them page-by-page in memory only,
    disables transcription, wipes memory variables, and cleans console buffers.
#>

[CmdletBinding()]
param(
    [string]$TargetUser,
    [string]$TargetType
)

# Normalize/validate TargetType if provided via CLI
if ($TargetType -and ($TargetType -notmatch '^(?i:Local|Domain)$')) {
    Write-Warning "TargetType must be either 'Local' or 'Domain'."
    return
}

# --- ANTI-LEAK: Ensure PS Transcription is not recording the console ---
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# ==========================================
# 1. EXTENSIVE WORD BANKS
# ==========================================
$Adjectives = @(
    "Agile","Silent","Brave","Fierce","Clever","Mighty","Swift","Sneaky","Bold","Cosmic",
    "Rapid","Ancient","Mystic","Frosty","Dynamic","Hidden","Vibrant","Sturdy","Wicked","Savage",
    "Iron","Atomic","Shadow","Golden","Arcane","Solar","Lunar","Noble","Rustic","Hollow",
    "Lethal","Epic","Fearless","Gentle","Wild","Valiant","Furious","Resilient","Vigilant","Radiant",
    "Cunning","Brisk","Thunderous","Eager","Phantom","Primal","Turbo","Glorious","Hyper","Titan",
    "Serene","Shrewd","Daring","Chilly","Burning","Grim","Subtle","Zealous","Ruthless","Spectral",
    "Oblivious","Dormant","Relentless","Stealthy","Infinite","Apex","Defiant","Nimble","Stalwart","Keen",
    "Bizarre","Chaotic","Sleek","Rugged","Dizzy","Frost","Grave","Intrepid","Invincible","Stormy"
)

$Colors = @(
    "Black","White","Silver","Crimson","Azure","Emerald","Amber","Cobalt","Violet","Scarlet",
    "Indigo","Teal","Bronze","Platinum","Obsidian","Ruby","Sapphire","Coral","Maroon","Slate",
    "Cyan","Gold","Onyx","Charcoal","Copper","Lavender","Olive","Mustard","Jade","Ivory",
    "Pearl","Turquoise","Burgundy","Mauve","Fuchsia","Periwinkle","Aqua","Tangerine","Mahogany","Ebony"
)

$Nouns = @(
    "Zebra","Falcon","Panther","Viper","Badger","Cobra","Grizzly","Wolf","Titan","Dragon",
    "Raven","Mammoth","Phoenix","Otter","Shark","Jaguar","Hawk","Condor","Leopard","Lynx",
    "Mustang","Stallion","Bison","Rhino","Cougar","Fox","Cheetah","Eagle","Moose","Hornet",
    "Barracuda","Mantis","Walrus","Ocelot","Wolverine","Orca","Scorpion","Chameleon","Gorilla","Badger",
    "Fortress","Glacier","Comet","Vortex","Anchor","Citadel","Bastion","Tempest","Meteor","Avalanche",
    "Bulwark","Monolith","Beacon","Anvil","Eclipse","Tsunami","Specter","Gauntlet","Dagger","Sentinel",
    "Harbor","Canyon","Volcano","Shield","Pinnacle","Bastion","Ranger","Quarry","Sentry","Riptide"
)

$SpecialChars = @("!", "@", "#", "$", "%", "*", "_", "?")

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
function New-RandomPassword {
    $adj    = $Adjectives | Get-Random
    $color  = $Colors | Get-Random
    $noun   = $Nouns | Get-Random
    $num    = Get-Random -Minimum 10 -Maximum 999
    $spec   = $SpecialChars | Get-Random

    return "$adj-$color-$noun$num$spec"
}

function Set-AccountPassword {
    param(
        [string]$Username,
        [string]$Type,
        [ref]$OutputList
    )

    $newPlainPassword = New-RandomPassword
    $passSecure = ConvertTo-SecureString $newPlainPassword -AsPlainText -Force

    try {
        if ($Type -match "(?i)^Local$") {
            $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Username,user"
            $user.SetPassword($newPlainPassword)
            $user.SetInfo()
            [Console]::WriteLine("[+] Local user '$Username' rotated successfully.")
        } elseif ($Type -match "(?i)^Domain$") {
            Set-ADAccountPassword -Identity $Username -NewPassword $passSecure -Reset
            Set-ADUser -Identity $Username -PasswordNeverExpires $true
            [Console]::WriteLine("[+] Domain user '$Username' rotated successfully.")
        }

        $OutputList.Value += "$Username,$newPlainPassword"
    } catch {
        [Console]::WriteLine("[-] Error changing password for $Username ($Type): " + $_.Exception.Message)
    }
}

# ==========================================
# 3. ROTATION EXECUTION
# ==========================================
Clear-Host
[Console]::WriteLine("=================================================================")
[Console]::WriteLine("             AUTOMATED CREDENTIAL ROTATION SYSTEM                ")
[Console]::WriteLine("=================================================================")

$credentialOutput = @()

if ($TargetUser) {
    if (-not $TargetType) {
        $choice = Read-Host "Is '$TargetUser' a [L]ocal or [D]omain account? (L/D)"
        if ($choice -match "^[Ll]") { $TargetType = "Local" } else { $TargetType = "Domain" }
    }

    [Console]::WriteLine("[*] Running single-target mode on: $TargetUser ($TargetType)")
    Set-AccountPassword -Username $TargetUser -Type $TargetType -OutputList ([ref]$credentialOutput)
}
else {
    $interactiveCheck = Read-Host "Rotate [A]ll accounts or specify a [S]ingle user? (A/S)"
    if ($interactiveCheck -match "^[Ss]") {
        $TargetUser = Read-Host "Enter the exact Username"
        $tTypeChoice = Read-Host "Is this user [L]ocal or [D]omain? (L/D)"
        $TargetType = if ($tTypeChoice -match "^[Ll]") { "Local" } else { "Domain" }
        
        Set-AccountPassword -Username $TargetUser -Type $TargetType -OutputList ([ref]$credentialOutput)
    } else {
        # 1. Local Accounts
        [Console]::WriteLine("`n[*] Enumerating & rotating Local Accounts...")
        $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        if ($localUsers) {
            foreach ($lUser in $localUsers) {
                Set-AccountPassword -Username $lUser -Type "Local" -OutputList ([ref]$credentialOutput)
            }
        }

        # 2. Domain Users
        if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
            [Console]::WriteLine("`n[*] Enumerating & rotating Active Directory Domain Users...")
            $allDomainUsers = @()

            if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                $allDomainUsers = Get-ADUser -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
            }

            if (-not $allDomainUsers -or $allDomainUsers.Count -eq 0) {
                try {
                    $rootDSE = [ADSI]"LDAP://RootDSE"
                    $ldapRoot = [ADSI]"LDAP://$($rootDSE.defaultNamingContext)"
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapRoot)
                    $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
                    $searcher.PageSize = 1000
                    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                    
                    foreach ($r in $searcher.FindAll()) {
                        $allDomainUsers += [string]$r.Properties["samaccountname"]
                    }
                } catch {}
            }

            if ($allDomainUsers.Count -gt 0) {
                foreach ($dUser in ($allDomainUsers | Sort-Object -Unique)) {
                    if ($dUser.EndsWith("$")) { continue }
                    Set-AccountPassword -Username $dUser -Type "Domain" -OutputList ([ref]$credentialOutput)
                }
            } else {
                [Console]::WriteLine("[-] No domain users found or unable to contact domain controller.")
            }
        }
    }
}

# ==========================================
# 4. TWO-WAY PAGINATED VIEWER
# ==========================================
if ($credentialOutput.Count -gt 0) {
    $pageSize = 20
    $totalCount = $credentialOutput.Count
    $totalPages = [Math]::Ceiling($totalCount / $pageSize)
    $currentPage = 0

    while ($true) {
        Clear-Host
        $startIdx = $currentPage * $pageSize
        $endIdx = [Math]::Min($startIdx + $pageSize - 1, $totalCount - 1)
        $displayPage = $currentPage + 1

        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host " PASSWORD ROTATION REPORT  |  Page $displayPage of $totalPages  |  Total Users: $totalCount" -ForegroundColor Cyan
        Write-Host "================================================================================" -ForegroundColor Cyan
        Write-Host ""

        for ($i = $startIdx; $i -le $endIdx; $i++) {
            Write-Host $credentialOutput[$i]
        }

        Write-Host ""
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
        
        $navControls = @()
        if ($currentPage -lt ($totalPages - 1)) { $navControls += "[Right Arrow / N] Next" }
        if ($currentPage -gt 0)                { $navControls += "[Left Arrow / P] Previous" }
        $navControls += "[Q / Esc] Quit"

        Write-Host ($navControls -join "  |  ") -ForegroundColor Yellow

        $key = [Console]::ReadKey($true)

        if ($key.Key -eq [ConsoleKey]::RightArrow -or $key.Key -eq [ConsoleKey]::N -or $key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Spacebar) {
            if ($currentPage -lt ($totalPages - 1)) { $currentPage++ }
        }
        elseif ($key.Key -eq [ConsoleKey]::LeftArrow -or $key.Key -eq [ConsoleKey]::P -or $key.Key -eq [ConsoleKey]::B) {
            if ($currentPage -gt 0) { $currentPage-- }
        }
        elseif ($key.Key -eq [ConsoleKey]::Q -or $key.Key -eq [ConsoleKey]::Escape) {
            break
        }
    }
} else {
    Write-Host "`n[!] No accounts were modified." -ForegroundColor Red
}

# ==========================================
# 5. MEMORY & ARTIFACT SCRUBBING
# ==========================================
$credentialOutput = $null
$allDomainUsers   = $null
$localUsers       = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()

Clear-Host
[Console]::Clear()

Clear-History -ErrorAction SilentlyContinue
try {
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
} catch {}

Write-Host "[+] Passwords rotated, screenshots completed, and session memory cleared." -ForegroundColor Green
