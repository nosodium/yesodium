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
        [string]$ExplicitPassword = $null,
        [ref]$OutputList
    )

    # Use explicit password if provided, otherwise auto-generate
    $plainPassword = if ($ExplicitPassword) { $ExplicitPassword } else { New-RandomPassword }
    $passSecure = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    try {
        if ($Type -match "(?i)^Local$") {
            $user = [ADSI]"WinNT://$env:COMPUTERNAME/$Username,user"
            $user.SetPassword($plainPassword)
            $user.SetInfo()
            [Console]::WriteLine("[+] Local user '$Username' updated successfully.")
        } elseif ($Type -match "(?i)^Domain$") {
            Set-ADAccountPassword -Identity $Username -NewPassword $passSecure -Reset
            Set-ADUser -Identity $Username -PasswordNeverExpires $true
            [Console]::WriteLine("[+] Domain user '$Username' updated successfully.")
        }

        $OutputList.Value += "$Username,$plainPassword"
    } catch {
        [Console]::WriteLine("[-] Error changing password for $Username ($Type): " + $_.Exception.Message)
    }
}

function Rotate-KrbtgtAccount {
    param(
        [ref]$OutputList
    )

    Write-Host "`n[!] WARNING: Double-rotating krbtgt invalidates all active Golden Tickets." -ForegroundColor Yellow
    Write-Host "[*] Executing first password rotation on 'krbtgt'..." -ForegroundColor Cyan
    $pass1 = New-RandomPassword
    $sec1  = ConvertTo-SecureString $pass1 -AsPlainText -Force
    
    try {
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $sec1 -Reset
        Write-Host " [+] Pass 1 complete. Pausing 5 seconds for replication..." -ForegroundColor Green
        Start-Sleep -Seconds 5

        Write-Host "[*] Executing second rotation (flushing previous Kerberos master key)..." -ForegroundColor Cyan
        $pass2 = New-RandomPassword
        $sec2  = ConvertTo-SecureString $pass2 -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $sec2 -Reset
        Set-ADUser -Identity "krbtgt" -PasswordNeverExpires $true
        Write-Host " [+] Pass 2 complete. 'krbtgt' double-rotation finished." -ForegroundColor Green

        $OutputList.Value += "krbtgt,$pass2"
    } catch {
        Write-Host "[-] Failed to rotate krbtgt: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==========================================
# 3. INTERACTIVE MENU & EXECUTION
# ==========================================
Clear-Host
[Console]::WriteLine("=================================================================")
[Console]::WriteLine("             AUTOMATED CREDENTIAL ROTATION SYSTEM                ")
[Console]::WriteLine("=================================================================")
Write-Host " [A] Rotate ALL accounts (Local & Domain, excluding krbtgt)"
Write-Host " [S] Rotate a SINGLE specified user (Auto or Custom password)"
Write-Host " [K] Double-rotate the 'krbtgt' account"
Write-Host " [Q] QUIT without changing anything"
Write-Host "================================================================="

$menuChoice = Read-Host "Select an option (A / S / K / Q)"

$credentialOutput = @()

switch -Regex ($menuChoice) {
    "^[Qq]" {
        Write-Host "`n[!] Aborted by user. No passwords were changed." -ForegroundColor Yellow
        exit
    }

    "^[Kk]" {
        if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
            Write-Host "[-] Host is not a domain controller or part of a domain." -ForegroundColor Red
            exit
        }
        Rotate-KrbtgtAccount -OutputList ([ref]$credentialOutput)
    }

    "^[Ss]" {
        $target = Read-Host "Enter the exact Username"
        if ([string]::IsNullOrWhiteSpace($target)) {
            Write-Host "[-] Invalid username. Exiting." -ForegroundColor Red
            exit
        }

        # If user explicitly enters krbtgt here, enforce the double-rotation
        if ($target -ieq "krbtgt") {
            Rotate-KrbtgtAccount -OutputList ([ref]$credentialOutput)
        } else {
            $tTypeChoice = Read-Host "Is this user [L]ocal or [D]omain? (L/D)"
            $targetType = if ($tTypeChoice -match "^[Ll]") { "Local" } else { "Domain" }

            # Prompt for Auto vs Custom password
            $passChoice = Read-Host "Password type: [A]uto-generate or [C]ustom? (A/C)"
            $customPass = $null

            if ($passChoice -match "^[Cc]") {
                $customPass = Read-Host "Enter custom password for $target"
                if ([string]::IsNullOrWhiteSpace($customPass)) {
                    Write-Host "[-] Password cannot be blank. Aborting." -ForegroundColor Red
                    exit
                }
            }

            Set-AccountPassword -Username $target -Type $targetType -ExplicitPassword $customPass -OutputList ([ref]$credentialOutput)
        }
    }

    "^[Aa]" {
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
                    # Skip computer accounts, MSAs, Exchange mailboxes, and KRBTGT
                    if (
                        $dUser.EndsWith("$") -or 
                        $dUser -match '^(krbtgt|HealthMailbox|SM_|\$)'
                    ) { 
                        continue 
                    }

                    Set-AccountPassword -Username $dUser -Type "Domain" -OutputList ([ref]$credentialOutput)
                }
            } else {
                [Console]::WriteLine("[-] No domain users found or unable to contact domain controller.")
            }
        }
    }

    default {
        Write-Host "[-] Invalid selection. Quitting without changes." -ForegroundColor Red
        exit
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
        if ($currentPage -lt ($totalPages - 1)) { $navControls += "[L / Right Arrow] Next" }
        if ($currentPage -gt 0)                { $navControls += "[J / Left Arrow] Previous" }
        $navControls += "[Q / Esc] Quit"

        Write-Host ($navControls -join "  |  ") -ForegroundColor Yellow

        $key = [Console]::ReadKey($true)

        # NEXT: L, Right Arrow, Enter, Space
        if ($key.Key -eq [ConsoleKey]::L -or $key.Key -eq [ConsoleKey]::RightArrow -or $key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Spacebar) {
            if ($currentPage -lt ($totalPages - 1)) { $currentPage++ }
        }
        # PREVIOUS: J, Left Arrow
        elseif ($key.Key -eq [ConsoleKey]::J -or $key.Key -eq [ConsoleKey]::LeftArrow) {
            if ($currentPage -gt 0) { $currentPage-- }
        }
        # QUIT: Q, Escape
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

Write-Host "[+] Session memory scrubbed and console cleared." -ForegroundColor Green
