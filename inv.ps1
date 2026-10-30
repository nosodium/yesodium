<#
.SYNOPSIS
    CCDC Universal Inventory & Baseline Engine (v7)
.DESCRIPTION
    Compatible with Windows Server 2012 through 2025.
    - ADUC All Domain Users listing (comma-separated)
    - Clean human-readable display names for Core AD services
    - Refined third-party service detection (filters out ADWS / .NET)
    - Unquoted service path detection
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

# ====================================================================
# HELPER FUNCTIONS
# ====================================================================

function Show-SystemNetworkConfig {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               SYSTEM & NETWORK INTERFACE BASELINE               " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    Write-Host "`n[+] HOST CONFIGURATION" -ForegroundColor Yellow
    Write-Output ("Hostname        : {0}" -f $env:COMPUTERNAME)
    Write-Output ("Domain / Workgr : {0}" -f $cs.Domain)
    Write-Output ("OS Caption      : {0}" -f $os.Caption)
    Write-Output ("Version / Build : {0} (Build {1})" -f $os.Version, $os.BuildNumber)
    Write-Output ("Architecture    : {0}" -f $os.OSArchitecture)
    Write-Output ("Last Boot Time  : {0}" -f $os.LastBootUpTime)

    Write-Host "`n[+] NETWORK INTERFACES" -ForegroundColor Yellow
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($nic in $adapters) {
        Write-Output "---------------------------------------------------------"
        Write-Output ("Adapter         : {0}" -f $nic.Description)
        Write-Output ("MAC Address     : {0}" -f $nic.MACAddress)
        Write-Output ("IPv4 Address    : {0}" -f ($nic.IPAddress -join ', '))
        Write-Output ("Subnet Mask     : {0}" -f ($nic.IPSubnet -join ', '))
        Write-Output ("Default Gateway : {0}" -f ($nic.DefaultIPGateway -join ', '))
        Write-Output ("DNS Servers     : {0}" -f ($nic.DNSServerSearchOrder -join ', '))
    }
}

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

        # ALL ADUC DOMAIN USERS (Comma-Separated)
        Write-Host "`n[+] ALL DOMAIN USERS (ADUC)" -ForegroundColor Yellow
        $allDomainUsers = @()
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            $allDomainUsers = Get-ADUser -Filter * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
        }
        
        # Fallback to DirectorySearcher if AD module is missing or fails
        if (-not $allDomainUsers -or $allDomainUsers.Count -eq 0) {
            try {
                $searcher = [adsisearcher]"(objectCategory=user)"
                $searcher.PageSize = 1000
                $allDomainUsers = $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }
            } catch {}
        }

        if ($allDomainUsers) {
            Write-Output ($allDomainUsers -join ', ')
        } else {
            Write-Host "Could not query Active Directory user accounts." -ForegroundColor Red
        }
    }
}

function Show-CoreServices {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               CORE AD & INFRASTRUCTURE SERVICES                " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f "SERVICE NAME", "STATE", "START MODE", "FRIENDLY NAME") -ForegroundColor White
    Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f "============", "=====", "==========", "=============") -ForegroundColor Gray

    $coreTargets = @{
        "NTDS"               = "Active Directory Domain Services"
        "kdc"                = "Kerberos Key Distribution Center"
        "DNS"                = "DNS Server"
        "Netlogon"           = "Netlogon Service"
        "W32Time"            = "Windows Time (NTP)"
        "RpcSs"              = "Remote Procedure Call (RPC)"
        "DFSR"               = "DFS Replication"
        "LanmanServer"       = "Server (SMB Share Host)"
        "LanmanWorkstation"  = "Workstation (SMB Client)"
        "sshd"               = "OpenSSH SSH Server (BACKDOOR AUDIT)"
        "wuauserv"           = "Windows Update Service"
        "CertSvc"            = "Active Directory Certificate Services"
    }

    $startMap = @{
        0 = "Boot"
        1 = "System"
        2 = "Automatic"
        3 = "Manual"
        4 = "Disabled"
    }

    foreach ($svcName in $coreTargets.Keys | Sort-Object) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
        
        if (Test-Path $regPath) {
            $regProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $friendlyName = $coreTargets[$svcName]
            $startDword = $regProps.Start
            $startMode = if ($startMap.ContainsKey($startDword)) { $startMap[$startDword] } else { "Unknown($startDword)" }

            $scOutput = cmd.exe /c "sc query $svcName" 2>$null | Select-String "STATE"
            $state = "STOPPED"
            if ($scOutput -match "RUNNING") {
                $state = "RUNNING"
            } elseif ($scOutput -match "PAUSED") {
                $state = "PAUSED"
            }

            $color = "White"
            if ($svcName -eq "sshd" -and $state -eq "RUNNING") {
                $color = "Red"
            } elseif ($state -eq "RUNNING") {
                $color = "Green"
            }

            Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f $svcName, $state, $startMode, $friendlyName) -ForegroundColor $color
        } else {
            Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f $svcName, "NOT PRESENT", "N/A", $coreTargets[$svcName]) -ForegroundColor DarkGray
        }
    }
}

function Show-ThirdPartyServices {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "          THIRD-PARTY / NON-DEFAULT INSTALLED SERVICES           " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "Identifies non-standard services, Red Team backdoors, and unquoted paths." -ForegroundColor Gray
    Write-Host ("{0,-22} {1,-10} {2,-10} {3}" -f "SERVICE NAME", "STATE", "STARTMODE", "PATHNAME") -ForegroundColor White
    Write-Host ("{0,-22} {1,-10} {2,-10} {3}" -f "============", "=====", "=========", "========") -ForegroundColor Gray

    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    $foundNonDefault = 0

    foreach ($s in $services) {
        $path = $s.PathName
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        # Filter out built-in Windows paths, including ADWS, Microsoft.NET, servicing, and SysWOW64
        $isWindowsCore = $path -match "^([A-Z]:\\Windows\\(system32|SysWOW64|WinSxS|servicing|ADWS|Microsoft\.NET)\b|system32\\)"

        if (-not $isWindowsCore) {
            $foundNonDefault++

            # Detect unquoted service path vulnerability
            $isUnquoted = ($path -notmatch '^"') -and ($path -match '\.exe(\s|$)') -and ($path -match ' ')

            $color = "Yellow"
            if ($s.Name -match "sshd|backdoor|nc|ncat|meterpreter" -or $isUnquoted) {
                $color = "Red"
            }

            $unquotedTag = if ($isUnquoted) { " [!] UNQUOTED PATH VULN" } else { "" }
            Write-Host ("{0,-22} {1,-10} {2,-10} {3}{4}" -f $s.Name, $s.State, $s.StartMode, $path, $unquotedTag) -ForegroundColor $color
        }
    }

    if ($foundNonDefault -eq 0) {
        Write-Host "No non-default third-party services detected." -ForegroundColor Green
    }
}

function Show-InstalledAppsAndFeatures {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               INSTALLED APPLICATIONS & FEATURES                 " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    Write-Host "`n[+] INSTALLED WINDOWS FEATURES (ACTIVE)" -ForegroundColor Yellow
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | ForEach-Object {
            Write-Output ("Feature: {0,-32} | {1}" -f $_.Name, $_.DisplayName)
        }
    } else {
        Write-Output "Get-WindowsFeature cmdlet not supported on this operating system."
    }

    Write-Host "`n[+] INSTALLED SOFTWARE (REGISTRY RUNTIME)" -ForegroundColor Yellow
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installedApps = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
    if ($installedApps) {
        foreach ($app in $installedApps) {
            Write-Output ("App: {0,-40} | Version: {1,-15} | Publisher: {2}" -f $app.DisplayName, $app.DisplayVersion, $app.Publisher)
        }
    } else {
        Write-Host "No third-party MSI/registered application packages found." -ForegroundColor DarkGray
    }
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

while ($true) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "             CCDC SYSTEM AUDIT & INVENTORY MENU         " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "[1] System & Network Configuration (IP, Gateway, DNS, MAC)"
    Write-Host "[2] Local & Domain Accounts / Privileged Groups / ADUC Users" -ForegroundColor Yellow
    Write-Host "[3] Core Active Directory & Infrastructure Services Status" -ForegroundColor Yellow
    Write-Host "[4] Third-Party & Non-Default Services (Unquoted Paths)" -ForegroundColor Yellow
    Write-Host "[5] Installed Applications & Enabled Windows Features"
    Write-Host "[A] Run FULL Inventory (All Modules - for Copy-Pasting)" -ForegroundColor Green
    Write-Host "[Q] Quit" -ForegroundColor Red
    Write-Host "--------------------------------------------------------"
    
    $choice = Read-Host "Select an option [1-5, A, Q]"

    switch ($choice.ToUpper()) {
        "1" { Show-SystemNetworkConfig }
        "2" { Show-UsersAndGroups }
        "3" { Show-CoreServices }
        "4" { Show-ThirdPartyServices }
        "5" { Show-InstalledAppsAndFeatures }
        "A" {
            Show-SystemNetworkConfig
            Show-UsersAndGroups
            Show-CoreServices
            Show-ThirdPartyServices
            Show-InstalledAppsAndFeatures
            Write-Host "`n=================================================================" -ForegroundColor Green
            Write-Host "                   FULL BASELINE COMPLETED                       " -ForegroundColor Green
            Write-Host "=================================================================" -ForegroundColor Green
        }
        "Q" {
            Write-Host "`nExiting CCDC Inventory Tool." -ForegroundColor Gray
            return
        }
        Default {
            Write-Host "`n[!] Invalid selection. Please enter 1-5, A, or Q." -ForegroundColor Red
        }
    }
}
