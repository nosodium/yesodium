<#
.SYNOPSIS
    CCDC Interactive Inventory & Baseline Engine (v3 - Third-Party Service Auditing)
.DESCRIPTION
    Collects system, network, listener, account, core infrastructure, and
    third-party/non-default service telemetry with unquoted path detection.
    Compatible with Windows Server 2012 through 2025.
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

function Show-ActiveListeners {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               ACTIVE LISTENERS (TCP / UDP)                      " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "PROTO", "LOCAL ADDRESS:PORT", "PID", "PROCESS NAME") -ForegroundColor White
    Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "=====", "==============================", "===", "============") -ForegroundColor Gray

    $procTable = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procTable[$_.Id] = $_.ProcessName }
    $procTable[0] = "System Idle"
    $procTable[4] = "System"

    $resultsFound = 0

    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $tcpList = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $tcpList) {
            $endpoint = "{0}:{1}" -f $conn.LocalAddress, $conn.LocalPort
            $pidNum   = [int]$conn.OwningProcess
            $pName    = if ($procTable.ContainsKey($pidNum)) { $procTable[$pidNum] } else { "UNKNOWN / RESTRICTED" }
            
            Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "TCP", $endpoint, $pidNum, $pName) -ForegroundColor $(if ($endpoint -match ":22$|:4444$|:3389$") { "Red" } else { "White" })
            $resultsFound++
        }

        $udpList = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        foreach ($udp in $udpList) {
            $endpoint = "{0}:{1}" -f $udp.LocalAddress, $udp.LocalPort
            $pidNum   = [int]$udp.OwningProcess
            $pName    = if ($procTable.ContainsKey($pidNum)) { $procTable[$pidNum] } else { "UNKNOWN / RESTRICTED" }
            
            Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "UDP", $endpoint, $pidNum, $pName) -ForegroundColor White
            $resultsFound++
        }
    }

    if ($resultsFound -eq 0) {
        cmd.exe /c "netstat -ano -p tcp" | Select-String "LISTENING" | ForEach-Object {
            $line = $_.Line.Trim()
            if ($line -match "^\s*TCP\s+(\S+)\s+\S+\s+LISTENING\s+(\d+)") {
                $endpoint = $matches[1]
                $pidNum   = [int]$matches[2]
                $pName    = if ($procTable.ContainsKey($pidNum)) { $procTable[$pidNum] } else { "UNKNOWN / RESTRICTED" }
                Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "TCP", $endpoint, $pidNum, $pName) -ForegroundColor $(if ($endpoint -match ":22$|:4444$|:3389$") { "Red" } else { "White" })
            }
        }

        cmd.exe /c "netstat -ano -p udp" | ForEach-Object {
            $line = $_.Trim()
            if ($line -match "^\s*UDP\s+(\S+)\s+\*:\*\s+(\d+)") {
                $endpoint = $matches[1]
                $pidNum   = [int]$matches[2]
                $pName    = if ($procTable.ContainsKey($pidNum)) { $procTable[$pidNum] } else { "UNKNOWN / RESTRICTED" }
                Write-Host ("{0,-6} {1,-32} {2,-10} {3}" -f "UDP", $endpoint, $pidNum, $pName) -ForegroundColor White
            }
        }
    }
}

function Show-UsersAndGroups {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               USERS AND PRIVILEGED GROUPS                       " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan

    Write-Host "`n[+] LOCAL ACCOUNTS" -ForegroundColor Yellow
    $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    foreach ($user in $localUsers) {
        Write-Output ("Account: {0,-25} | Disabled: {1,-5} | PasswordChangeable: {2}" -f $user.Name, $user.Disabled, $user.PasswordChangeable)
    }

    Write-Host "`n[+] LOCAL ADMINISTRATORS" -ForegroundColor Yellow
    try {
        $adminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction Stop
        $admins = Get-CimInstance -Query "ASSOCIATORS OF {Win32_Group.Domain='$($env:COMPUTERNAME)',Name='$($adminGroup.Name)'} WHERE ResultClass=Win32_UserAccount"
        Write-Output ("Members: {0}" -f ($admins.Name -join ', '))
    } catch {
        $netAdmin = (net localgroup administrators | Select-Object -Skip 6) -notmatch "The command completed" | Where-Object { $_ -ne "" }
        Write-Output ("Members: {0}" -f ($netAdmin -join ', '))
    }

    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Host "`n[+] ACTIVE DIRECTORY PRIVILEGED GROUPS" -ForegroundColor Yellow
        try {
            $da = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object -ExpandProperty SamAccountName
            Write-Output ("Domain Admins     : {0}" -f ($da -join ', '))
        } catch {}
        try {
            $ea = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Select-Object -ExpandProperty SamAccountName
            Write-Output ("Enterprise Admins : {0}" -f ($ea -join ', '))
        } catch {}
    }
}

function Show-CoreServices {
    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "               CORE AD & INFRASTRUCTURE SERVICES                " -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f "SERVICE NAME", "STATUS", "START TYPE", "DISPLAY NAME") -ForegroundColor White
    Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f "============", "======", "==========", "============") -ForegroundColor Gray

    $adServices = @(
        "NTDS", "kdc", "DNS", "Netlogon", "W32Time", 
        "RpcSs", "DFSR", "LanmanServer", "LanmanWorkstation", 
        "sshd", "wuauserv", "CertSvc"
    )

    foreach ($svcName in $adServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host ("{0,-20} {1,-12} {2,-12} {3}" -f $svc.Name, $svc.Status.ToString(), $svc.StartType.ToString(), $svc.DisplayName) -ForegroundColor $(if ($svcName -eq "sshd" -and $svc.Status -eq "Running") { "Red" } else { "White" })
        } else {
            Write-Output ("{0,-20} {1,-12} {2,-12} {3}" -f $svcName, "NOT PRESENT", "N/A", "Service not installed")
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

    # Enumerate all system services via CIM/WMI to pull exact executable paths
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

    $foundNonDefault = 0
    foreach ($s in $services) {
        $path = $s.PathName
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        # Filter out native Windows core paths: C:\Windows\system32, C:\Windows\SysWOW64, C:\Windows\WinSxS
        $isWindowsCore = $path -match "^([A-Z]:\\Windows\\(system32|SysWOW64|WinSxS|servicing)\b|system32\\)"

        if (-not $isWindowsCore) {
            $foundNonDefault++

            # Check for Unquoted Service Path Vulnerability:
            # Contains space in directory path, doesn't start with quote, and ends in .exe
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
    Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        Write-Output ("App: {0,-40} | Version: {1,-15} | Publisher: {2}" -f $_.DisplayName, $_.DisplayVersion, $_.Publisher)
    }
}

# ====================================================================
# MAIN INTERACTIVE MENU
# ====================================================================

while ($true) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host "             CCDC SYSTEM AUDIT & INVENTORY MENU         " -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "[1] Active Network Listeners (TCP & UDP with PID/Process)" -ForegroundColor Yellow
    Write-Host "[2] System & Network Configuration (IP, Gateway, DNS, MAC)"
    Write-Host "[3] Local & Domain Accounts / Privileged Groups"
    Write-Host "[4] Core Active Directory & Infrastructure Services Status"
    Write-Host "[5] Third-Party & Non-Default Services (Unquoted Paths)" -ForegroundColor Yellow
    Write-Host "[6] Installed Applications & Enabled Windows Features"
    Write-Host "[A] Run FULL Inventory (All Modules - for Copy-Pasting)" -ForegroundColor Green
    Write-Host "[Q] Quit" -ForegroundColor Red
    Write-Host "--------------------------------------------------------"
    
    $choice = Read-Host "Select an option [1-6, A, Q]"

    switch ($choice.ToUpper()) {
        "1" { Show-ActiveListeners }
        "2" { Show-SystemNetworkConfig }
        "3" { Show-UsersAndGroups }
        "4" { Show-CoreServices }
        "5" { Show-ThirdPartyServices }
        "6" { Show-InstalledAppsAndFeatures }
        "A" {
            Show-SystemNetworkConfig
            Show-ActiveListeners
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
            Write-Host "`n[!] Invalid selection. Please enter 1-6, A, or Q." -ForegroundColor Red
        }
    }
}
