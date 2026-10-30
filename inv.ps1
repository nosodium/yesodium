[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

# ====================================================================
# HELPER FUNCTIONS
# ====================================================================

function Show-SystemNetworkConfig {
    Write-Output "`n================================================================="
    Write-Output "               SYSTEM & NETWORK INTERFACE BASELINE               "
    Write-Output "================================================================="
    
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    Write-Output "`n[+] HOST CONFIGURATION"
    Write-Output ("Hostname        : {0}" -f $env:COMPUTERNAME)
    Write-Output ("Domain / Workgr : {0}" -f $cs.Domain)
    Write-Output ("OS Caption      : {0}" -f $os.Caption)
    Write-Output ("Version / Build : {0} (Build {1})" -f $os.Version, $os.BuildNumber)
    Write-Output ("Architecture    : {0}" -f $os.OSArchitecture)
    Write-Output ("Last Boot Time  : {0}" -f $os.LastBootUpTime)

    Write-Output "`n[+] NETWORK INTERFACES"
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
    Write-Output "`n================================================================="
    Write-Output "               ACTIVE LISTENERS (TCP / UDP)                      "
    Write-Output "================================================================="
    Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "PROTO", "LOCAL ADDRESS:PORT", "PID", "PROCESS NAME")
    Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "=====", "==============================", "===", "============")

    # 1. TCP Listeners
    $tcpFound = $false
    try {
        $tcpConnections = Get-NetTCPConnection -State Listen -ErrorAction Stop
        $tcpFound = $true
        foreach ($conn in $tcpConnections) {
            $endpoint = "{0}:{1}" -f $conn.LocalAddress, $conn.LocalPort
            $pidNum   = $conn.OwningProcess
            $pName    = "UNKNOWN"

            if ($pidNum -eq 0) {
                $pName = "System Idle"
            } elseif ($pidNum -eq 4) {
                $pName = "System"
            } else {
                $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
                if ($p) { $pName = $p.ProcessName }
            }
            Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "TCP", $endpoint, $pidNum, $pName)
        }
    } catch {}

    # Netstat fallback for minimal environments (Win Server 2012 / missing NetTCPIP module)
    if (-not $tcpFound) {
        netstat -ano -p tcp | Select-String "LISTENING" | ForEach-Object {
            $tokens = ($_.ToString().Trim() -split '\s+')
            if ($tokens.Count -ge 5) {
                $endpoint = $tokens[1]
                $pidNum   = $tokens[4]
                $pName    = "UNKNOWN"
                if ($pidNum -eq "0") { $pName = "System Idle" }
                elseif ($pidNum -eq "4") { $pName = "System" }
                else {
                    $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
                    if ($p) { $pName = $p.ProcessName }
                }
                Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "TCP", $endpoint, $pidNum, $pName)
            }
        }
    }

    # 2. UDP Listeners
    $udpFound = $false
    try {
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
        $udpFound = $true
        foreach ($udp in $udpEndpoints) {
            $endpoint = "{0}:{1}" -f $udp.LocalAddress, $udp.LocalPort
            $pidNum   = $udp.OwningProcess
            $pName    = "UNKNOWN"

            if ($pidNum -eq 0) {
                $pName = "System Idle"
            } elseif ($pidNum -eq 4) {
                $pName = "System"
            } else {
                $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
                if ($p) { $pName = $p.ProcessName }
            }
            Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "UDP", $endpoint, $pidNum, $pName)
        }
    } catch {}

    # Netstat fallback for UDP
    if (-not $udpFound) {
        netstat -ano -p udp | ForEach-Object {
            $tokens = ($_.ToString().Trim() -split '\s+')
            if ($tokens.Count -ge 4 -and $tokens[0] -eq "UDP") {
                $endpoint = $tokens[1]
                $pidNum   = $tokens[3]
                $pName    = "UNKNOWN"
                if ($pidNum -eq "0") { $pName = "System Idle" }
                elseif ($pidNum -eq "4") { $pName = "System" }
                else {
                    $p = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
                    if ($p) { $pName = $p.ProcessName }
                }
                Write-Output ("{0,-6} {1,-32} {2,-10} {3}" -f "UDP", $endpoint, $pidNum, $pName)
            }
        }
    }
}

function Show-UsersAndGroups {
    Write-Output "`n================================================================="
    Write-Output "               USERS AND PRIVILEGED GROUPS                       "
    Write-Output "================================================================="

    Write-Output "`n[+] LOCAL ACCOUNTS"
    $localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
    foreach ($user in $localUsers) {
        Write-Output ("Account: {0,-25} | Disabled: {1,-5} | PasswordChangeable: {2}" -f $user.Name, $user.Disabled, $user.PasswordChangeable)
    }

    Write-Output "`n[+] LOCAL ADMINISTRATORS"
    try {
        $adminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction Stop
        $admins = Get-CimInstance -Query "ASSOCIATORS OF {Win32_Group.Domain='$($env:COMPUTERNAME)',Name='$($adminGroup.Name)'} WHERE ResultClass=Win32_UserAccount"
        Write-Output ("Members: {0}" -f ($admins.Name -join ', '))
    } catch {
        # Fallback to net localgroup
        $netAdmin = (net localgroup administrators | Select-Object -Skip 6) -notmatch "The command completed" | Where-Object { $_ -ne "" }
        Write-Output ("Members: {0}" -f ($netAdmin -join ', '))
    }

    # Domain users check (if AD module is present)
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
        Write-Output "`n[+] ACTIVE DIRECTORY PRIVILEGED GROUPS"
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
    Write-Output "`n================================================================="
    Write-Output "               CORE AD & INFRASTRUCTURE SERVICES                "
    Write-Output "================================================================="
    Write-Output ("{0,-20} {1,-12} {2,-12} {3}" -f "SERVICE NAME", "STATUS", "START TYPE", "DISPLAY NAME")
    Write-Output ("{0,-20} {1,-12} {2,-12} {3}" -f "============", "======", "==========", "============")

    $adServices = @(
        "NTDS", "kdc", "DNS", "Netlogon", "W32Time", 
        "RpcSs", "DFSR", "LanmanServer", "LanmanWorkstation", 
        "sshd", "wuauserv", "CertSvc"
    )

    foreach ($svcName in $adServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Output ("{0,-20} {1,-12} {2,-12} {3}" -f $svc.Name, $svc.Status.ToString(), $svc.StartType.ToString(), $svc.DisplayName)
        } else {
            Write-Output ("{0,-20} {1,-12} {2,-12} {3}" -f $svcName, "NOT PRESENT", "N/A", "Service not installed")
        }
    }
}

function Show-InstalledAppsAndFeatures {
    Write-Output "`n================================================================="
    Write-Output "               INSTALLED APPLICATIONS & FEATURES                 "
    Write-Output "================================================================="

    Write-Output "`n[+] INSTALLED WINDOWS FEATURES (ACTIVE)"
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | ForEach-Object {
            Write-Output ("Feature: {0,-32} | {1}" -f $_.Name, $_.DisplayName)
        }
    } else {
        Write-Output "Get-WindowsFeature cmdlet not supported on this workstation or environment."
    }

    Write-Output "`n[+] INSTALLED SOFTWARE (REGISTRY RUNTIME)"
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
    Write-Host "[4] Core Active Directory & Domain Services Status"
    Write-Host "[5] Installed Applications & Enabled Windows Features"
    Write-Host "[A] Run FULL Inventory (All Modules - for Copy-Pasting)" -ForegroundColor Green
    Write-Host "[Q] Quit" -ForegroundColor Red
    Write-Host "--------------------------------------------------------"
    
    $choice = Read-Host "Select an option [1-5, A, Q]"

    switch ($choice.ToUpper()) {
        "1" { Show-ActiveListeners }
        "2" { Show-SystemNetworkConfig }
        "3" { Show-UsersAndGroups }
        "4" { Show-CoreServices }
        "5" { Show-InstalledAppsAndFeatures }
        "A" {
            Show-SystemNetworkConfig
            Show-ActiveListeners
            Show-UsersAndGroups
            Show-CoreServices
            Show-InstalledAppsAndFeatures
            Write-Output "`n================================================================="
            Write-Output "                   FULL BASELINE COMPLETED                       "
            Write-Output "================================================================="
        }
        "Q" {
            Write-Host "`nExiting CCDC Inventory Tool." -ForegroundColor Gray
            return
        }
        Default {
            Write-Host "`n[!] Invalid selection. Please enter 1, 2, 3, 4, 5, A, or Q." -ForegroundColor Red
        }
    }
}
