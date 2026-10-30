[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

Write-Output "================================================================="
Write-Output "               CCDC MINUTE-ZERO SYSTEM INVENTORY                 "
Write-Output "================================================================="

Write-Output "`n[+] SYSTEM CONFIGURATION"
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Output "Hostname        : $($env:COMPUTERNAME)"
Write-Output "Domain / Workgr : $($cs.Domain)"
Write-Output "OS Caption      : $($os.Caption)"
Write-Output "Version / Build : $($os.Version) (Build $($os.BuildNumber))"
Write-Output "Architecture    : $($os.OSArchitecture)"
Write-Output "Last Boot Time  : $($os.LastBootUpTime)"

Write-Output "`n[+] NETWORK INTERFACES"
$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($nic in $adapters) {
    Write-Output "---------------------------------------------------------"
    Write-Output "Adapter Name    : $($nic.Description)"
    Write-Output "MAC Address     : $($nic.MACAddress)"
    Write-Output "IPv4 Address    : $($nic.IPAddress -join ', ')"
    Write-Output "Subnet Mask     : $($nic.IPSubnet -join ', ')"
    Write-Output "Default Gateway : $($nic.DefaultIPGateway -join ', ')"
    Write-Output "DNS Servers     : $($nic.DNSServerSearchOrder -join ', ')"
}

Write-Output "`n[+] LOCAL ADMINISTRATORS & USERS"
$localUsers = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"
Write-Output "Local Accounts: $($localUsers.Name -join ', ')"

try {
    $adminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
    $admins = Get-CimInstance -Query "ASSOCIATORS OF {Win32_Group.Domain='$($env:COMPUTERNAME)',Name='$($adminGroup.Name)'} WHERE ResultClass=Win32_UserAccount"
    Write-Output "Local Admins  : $($admins.Name -join ', ')"
} catch {
    Write-Output "Local Admins  : Unable to enumerate CIM admin group directly."
}

if ($cs.PartOfDomain -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    Write-Output "`n[+] ACTIVE DIRECTORY PRIVILEGED USERS"
    $da = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object -ExpandProperty SamAccountName
    $ea = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Select-Object -ExpandProperty SamAccountName
    Write-Output "Domain Admins    : $($da -join ', ')"
    Write-Output "Enterprise Admins: $($ea -join ', ')"
}

Write-Output "`n[+] CORE ACTIVE DIRECTORY & INFRASTRUCTURE SERVICES"
$adServices = @("NTDS", "kdc", "DNS", "Netlogon", "W32Time", "RpcSs", "DFSR", "LanmanServer", "LanmanWorkstation")
foreach ($svc in $adServices) {
    $status = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($status) {
        Write-Output "Service: $($svc.PadRight(18)) | Status: $($status.Status.ToString().PadRight(10)) | StartType: $($status.StartType)"
    } else {
        Write-Output "Service: $($svc.PadRight(18)) | Status: NOT INSTALLED"
    }
}

Write-Output "`n[+] ACTIVE NETWORK LISTENERS (TCP / UDP)"
$tcpListeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -Property LocalAddress, LocalPort, OwningProcess
foreach ($listener in $tcpListeners) {
    $procName = (Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Output "TCP  $($listener.LocalAddress):$($listener.LocalPort)".PadRight(28) + " PID: $($listener.OwningProcess)".PadRight(15) + " Process: $procName"
}

Write-Output "`n[+] INSTALLED ROLES & OPTIONAL FEATURES"
if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Get-WindowsFeature | Where-Object { $_.Installed -eq $true } | ForEach-Object {
        Write-Output "Feature: $($_.Name.PadRight(30)) | Display: $($_.DisplayName)"
    }
}

Write-Output "`n[+] INSTALLED SOFTWARE (64-bit and 32-bit)"
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
Get-ItemProperty $regPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
    Write-Output "App: $($_.DisplayName) | Version: $($_.DisplayVersion) | Publisher: $($_.Publisher)"
}

Write-Output "================================================================="
Write-Output "                        INVENTORY COMPLETE                       "
Write-Output "================================================================="
