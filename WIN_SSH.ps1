<#
.SYNOPSIS
    Installs and configures OpenSSH Server and sets up the inbound firewall rule.
#>

# 0. Ensure script is run with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please Run as Administrator."
    exit 1
}

Write-Host "--- Starting OpenSSH Server Setup ---" -ForegroundColor Cyan

# 1. Query and install the OpenSSH Server capability
Write-Host "Checking OpenSSH Server capability..." -ForegroundColor Yellow
$capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

if (-not $capability) {
    Write-Error "OpenSSH Server capability was not found on this system."
    exit 1
}

if ($capability.State -ne 'Installed') {
    Write-Host "Installing $($capability.Name)..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name $capability.Name
    Write-Host "OpenSSH Server installed successfully." -ForegroundColor Green
} else {
    Write-Host "OpenSSH Server is already installed." -ForegroundColor Green
}

# 2. Configure and start the sshd service
Write-Host "Configuring 'sshd' service..." -ForegroundColor Yellow
Set-Service -Name sshd -StartupType 'Automatic'
Start-Service -Name sshd
Write-Host "'sshd' service set to Automatic and started." -ForegroundColor Green

# 3. Check and configure the firewall rule
Write-Host "Configuring firewall rule..." -ForegroundColor Yellow
$ruleName = "OpenSSH-Server-In-TCP"

if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
    Write-Host "Firewall Rule '$ruleName' does not exist, creating it..." -ForegroundColor Yellow
    New-NetFirewallRule -Name $ruleName `
                        -DisplayName 'OpenSSH Server (sshd)' `
                        -Enabled True `
                        -Direction Inbound `
                        -Protocol TCP `
                        -Action Allow `
                        -LocalPort 22 `
                        -Profile Any | Out-Null
    Write-Host "Firewall rule created successfully." -ForegroundColor Green
} else {
    Write-Host "Firewall rule '$ruleName' has been created and exists." -ForegroundColor Green
}

# Ensure profile is applied to Any
Set-NetFirewallRule -Name $ruleName -Profile Any
Write-Host "Firewall rule profile set to 'Any'." -ForegroundColor Green

Write-Host "--- OpenSSH Server Setup Complete! ---" -ForegroundColor Cyan
