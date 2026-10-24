# ==============================================================================
# PHASE 1: INSTALL AD-DS & CREATE NEW FOREST
# Run this on a clean Windows Server 2012 R2 machine as Administrator.
# ==============================================================================

# Define Lab Environment Variables
$DomainName = "mocklab.local"
$NetBIOSName = "MOCKLAB"
$SafeModePassword = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

Write-Host "1. Installing Active Directory Domain Services Role..." -ForegroundColor Cyan
Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools -IncludeAllSubFeature

Write-Host "2. Promoting server to a Domain Controller (New Forest)..." -ForegroundColor Cyan
# This cmdlet will trigger an automatic reboot when finished
Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "Win2012R2" `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOSName `
    -ForestMode "Win2012R2" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -SafeModeAdministratorPassword $SafeModePassword `
    -Force:$true
