# ==============================================================================
# PHASE 2: POPULATE MOCK USERS AND ORGANIZATIONAL UNITS (FIXED)
# Run this AFTER the server has rebooted and you have logged into the domain.
# ==============================================================================

Import-Module ActiveDirectory

# 1. Create a Target Organizational Unit (OU)
$OUName = "MockUsers"
$DomainDN = (Get-ADRootDSE).defaultNamingContext
$TargetOUPath = "OU=$OUName,$DomainDN"

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'")) {
    Write-Host "Creating Organizational Unit: $OUName..." -ForegroundColor Cyan
    New-ADOrganizationalUnit -Name $OUName -Path $DomainDN -ProtectedFromAccidentalDeletion $false
}

# 2. Define Mock Users Array
$MockUsers = @(
    @{First="John";  Last="Doe";      Dept="IT";       Title="System Administrator"}
    @{First="Jane";  Last="Smith";    Dept="HR";       Title="HR Specialist"}
    @{First="Bob";   Last="Johnson";  Dept="Sales";    Title="Sales Manager"}
    @{First="Alice"; Last="Williams"; Dept="Finance";  Title="Accountant"}
    @{First="Charlie";Last="Brown";   Dept="IT";       Title="Helpdesk Technician"}
)

# 3. Create the users inside Active Directory
$DefaultPassword = ConvertTo-SecureString "MockUserP@ss123" -AsPlainText -Force

foreach ($User in $MockUsers) {
    $SAMAccountName = ($User.First + $User.Last).ToLower()
    $UserPrincipalName = "$SAMAccountName@$((Get-ADDomain).DNSRoot)"
    $DisplayName = "$($User.First) $($User.Last)"
    
    # Check if user already exists
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$SAMAccountName'")) {
        Write-Host "Creating user: $DisplayName ($SAMAccountName)" -ForegroundColor Green
        
        New-ADUser -Name $DisplayName `
                   -SamAccountName $SAMAccountName `
                   -UserPrincipalName $UserPrincipalName `
                   -GivenName $User.First `
                   -Surname $User.Last `
                   -Path $TargetOUPath `
                   -AccountPassword $DefaultPassword `
                   -ChangePasswordAtLogon $false `
                   -Department $User.Dept `
                   -Title $User.Title `
                   -Enabled $true
    } else {
        Write-Host "User $SAMAccountName already exists, skipping." -ForegroundColor Yellow
    }
}

Write-Host "`nMock Domain Setup Complete!" -ForegroundColor Cyan
Write-Host "All users have been set with the default password: MockUserP@ss123" -ForegroundColor Green
