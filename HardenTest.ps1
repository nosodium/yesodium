[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Perform non-destructive discovery and configuration verification only.")]
    [switch]$AuditOnly,

    [Parameter(Mandatory = $false, HelpMessage = "Number of cached domain logons allowed (Default: 0 for Domain Controllers).")]
    [ValidateRange(0, 50)]
    [int]$CachedLogonsCount = 0,

    [Parameter(Mandatory = $false, HelpMessage = "RunAsPPL mode for modern OS (1 = UEFI Variable Protected, 2 = Without UEFI Variable Lock).")]
    [ValidateSet(1, 2)]
    [int]$PPLMode = 1
)

#region Internal Helper Functions

function Write-HardeningLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-RegistryValueDirect {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    # Compatible across PowerShell 3.0 up to 7+ (avoids Get-ItemPropertyValue which is absent in PS 3.0/4.0 on Server 2012/2012R2)
    try {
        if (Test-Path -Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $item -and ($item.PSObject.Properties.Name -contains $Name)) {
                return $item.$Name
            }
        }
    }
    catch {
        return $null
    }
    return $null
}

function Set-RegistryValueSafely {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Value,
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryValueKind]$PropertyType
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            Write-HardeningLog -Message "Target registry path does not exist. Creating path: $Path" -Level 'INFO'
            if ($PSCmdlet.ShouldProcess($Path, "Create Registry Key")) {
                $null = New-Item -Path $Path -Force -ErrorAction Stop
            }
        }

        $currentValue = Get-RegistryValueDirect -Path $Path -Name $Name
        if ($null -ne $currentValue -and ($currentValue -eq $Value)) {
            Write-HardeningLog -Message "Key '$Path' -> '$Name' is already set to expected value ($Value)." -Level 'INFO'
            return
        }

        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set registry property to '$Value' ($PropertyType)")) {
            # New-ItemProperty with -Force safely creates or overwrites with the correct type across PS 3.0 - 7+
            $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Stop
            Write-HardeningLog -Message "Successfully configured '$Path\$Name' = $Value" -Level 'SUCCESS'
        }
    }
    catch {
        Write-HardeningLog -Message "Failed to set registry item '$Path\$Name': $($_.Exception.Message)" -Level 'ERROR'
    }
}

function Get-HostOSProfile {
    [CmdletBinding()]
    param ()

    try {
        $os = $null
        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        } else {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        }

        $version = [Version]$os.Version
        $buildNumber = $version.Build

        # Server [2012, 2012 R2, 2016, 2019, 2022, 2025] dynamic classification
        $friendlyYear = switch ($buildNumber) {
            9200    { '2012' }
            9600    { '2012R2' }
            14393   { '2016' }
            17763   { '2019' }
            20348   { '2022' }
            { $_ -ge 26100 } { '2025' }
            default { 'Unknown' }
        }

        return [PSCustomObject]@{
            Caption      = $os.Caption
            Version      = $version
            Build        = $buildNumber
            ServerYear   = $friendlyYear
            ProductType  = $os.ProductType # 1 = Workstation, 2 = Domain Controller, 3 = Standalone/Member Server
            IsDC         = ($os.ProductType -eq 2)
        }
    }
    catch {
        Write-HardeningLog -Message "Unable to query WMI/CIM for host OS metadata: $($_.Exception.Message)" -Level 'ERROR'
        throw $_
    }
}

#endregion

#region Pre-Execution Flight Checks

# Verify elevated execution context
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-HardeningLog -Message "Execution terminated: This script must be executed within an elevated (Run as Administrator) session." -Level 'ERROR'
    return
}

# Resolve target host telemetry
$HostOS = Get-HostOSProfile
Write-HardeningLog -Message "Host Detected: $($HostOS.Caption) (Build: $($HostOS.Build), Recognized Branch: Windows Server $($HostOS.ServerYear))" -Level 'INFO'

# Enforce DC execution context
if (-not $HostOS.IsDC) {
    Write-HardeningLog -Message "Host does not advertise as ProductType=2 (Domain Controller). AD-specific mitigations require a DC context." -Level 'WARN'
}

#endregion

#region Component 1: LSASS Protection (RunAsPPL)
# Server [2012]       - RunAsPPL is not natively supported by the kernel on Windows Server 2012 (Build 9200).
# Server [2012R2]     - Introduced RunAsPPL (DWORD = 1).
# Server [2016, 2019] - RunAsPPL standard enforcement (DWORD = 1).
# Server [2022, 2025] - Enhanced PPL options: Value 1 = Protected Process Light with UEFI Variable Lock, Value 2 = Without UEFI Variable Lock.
Write-HardeningLog -Message "Executing Component 1: LSASS Process Protection (RunAsPPL)..." -Level 'INFO'

$lsaRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

try {
    if ($HostOS.ServerYear -eq '2012') {
        # Server [2012]
        Write-HardeningLog -Message "Server 2012 (Build 9200) kernel does not natively support RunAsPPL. Skipping modification." -Level 'WARN'
    }
    elseif ($HostOS.ServerYear -in @('2012R2', '2016', '2019')) {
        # Server [2012R2, 2016, 2019]
        if (-not $AuditOnly) {
            Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RunAsPPL' -Value 1 -PropertyType DWord
        } else {
            $val = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'RunAsPPL'
            Write-HardeningLog -Message "[AUDIT] $lsaRegistryPath\RunAsPPL = $(if ($null -ne $val) { $val } else { 'Not Set' }) (Target: 1)" -Level 'INFO'
        }
    }
    elseif ($HostOS.ServerYear -in @('2022', '2025') -or ($HostOS.Build -ge 20348)) {
        # Server [2022, 2025]
        if (-not $AuditOnly) {
            Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RunAsPPL' -Value $PPLMode -PropertyType DWord
            Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RunAsPPLBoot' -Value $PPLMode -PropertyType DWord
        } else {
            $val = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'RunAsPPL'
            $bootVal = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'RunAsPPLBoot'
            Write-HardeningLog -Message "[AUDIT] $lsaRegistryPath\RunAsPPL = $(if ($null -ne $val) { $val } else { 'Not Set' }) (Target: $PPLMode)" -Level 'INFO'
            Write-HardeningLog -Message "[AUDIT] $lsaRegistryPath\RunAsPPLBoot = $(if ($null -ne $bootVal) { $bootVal } else { 'Not Set' }) (Target: $PPLMode)" -Level 'INFO'
        }
    }
}
catch {
    Write-HardeningLog -Message "Failed during RunAsPPL configuration: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 2: WDigest Cleartext Password Caching Mitigation
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Applies uniformly. Prevents LSASS from maintaining cleartext credentials in memory for Digest Authentication.
Write-HardeningLog -Message "Executing Component 2: WDigest Cleartext Mitigation..." -Level 'INFO'

$wdigestRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'

try {
    if (-not $AuditOnly) {
        Set-RegistryValueSafely -Path $wdigestRegistryPath -Name 'UseLogonCredential' -Value 0 -PropertyType DWord
    } else {
        $wdigestVal = Get-RegistryValueDirect -Path $wdigestRegistryPath -Name 'UseLogonCredential'
        Write-HardeningLog -Message "[AUDIT] $wdigestRegistryPath\UseLogonCredential = $(if ($null -ne $wdigestVal) { $wdigestVal } else { 'Not Set (Default varies)' }) (Target: 0)" -Level 'INFO'
    }
}
catch {
    Write-HardeningLog -Message "Failed to enforce WDigest mitigation: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 3: Hardening SAM & Domain Credential Caching
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Restricts anonymous user enumeration against the SAM database and limits interactive cached logon tokens.
Write-HardeningLog -Message "Executing Component 3: SAM Enumeration & Credential Caching Hardening..." -Level 'INFO'

$winlogonRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

try {
    if (-not $AuditOnly) {
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType DWord

        # Winlogon CachedLogonsCount MUST be configured as REG_SZ (string value)
        Set-RegistryValueSafely -Path $winlogonRegistryPath -Name 'CachedLogonsCount' -Value ([string]$CachedLogonsCount) -PropertyType String
    } else {
        $raVal  = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'RestrictAnonymous'
        $rasVal = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'RestrictAnonymousSAM'
        $clcVal = Get-RegistryValueDirect -Path $winlogonRegistryPath -Name 'CachedLogonsCount'

        Write-HardeningLog -Message "[AUDIT] $lsaRegistryPath\RestrictAnonymous = $raVal (Target: 1)" -Level 'INFO'
        Write-HardeningLog -Message "[AUDIT] $lsaRegistryPath\RestrictAnonymousSAM = $rasVal (Target: 1)" -Level 'INFO'
        Write-HardeningLog -Message "[AUDIT] $winlogonRegistryPath\CachedLogonsCount = $clcVal (Target: $CachedLogonsCount)" -Level 'INFO'
    }
}
catch {
    Write-HardeningLog -Message "Failed to apply SAM/Winlogon hardening settings: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 4: Local Administrator Password Solution (LAPS) Assessment
# Server [2012, 2012R2, 2016] - Relies on Legacy LAPS (AdmPwd.dll CSE).
# Server [2019, 2022]        - Supports Legacy LAPS OR Native Windows LAPS (via modern cumulative updates).
# Server [2025]              - Built-in Native Windows LAPS with support for encryption and DSRM password backup.
Write-HardeningLog -Message "Executing Component 4: LAPS Architecture & Feature Detection..." -Level 'INFO'

try {
    $hasNativeLaps = $false
    $hasLegacyLaps = $false

    # Detect Native Windows LAPS (DLL or cmdlets present)
    $nativeLapsDll = Join-Path -Path $env:SystemRoot -ChildPath 'System32\LapsSnapIn.dll'
    if ((Test-Path -Path $nativeLapsDll) -or (Get-Command -Name 'Get-LapsDiagnostics' -ErrorAction SilentlyContinue)) {
        $hasNativeLaps = $true
    }

    # Detect Legacy LAPS (AdmPwd.dll client-side extension)
    $legacyLapsDll = Join-Path -Path $env:ProgramFiles -ChildPath 'LAPS\CSE\AdmPwd.dll'
    $legacyLapsSys32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\AdmPwd.dll'
    if ((Test-Path -Path $legacyLapsDll) -or (Test-Path -Path $legacyLapsSys32)) {
        $hasLegacyLaps = $true
    }

    Write-HardeningLog -Message "LAPS Status: Native Windows LAPS Detected = $hasNativeLaps | Legacy AdmPwd Detected = $hasLegacyLaps" -Level 'INFO'

    if ($hasNativeLaps) {
        # Server [2019, 2022, 2025] Native Windows LAPS baseline policy key
        $lapsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\LAPS'

        if (-not $AuditOnly) {
            # Enable Password Encryption for LAPS metadata stored in Active Directory
            Set-RegistryValueSafely -Path $lapsPolicyPath -Name 'PasswordEncryption' -Value 1 -PropertyType DWord
            
            # Server [2025] Enable Dedicated DSRM Password synchronization to LAPS if on Windows Server 2025
            if ($HostOS.ServerYear -eq '2025' -and $HostOS.IsDC) {
                Set-RegistryValueSafely -Path $lapsPolicyPath -Name 'BackupDirectory' -Value 1 -PropertyType DWord
                Write-HardeningLog -Message "Configured Windows Server 2025 Native LAPS directory backup policy." -Level 'SUCCESS'
            }
        } else {
            $encVal = Get-RegistryValueDirect -Path $lapsPolicyPath -Name 'PasswordEncryption'
            Write-HardeningLog -Message "[AUDIT] $lapsPolicyPath\PasswordEncryption = $(if ($null -ne $encVal) { $encVal } else { 'Not Configured' })" -Level 'INFO'
        }
    }
    elseif ($hasLegacyLaps) {
        # Server [2012, 2012R2, 2016] Legacy LAPS check
        Write-HardeningLog -Message "Host is using Legacy LAPS (AdmPwd). Ensure Active Directory Schema permissions for 'ms-Mcs-AdmPwd' are delegated securely." -Level 'WARN'
    }
    else {
        Write-HardeningLog -Message "No LAPS infrastructure (Legacy or Native) detected on this host. Deployment is strongly recommended." -Level 'WARN'
    }
}
catch {
    Write-HardeningLog -Message "Error evaluating LAPS architecture: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 5: Remote Hash Dumping / DCSync Audit (DS-Replication Rights)
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Audits the root of the Active Directory domain for non-standard principals possessing replication rights:
# 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
# 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
# 89e0becb-81e1-4243-97fb-01f97f4e9a4b (DS-Replication-Get-Changes-In-Filtered-Set)
Write-HardeningLog -Message "Executing Component 5: Active Directory DCSync Access Control Audit..." -Level 'INFO'

function Audit-DCSyncReplicationRights {
    [CmdletBinding()]
    param ()

    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-HardeningLog -Message "ActiveDirectory PowerShell module not available. Attempting raw dsacls fallback audit." -Level 'WARN'
            
            $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            $dsaclsPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\dsacls.exe"
            
            if (Test-Path -Path $dsaclsPath) {
                $rawAcl = & "$dsaclsPath" "$domainDN"
                $matches = $rawAcl | Select-String -Pattern 'Replicating Directory Changes'
                foreach ($line in $matches) {
                    Write-HardeningLog -Message "DSACLS ACE Warning: $($line.Line.Trim())" -Level 'WARN'
                }
            } else {
                Write-HardeningLog -Message "dsacls.exe binary was not located. Unable to execute DCSync rights audit." -Level 'ERROR'
            }
            return
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        $domainDN = (Get-ADDomain).DistinguishedName
        $domainAcl = Get-Acl -Path "AD:\$domainDN"

        # Well-Known DCSync Extended Right GUIDs
        $dcSyncGuids = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e0becb-81e1-4243-97fb-01f97f4e9a4b' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        }

        # Baseline authorized well-known SIDs
        $allowedSids = @(
            'S-1-5-32-544',        # Builtin Administrators
            'S-1-5-9',             # Enterprise Domain Controllers
            'S-1-5-18'             # Local System
        )

        # Baseline well-known RIDs for default replication principals
        $allowedRids = @(
            512, # Domain Admins
            516, # Domain Controllers
            519, # Enterprise Admins
            521  # Read-only Domain Controllers (Filtered Set only)
        )

        # Standard array initialization for backward compatibility with PS 3.0/4.0
        $unauthorizedPrincipals = @()

        foreach ($ace in $domainAcl.Access) {
            $guid = $ace.ObjectType.ToString()
            if ($dcSyncGuids.ContainsKey($guid)) {
                $identity = $ace.IdentityReference.Value
                $isStandard = $false
                $sid = $null

                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($identity)
                    $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

                    if ($allowedSids -contains $sid) {
                        $isStandard = $true
                    }
                    elseif ($sid -match '-(\d+)$') {
                        $rid = [int]$matches[1]
                        if ($allowedRids -contains $rid) {
                            $isStandard = $true
                        }
                    }
                }
                catch {
                    $sid = "UNRESOLVABLE_OR_ORPHANED_SID"
                }

                if (-not $isStandard) {
                    $finding = New-Object -TypeName PSCustomObject -Property @{
                        IdentityReference = $identity
                        SID               = $sid
                        ExtendedRight     = $dcSyncGuids[$guid]
                        ActiveDirectory   = $domainDN
                        AccessControlType = $ace.AccessControlType.ToString()
                    }
                    $unauthorizedPrincipals += $finding
                }
            }
        }

        if ($unauthorizedPrincipals.Count -gt 0) {
            Write-HardeningLog -Message "CRITICAL: Potential unauthorized DCSync accounts detected with directory replication rights!" -Level 'ERROR'
            foreach ($finding in $unauthorizedPrincipals) {
                Write-HardeningLog -Message "ALERT: Principal [$($finding.IdentityReference)] (SID: $($finding.SID)) holds [$($finding.ExtendedRight)] (Access: $($finding.AccessControlType))" -Level 'WARN'
            }
        } else {
            Write-HardeningLog -Message "DCSync Audit Passed: Only standard default Active Directory administrative containers possess directory replication rights." -Level 'SUCCESS'
        }
    }
    catch {
        Write-HardeningLog -Message "Error auditing replication access controls: $($_.Exception.Message)" -Level 'ERROR'
    }
}

Audit-DCSyncReplicationRights

#endregion

Write-HardeningLog -Message "Domain Controller hardening inspection/enforcement pass complete." -Level 'SUCCESS'
