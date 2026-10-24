[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Perform non-destructive discovery and configuration verification only.")]
    [switch]$AuditOnly,

    [Parameter(Mandatory = $false, HelpMessage = "Roll back configuration to a previously captured state file.")]
    [switch]$Rollback,

    [Parameter(Mandatory = $false, HelpMessage = "Path to specific .clixml state backup file for rollback operations.")]
    [string]$BackupFile,

    [Parameter(Mandatory = $false, HelpMessage = "Directory to store state snapshots prior to applying hardening.")]
    [string]$BackupDirectory = "$env:SystemDrive\ProgramData\DCHardening\Backups",

    [Parameter(Mandatory = $false, HelpMessage = "Number of cached domain logons allowed (Default: 0 for DCs).")]
    [ValidateRange(0, 50)]
    [int]$CachedLogonsCount = 0,

    [Parameter(Mandatory = $false, HelpMessage = "RunAsPPL mode for modern OS (1 = UEFI Variable Protected, 2 = Without UEFI Variable Lock).")]
    [ValidateSet(1, 2)]
    [int]$PPLMode = 1
)

#region Internal Helper & State Functions

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
    try {
        if (Test-Path -Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $item -and ($item.PSObject.Properties.Name -contains $Name)) {
                return $item.$Name
            }
        }
    } catch { return $null }
    return $null
}

$script:OriginalStateRecords = @()

function Record-CurrentState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $keyExists = Test-Path -Path $Path
    $valueExists = $false
    $currentVal = $null
    $valKind = 'None'

    if ($keyExists) {
        try {
            $subPath = $Path -replace '^HKLM:\\', '' -replace '^HKLM:', ''
            $baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subPath, $false)
            if ($null -ne $baseKey) {
                if ($baseKey.GetValueNames() -contains $Name) {
                    $valKind = $baseKey.GetValueKind($Name).ToString()
                    $currentVal = $baseKey.GetValue($Name)
                    $valueExists = $true
                }
                $baseKey.Close()
            }
        } catch { $valueExists = $false }
    }

    $stateRecord = New-Object -TypeName PSCustomObject -Property @{
        Path         = $Path
        Name         = $Name
        KeyExisted   = $keyExists
        ValueExists  = $valueExists
        Value        = $currentVal
        PropertyType = $valKind
    }

    $script:OriginalStateRecords += $stateRecord
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
        Record-CurrentState -Path $Path -Name $Name

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
            ProductType  = $os.ProductType
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

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-HardeningLog -Message "Execution terminated: Must run from an elevated session." -Level 'ERROR'
    return
}

$HostOS = Get-HostOSProfile
Write-HardeningLog -Message "Host Detected: $($HostOS.Caption) (Build: $($HostOS.Build), Recognized Branch: Windows Server $($HostOS.ServerYear))" -Level 'INFO'

if (-not $HostOS.IsDC) {
    Write-HardeningLog -Message "Host does not advertise as ProductType=2 (Domain Controller). Proceeding with caution." -Level 'WARN'
}

#endregion

#region Rollback Engine

if ($Rollback) {
    Write-HardeningLog -Message "Initiating Rollback Engine..." -Level 'WARN'

    $targetFile = $BackupFile
    if ([string]::IsNullOrEmpty($targetFile)) {
        if (-not (Test-Path -Path $BackupDirectory)) {
            Write-HardeningLog -Message "Backup directory '$BackupDirectory' does not exist." -Level 'ERROR'
            return
        }

        $latestBackup = Get-ChildItem -Path $BackupDirectory -Filter "DCHardening_Backup_*.clixml" |
                        Sort-Object -Property LastWriteTime -Descending |
                        Select-Object -First 1

        if (-not $latestBackup) {
            Write-HardeningLog -Message "No state backup files (.clixml) found in '$BackupDirectory'." -Level 'ERROR'
            return
        }
        $targetFile = $latestBackup.FullName
    }

    if (-not (Test-Path -Path $targetFile)) {
        Write-HardeningLog -Message "Specified backup file does not exist: $targetFile" -Level 'ERROR'
        return
    }

    Write-HardeningLog -Message "Loading state manifest: $targetFile" -Level 'INFO'
    try {
        $restoreEntries = Import-Clixml -Path $targetFile -ErrorAction Stop

        foreach ($entry in $restoreEntries) {
            $path = $entry.Path
            $name = $entry.Name

            if (-not $entry.KeyExisted) {
                if (Test-Path -Path $path) {
                    if ($PSCmdlet.ShouldProcess($path, "Remove Registry Key (Created by Hardening)")) {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                        Write-HardeningLog -Message "Removed created key: $path" -Level 'SUCCESS'
                    }
                }
                continue
            }

            if (-not $entry.ValueExists) {
                if (Test-Path -Path $path) {
                    $existingVal = Get-RegistryValueDirect -Path $path -Name $name
                    if ($null -ne $existingVal) {
                        if ($PSCmdlet.ShouldProcess("$path\$name", "Remove Registry Value (Created by Hardening)")) {
                            Remove-ItemProperty -Path $path -Name $name -Force -ErrorAction SilentlyContinue
                            Write-HardeningLog -Message "Removed property: $path\$name" -Level 'SUCCESS'
                        }
                    }
                }
            } else {
                $origValue = $entry.Value
                $origType = [Microsoft.Win32.RegistryValueKind]::Parse([Microsoft.Win32.RegistryValueKind], $entry.PropertyType)

                if ($PSCmdlet.ShouldProcess("$path\$name", "Revert to original value: '$origValue' ($origType)")) {
                    $null = New-ItemProperty -Path $path -Name $name -Value $origValue -PropertyType $origType -Force -ErrorAction Stop
                    Write-HardeningLog -Message "Reverted '$path\$name' to: $origValue" -Level 'SUCCESS'
                }
            }
        }

        # Remove custom LOLBAS outbound firewall rules created during hardening
        $lolbasBinaries = @('mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'hh.exe')
        foreach ($bin in $lolbasBinaries) {
            $ruleName = "Block Outbound $bin"
            if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
                if ($PSCmdlet.ShouldProcess($ruleName, "Remove Hardening Firewall Rule")) {
                    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                    Write-HardeningLog -Message "Removed firewall rule: $ruleName" -Level 'SUCCESS'
                }
            }
        }

        Write-HardeningLog -Message "Rollback complete. Reboot the DC to flush kernel security state." -Level 'SUCCESS'
        return
    }
    catch {
        Write-HardeningLog -Message "Failed during rollback execution: $($_.Exception.Message)" -Level 'ERROR'
        return
    }
}

#endregion

#region Component 1: LSASS Protection (RunAsPPL)
# Server [2012]       - Unsupported natively (Build 9200).
# Server [2012R2]     - Introduced RunAsPPL (DWORD = 1).
# Server [2016, 2019] - RunAsPPL standard enforcement (DWORD = 1).
# Server [2022, 2025] - Value 1 = UEFI Lock, Value 2 = Without UEFI Lock.
Write-HardeningLog -Message "Executing Component 1: LSASS Process Protection (RunAsPPL)..." -Level 'INFO'

$lsaRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

try {
    if ($HostOS.ServerYear -eq '2012') {
        # Server [2012]
        Write-HardeningLog -Message "Server 2012 kernel does not natively support RunAsPPL. Skipping." -Level 'WARN'
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

#region Component 2: Mandatory Security Lockdown (NTLMv2, SMB Signing, Netlogon)
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Enforces NTLMv2 only, requires SMB Signing, encrypts Netlogon secure channel, and stops cleartext caching.
Write-HardeningLog -Message "Executing Component 2: Mandatory Security Lockdown..." -Level 'INFO'

$wdigestRegistryPath     = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$lanmanServerParamPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$lanmanWorkstationParam  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$netlogonParamPath       = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$winlogonRegistryPath    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

try {
    if (-not $AuditOnly) {
        # WDigest cleartext mitigation
        Set-RegistryValueSafely -Path $wdigestRegistryPath -Name 'UseLogonCredential' -Value 0 -PropertyType DWord

        # Enforce NTLMv2 Only; Refuse LM & NTLMv1 (LmCompatibilityLevel = 5)
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'LmCompatibilityLevel' -Value 5 -PropertyType DWord

        # Restrict Anonymous SAM and Enumeration
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RestrictAnonymous' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'EveryoneIncludesAnonymous' -Value 0 -PropertyType DWord

        # Require SMB Server & Workstation Packet Signing (Prevents SMB Relay/MitM attacks)
        Set-RegistryValueSafely -Path $lanmanServerParamPath -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $lanmanServerParamPath -Name 'EnableSecuritySignature' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $lanmanWorkstationParam -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWord

        # Disable Insecure Guest Logons on SMB Workstation redirector
        Set-RegistryValueSafely -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 -PropertyType DWord

        # Netlogon Secure Channel: Force Encryption and Signing
        Set-RegistryValueSafely -Path $netlogonParamPath -Name 'RequireSignOrSeal' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $netlogonParamPath -Name 'SealSecureChannel' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $netlogonParamPath -Name 'SignSecureChannel' -Value 1 -PropertyType DWord

        # Winlogon CachedLogonsCount: MUST be REG_SZ (string 0 on DCs)
        Set-RegistryValueSafely -Path $winlogonRegistryPath -Name 'CachedLogonsCount' -Value ([string]$CachedLogonsCount) -PropertyType String
    } else {
        Write-HardeningLog -Message "[AUDIT] Checking Mandatory Security Settings..." -Level 'INFO'
        $wdig = Get-RegistryValueDirect -Path $wdigestRegistryPath -Name 'UseLogonCredential'
        $lm   = Get-RegistryValueDirect -Path $lsaRegistryPath -Name 'LmCompatibilityLevel'
        $smb  = Get-RegistryValueDirect -Path $lanmanServerParamPath -Name 'RequireSecuritySignature'
        $nlog = Get-RegistryValueDirect -Path $netlogonParamPath -Name 'RequireSignOrSeal'
        Write-HardeningLog -Message "[AUDIT] UseLogonCredential: $wdig | LmCompatibilityLevel: $lm | SMB RequireSecuritySignature: $smb | Netlogon RequireSignOrSeal: $nlog" -Level 'INFO'
    }
}
catch {
    Write-HardeningLog -Message "Failed to apply Mandatory Security Lockdown: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 3: Advanced Logging, Event Log Sizing & Audit Policies
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Prioritizes Advanced Audit Subcategories, enables Command-Line & ScriptBlock logging, expands log buffers.
Write-HardeningLog -Message "Executing Component 3: Advanced Logging & Security Audit Configuration..." -Level 'INFO'

$auditPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$psPolicyPath    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

try {
    if (-not $AuditOnly) {
        # Prioritize Advanced Subcategories over legacy Basic categories
        Set-RegistryValueSafely -Path $lsaRegistryPath -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -PropertyType DWord

        # Log process command-line arguments in Event 4688
        Set-RegistryValueSafely -Path $auditPolicyPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord

        # Enable PowerShell Deep Logging (ScriptBlock & Module)
        Set-RegistryValueSafely -Path $psPolicyPath -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord
        Set-RegistryValueSafely -Path $psPolicyPath -Name 'EnableModuleLogging' -Value 1 -PropertyType DWord

        # Increase Event Log Sizes to 1GB to prevent rollover during forensic investigations
        $logNames = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')
        foreach ($log in $logNames) {
            $wevtutil = Join-Path -Path $env:SystemRoot -ChildPath 'System32\wevtutil.exe'
            if (Test-Path $wevtutil) {
                if ($PSCmdlet.ShouldProcess($log, "Expand log size to 1024000 KB")) {
                    & $wevtutil sl "$log" /ms:1048576000 | Out-Null
                }
            }
        }

        # Enforce Fine-Grained Advanced Subcategory Auditing via auditpol.exe
        $auditpol = Join-Path -Path $env:SystemRoot -ChildPath 'System32\auditpol.exe'
        if (Test-Path $auditpol) {
            $auditSettings = @(
                @{ Sub = "Credential Validation";               Succ = "enable"; Fail = "enable" }, # Event 4776
                @{ Sub = "Kerberos Service Ticket Operations";  Succ = "enable"; Fail = "enable" }, # Event 4769 (Kerberoast)
                @{ Sub = "Kerberos Authentication Service";     Succ = "enable"; Fail = "enable" }, # Event 4768 / 4771 (AS-REP)
                @{ Sub = "Process Creation";                    Succ = "enable"; Fail = "disable" },# Event 4688
                @{ Sub = "Security Group Management";           Succ = "enable"; Fail = "enable" }, # Event 4728, 4732
                @{ Sub = "User Account Management";             Succ = "enable"; Fail = "enable" }, # Event 4720, 4722
                @{ Sub = "Security System Extension";           Succ = "enable"; Fail = "enable" }, # LSA extension loading
                @{ Sub = "System Integrity";                    Succ = "enable"; Fail = "enable" }, # Driver/code integrity
                @{ Sub = "Sensitive Privilege Use";             Succ = "enable"; Fail = "enable" }, # Event 4672
                @{ Sub = "Directory Service Access";            Succ = "enable"; Fail = "enable" }, # Event 4662 (AD object reads)
                @{ Sub = "Directory Service Changes";           Succ = "enable"; Fail = "enable" }  # Event 5136 (AD modifications)
            )

            foreach ($setting in $auditSettings) {
                if ($PSCmdlet.ShouldProcess($setting.Sub, "Set Audit Policy: Success=$($setting.Succ), Failure=$($setting.Fail)")) {
                    & $auditpol /set /subcategory:"$($setting.Sub)" /success:$($setting.Succ) /failure:$($setting.Fail) | Out-Null
                }
            }
            Write-HardeningLog -Message "Configured critical DC security subcategory audit policies." -Level 'SUCCESS'
        }
    } else {
        $cmdLine = Get-RegistryValueDirect -Path $auditPolicyPath -Name 'ProcessCreationIncludeCmdLine_Enabled'
        $sbLog   = Get-RegistryValueDirect -Path $psPolicyPath -Name 'EnableScriptBlockLogging'
        Write-HardeningLog -Message "[AUDIT] ProcessCreationIncludeCmdLine: $cmdLine | EnableScriptBlockLogging: $sbLog" -Level 'INFO'
    }
}
catch {
    Write-HardeningLog -Message "Failed configuring logging and audit policies: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 4: Windows Firewall Hardening & LOLBAS Outbound Mitigations
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Enables Firewall across Domain, Private, and Public profiles, enables logging, and blocks LOLBAS outbound beacons.
Write-HardeningLog -Message "Executing Component 4: Windows Firewall & LOLBAS Egress Hardening..." -Level 'INFO'

try {
    if (-not $AuditOnly) {
        # 1. Enable Windows Firewall for all profiles
        if ($PSCmdlet.ShouldProcess("Firewall Profiles", "Enable Domain, Private, Public")) {
            Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
            Write-HardeningLog -Message "Windows Firewall enabled for Domain, Private, and Public profiles." -Level 'SUCCESS'
        }

        # 2. Configure Firewall Diagnostic Logging to pfirewall.log (16MB buffer)
        $fwLogPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\LogFiles\Firewall\pfirewall.log'
        if ($PSCmdlet.ShouldProcess("Firewall Logging", "Enable logging dropped and allowed connections to $fwLogPath")) {
            Set-NetFirewallProfile -Profile Domain, Private, Public -LogFileName $fwLogPath -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True -ErrorAction SilentlyContinue
            Write-HardeningLog -Message "Configured Windows Firewall connection logging: $fwLogPath" -Level 'SUCCESS'
        }

        # 3. Block Living-Off-The-Land Binaries (LOLBAS) from making outbound network connections
        $lolbasBinaries = @('mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'hh.exe')
        foreach ($bin in $lolbasBinaries) {
            $ruleName = "Block Outbound $bin"
            $binPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\$bin"

            if (Test-Path $binPath) {
                $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $existingRule) {
                    if ($PSCmdlet.ShouldProcess($ruleName, "Create outbound block firewall rule for $binPath")) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $binPath -Action Block -Profile Any -ErrorAction Stop | Out-Null
                        Write-HardeningLog -Message "Created egress firewall block: $ruleName" -Level 'SUCCESS'
                    }
                }
            }
        }
    } else {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($p in $profiles) {
            Write-HardeningLog -Message "[AUDIT] Firewall Profile [$($p.Name)] -> Enabled: $($p.Enabled) | BlockedLog: $($p.LogBlocked)" -Level 'INFO'
        }
    }
}
catch {
    Write-HardeningLog -Message "Failed to apply Windows Firewall hardening: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 5: Local Administrator Password Solution (LAPS) Assessment
# Server [2012, 2012R2, 2016] - Relies on Legacy LAPS (AdmPwd.dll CSE).
# Server [2019, 2022]        - Supports Legacy LAPS OR Native Windows LAPS.
# Server [2025]              - Built-in Native Windows LAPS with DSRM synchronization.
Write-HardeningLog -Message "Executing Component 5: LAPS Architecture & Feature Detection..." -Level 'INFO'

try {
    $hasNativeLaps = $false
    $hasLegacyLaps = $false

    $nativeLapsDll = Join-Path -Path $env:SystemRoot -ChildPath 'System32\LapsSnapIn.dll'
    if ((Test-Path -Path $nativeLapsDll) -or (Get-Command -Name 'Get-LapsDiagnostics' -ErrorAction SilentlyContinue)) {
        $hasNativeLaps = $true
    }

    $legacyLapsDll = Join-Path -Path $env:ProgramFiles -ChildPath 'LAPS\CSE\AdmPwd.dll'
    $legacyLapsSys32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\AdmPwd.dll'
    if ((Test-Path -Path $legacyLapsDll) -or (Test-Path -Path $legacyLapsSys32)) {
        $hasLegacyLaps = $true
    }

    Write-HardeningLog -Message "LAPS Status: Native LAPS = $hasNativeLaps | Legacy AdmPwd = $hasLegacyLaps" -Level 'INFO'

    if ($hasNativeLaps) {
        # Server [2019, 2022, 2025]
        $lapsPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\LAPS'
        if (-not $AuditOnly) {
            Set-RegistryValueSafely -Path $lapsPolicyPath -Name 'PasswordEncryption' -Value 1 -PropertyType DWord

            # Server [2025] Dedicated DSRM Password synchronization
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
        # Server [2012, 2012R2, 2016]
        Write-HardeningLog -Message "Host is using Legacy LAPS (AdmPwd). Ensure 'ms-Mcs-AdmPwd' schema permissions are restricted." -Level 'WARN'
    }
    else {
        Write-HardeningLog -Message "No LAPS infrastructure detected. Deployment is strongly recommended." -Level 'WARN'
    }
}
catch {
    Write-HardeningLog -Message "Error evaluating LAPS architecture: $($_.Exception.Message)" -Level 'ERROR'
}
#endregion

#region Component 6: Remote Hash Dumping / DCSync Audit (DS-Replication Rights)
# Server [2012, 2012R2, 2016, 2019, 2022, 2025]
# Audits the root of Active Directory for non-standard accounts possessing replication rights.
# Whitelists RID 498 (Enterprise Read-only Domain Controllers) and RID 521 (Read-only Domain Controllers).
Write-HardeningLog -Message "Executing Component 6: Active Directory DCSync Access Control Audit..." -Level 'INFO'

function Audit-DCSyncReplicationRights {
    [CmdletBinding()]
    param ()

    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-HardeningLog -Message "ActiveDirectory PowerShell module missing. Performing fallback dsacls check." -Level 'WARN'
            $domainDN = ([ADSI]"LDAP://RootDSE").defaultNamingContext
            $dsaclsPath = Join-Path -Path $env:SystemRoot -ChildPath "System32\dsacls.exe"

            if (Test-Path -Path $dsaclsPath) {
                $rawAcl = & "$dsaclsPath" "$domainDN"
                $matches = $rawAcl | Select-String -Pattern 'Replicating Directory Changes'
                foreach ($line in $matches) {
                    Write-HardeningLog -Message "DSACLS ACE Finding: $($line.Line.Trim())" -Level 'WARN'
                }
            } else {
                Write-HardeningLog -Message "dsacls.exe not found. Unable to audit replication rights." -Level 'ERROR'
            }
            return
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        $domainDN = (Get-ADDomain).DistinguishedName
        $domainAcl = Get-Acl -Path "AD:\$domainDN"

        # Extended Rights GUIDs for DCSync
        $dcSyncGuids = @{
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
            '89e0becb-81e1-4243-97fb-01f97f4e9a4b' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        }

        $allowedSids = @(
            'S-1-5-32-544', # Builtin Administrators
            'S-1-5-9',       # Enterprise Domain Controllers
            'S-1-5-18'       # Local System
        )

        # Baseline Allowed RIDs (includes 498 and 521 to eliminate false positives)
        $allowedRids = @(
            498, # Enterprise Read-only Domain Controllers (Universal Group)
            512, # Domain Admins
            516, # Domain Controllers
            519, # Enterprise Admins
            521  # Read-only Domain Controllers (Domain Global Group)
        )

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
            Write-HardeningLog -Message "CRITICAL: Non-standard accounts detected with directory replication rights!" -Level 'ERROR'
            foreach ($finding in $unauthorizedPrincipals) {
                Write-HardeningLog -Message "ALERT: Principal [$($finding.IdentityReference)] (SID: $($finding.SID)) holds [$($finding.ExtendedRight)] (Access: $($finding.AccessControlType))" -Level 'WARN'
            }
        } else {
            Write-HardeningLog -Message "DCSync Audit Passed: Only standard AD containers possess replication rights." -Level 'SUCCESS'
        }
    }
    catch {
        Write-HardeningLog -Message "Error auditing DCSync replication access: $($_.Exception.Message)" -Level 'ERROR'
    }
}

Audit-DCSyncReplicationRights

#endregion

#region Post-Hardening State Persistence

if (-not $AuditOnly -and $script:OriginalStateRecords.Count -gt 0) {
    try {
        if (-not (Test-Path -Path $BackupDirectory)) {
            $null = New-Item -Path $BackupDirectory -ItemType Directory -Force -ErrorAction Stop
        }

        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $manifestPath = Join-Path -Path $BackupDirectory -ChildPath "DCHardening_Backup_$timestamp.clixml"

        $script:OriginalStateRecords | Export-Clixml -Path $manifestPath -Force -ErrorAction Stop
        Write-HardeningLog -Message "Pre-hardening state saved to: $manifestPath" -Level 'SUCCESS'
        Write-HardeningLog -Message "To rollback: .\script.ps1 -Rollback -BackupFile `"$manifestPath`"" -Level 'INFO'
    }
    catch {
        Write-HardeningLog -Message "Warning: Failed to save rollback snapshot: $($_.Exception.Message)" -Level 'WARN'
    }
}

#endregion

Write-HardeningLog -Message "Domain Controller hardening pass completed successfully." -Level 'SUCCESS'
