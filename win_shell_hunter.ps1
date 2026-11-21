<#
.SYNOPSIS
    Universal CCDC Windows Webshell & Backdoor Hunter
.DESCRIPTION
    Pure ASCII. Compatible with PowerShell 5.1+.
    1. Auto-discovers webroots via IIS, listening web processes, and well-known paths.
    2. Searches for dangerous script functions (PHP, ASPX, JSP, Python).
    3. Identifies files modified recently (within the competition window).
    4. Detects hidden/disguised script files.
#>

$ErrorActionPreference = "SilentlyContinue"

Write-Output "`n=========================================================================================="
Write-Output "                      CCDC UNIVERSAL WEBSHELL & BACKDOOR HUNTER                           "
Write-Output "=========================================================================================="

# ====================================================================
# STEP 1: AUTO-DISCOVER ALL WEB APPLICATION LOCATIONS
# ====================================================================
Write-Output "[*] Discovering web application directories on $(hostname)..."

$discoveredPaths = New-Object System.Collections.Generic.HashSet[string]

# 1. Query IIS Websites (if IIS is running)
if (Get-Module -ListAvailable -Name WebAdministration) {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $iisSites = Get-Website -ErrorAction SilentlyContinue
    foreach ($site in $iisSites) {
        $p = $site.PhysicalPath
        if ($p -and (Test-Path $p)) {
            [void]$discoveredPaths.Add((Resolve-Path $p).Path)
        }
    }
}

# 2. Inspect Running Web Server Processes for Working Directories
$webProcs = @("httpd", "apache", "nginx", "php", "node", "python", "tomcat", "w3wp")
Get-CimInstance Win32_Process | Where-Object { $webProcs -contains $_.ProcessName.ToLower().Replace(".exe","") } | ForEach-Object {
    if ($_.ExecutablePath) {
        $procDir = Split-Path $_.ExecutablePath -Parent
        # Check adjacent htdocs/www/html folders
        foreach ($sub in @("htdocs", "html", "www", "webapps", "public")) {
            $candidate = Join-Path $procDir $sub
            if (Test-Path $candidate) { [void]$discoveredPaths.Add((Resolve-Path $candidate).Path) }
        }
    }
}

# 3. Well-Known Standard Webroot Paths on Windows
$commonRoots = @(
    "C:\inetpub\wwwroot",
    "C:\inetpub",
    "C:\xampp\htdocs",
    "C:\tools\xampp\htdocs",
    "C:\wamp\www",
    "C:\wamp64\www",
    "C:\laragon\www",
    "C:\Apache24\htdocs",
    "C:\nginx\html",
    "C:\Program Files\Apache Software Foundation\Tomcat*\webapps",
    "C:\Program Files\Apache Group\Apache*\htdocs",
    "C:\Program Files (x86)\Apache Group\Apache*\htdocs"
)

foreach ($cPath in $commonRoots) {
    Get-Item -Path $cPath -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-Path $_.FullName) { [void]$discoveredPaths.Add((Resolve-Path $_.FullName).Path) }
    }
}

# 4. Check Root C:\ for custom application/food service directories
Get-ChildItem -Path "C:\" -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match "^(app|apps|web|website|site|food|order|orders|restaurant|pos|store|shop|flokie|flokid)$"
} | ForEach-Object {
    [void]$discoveredPaths.Add((Resolve-Path $_.FullName).Path)
}

# 5. Always check staging/temp upload locations
$tempDirs = @("C:\Windows\Temp", "C:\Temp", "C:\ProgramData\tmp")
foreach ($td in $tempDirs) {
    if (Test-Path $td) { [void]$discoveredPaths.Add($td) }
}

Write-Output "[+] Discovered Target Scan Paths:"
foreach ($p in $discoveredPaths) {
    Write-Output "    -> $p"
}

if ($discoveredPaths.Count -eq 0) {
    Write-Output "[-] No webroot locations found! Please verify where the app was installed."
    return
}

# ====================================================================
# STEP 2: WEBSHELL EXTENSIONS & SIGNATURE SCAN
# ====================================================================
$extensions = @("*.php", "*.phtml", "*.php5", "*.php7", "*.phar", "*.aspx", "*.ashx", "*.asmx", "*.asp", "*.jsp", "*.jspx", "*.cfm", "*.pl", "*.cgi")

# Dangerous functions and command execution strings
$signatures = '(eval\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|cmd\.exe|powershell(\.exe)?\s+|Runtime\.getRuntime\(\)\.exec|Process\.Start|Request\.Item\[|upload_tmp_dir)'

Write-Output "`n[*] Scanning web directories for signature matches..."

$findings = @()

foreach ($dir in $discoveredPaths) {
    $files = Get-ChildItem -Path $dir -Include $extensions -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $matches = Select-String -Path $file.FullName -Pattern $signatures -ErrorAction SilentlyContinue
        if ($matches) {
            foreach ($m in $matches) {
                $snippet = $m.Line.Trim()
                if ($snippet.Length -gt 70) { $snippet = $snippet.Substring(0, 67) + "..." }
                $findings += [PSCustomObject]@{
                    File        = $file.Name
                    Line        = $m.LineNumber
                    Matched     = $m.Pattern
                    Path        = $file.FullName
                    Snippet     = $snippet
                }
            }
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Output "`n[!] CRITICAL: SUSPICIOUS EXECUTABLE CODE DETECTED:"
    $findings | Format-Table -Property File, Line, Snippet, Path -AutoSize -Wrap
} else {
    Write-Output "  [+] No dangerous execution keywords found in scanned files."
}

# ====================================================================
# STEP 3: RECENTLY CREATED OR MODIFIED SCRIPT FILES
# ====================================================================
# Defaults to files touched in the last 120 minutes
$sinceTime = (Get-Date).AddMinutes(-120)
Write-Output "`n[*] Checking for files created or modified since: $sinceTime (Last 2 hours)..."

$recentFiles = @()
foreach ($dir in $discoveredPaths) {
    $recent = Get-ChildItem -Path $dir -Include $extensions -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -ge $sinceTime -or $_.CreationTime -ge $sinceTime }
    
    foreach ($rf in $recent) {
        $recentFiles += [PSCustomObject]@{
            File         = $rf.Name
            SizeKB       = [math]::Round($rf.Length / 1KB, 2)
            LastModified = $rf.LastWriteTime
            Created      = $rf.CreationTime
            Directory    = $rf.DirectoryName
        }
    }
}

if ($recentFiles.Count -gt 0) {
    Write-Output "[!] CAUTION: RECENTLY MODIFIED WEB SCRIPTS DETECTED:"
    $recentFiles | Sort-Object LastModified -Descending | Format-Table -AutoSize
} else {
    Write-Output "  [+] No web scripts have been modified in the last 2 hours."
}

# ====================================================================
# STEP 4: HIDDEN FILES INSIDE WEB ROOTS
# ====================================================================
Write-Output "`n[*] Checking for hidden or dot-prefixed scripts (e.g. .shell.php)..."

$hiddenScripts = @()
foreach ($dir in $discoveredPaths) {
    Get-ChildItem -Path $dir -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object { ($_.Attributes -match "Hidden" -or $_.Name -like ".*") -and ($extensions -contains ("*" + $_.Extension)) } |
        ForEach-Object {
            $hiddenScripts += [PSCustomObject]@{
                File      = $_.Name
                Path      = $_.FullName
                Attribute = $_.Attributes
            }
        }
}

if ($hiddenScripts.Count -gt 0) {
    Write-Output "[!] WARNING: HIDDEN WEB SCRIPTS DISCOVERED:"
    $hiddenScripts | Format-Table -AutoSize
} else {
    Write-Output "  [+] No hidden scripts detected."
}

Write-Output "`n=========================================================================================="
Write-Output "[+] Webshell scan completed. Review any flagged files above immediately."
Write-Output "=========================================================================================="
