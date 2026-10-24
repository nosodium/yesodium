SSH PS Script CMD Prompt:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/WIN_SSH.ps1'))"
```

Test Harden Script CMD Prompt:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/HardenTest.ps1'))"
```
Mock Setup DC CMD Prompt:

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/MockDCPt1.ps1'))"
```

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/MockDCPt2.ps1'))"
```

HardenTest2:

Download:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/HardenTest2.ps1' -OutFile \"$env:USERPROFILE\Desktop\DCHardening.ps1\" -UseBasicParsing"
```

Dry Run:
```shell
# 1. Audit-Only Mode: Scans settings and DCSync rights, changes nothing
.\DCHardening.ps1 -AuditOnly

# 2. WhatIf Simulation: Simulates execution and shows every registry/firewall change that would occur
.\DCHardening.ps1 -WhatIf
```

Enforce:
```shell
.\DCHardening.ps1 | Tee-Object -FilePath "C:\DCHardening_Execution.log"
```

View Script Execution Logs:
```shell
Get-Content -Path "C:\DCHardening_Execution.log" -Tail 50
```

View Firewall Logs:
```shell
# View the live firewall log stream:
Get-Content -Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -Tail 30 -Wait
```
