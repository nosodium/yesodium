Setup:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $u='https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/setup.ps1?nocache='+(Get-Random); (New-Object System.Net.WebClient).DownloadFile($u, \"$env:TEMP\setup.ps1\"); & \"$env:TEMP\setup.ps1\""
```

```shell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/setup.ps1?v=' + (Get-Random), "$env:TEMP\setup.ps1"); & "$env:TEMP\setup.ps1"
```

SSH PS Script CMD Prompt:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/WIN_SSH.ps1'))"
```
Harden:

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/harden.ps1'))"
```

Audit Harden:

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/auditpost.ps1'))"
```

Security Policies:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/secpol.ps1'))"
```


Mock Setup DC CMD Prompt:

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/MockDCPt1.ps1'))"
```

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/MockDCPt2.ps1'))"
```


Seeder Test:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/seeder.ps1'))"
```


Inventory:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/inv.ps1'))"
```

Password Change Semi Manual:
```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nosodium/yesodium/refs/heads/main/pw.ps1'))"
```
