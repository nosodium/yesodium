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
