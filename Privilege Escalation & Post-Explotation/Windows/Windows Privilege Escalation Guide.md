> For advanced techniques and automated enumeration, refer to tools like PowerUp, PowerView, and SharpHound. 

## Basic Reconnaissance

Collect system-level and user-level information to understand the attack surface:
```powershell
whoami                     # Current user
hostname                   # Hostname
systeminfo                 # OS version, hotfixes, architecture
echo %USERNAME%            # Username
echo %USERDOMAIN%          # Domain
net config workstation     # More about the user context
```

## Environment Variables and PATH Abuse

Check PATH variable and environment for hijack opportunities:
```powershell
Get-ChildItem Env:         # List all environment variables
$env:PATH.Split(';')       # View each path entry individually
```

## User and Group Enumeration

Identify local users, admins, and domain memberships:
```powershell
net user                   # List local users
net localgroup administrators   # Local admins
whoami /groups             # List user groups
whoami /priv               # User privileges
whoami /all                # Get all the information related with the user
```

## Privilege Escalation via Schedules or Services

Check for scheduled tasks and weak service configurations:
```powershell
schtasks /query /fo LIST /v      # Enumerate scheduled tasks
Get-Service | Where { $_.StartType -eq "Auto" }  # Autostart services
```

## Credential Access

Use native Windows tools to dump or discover sensitive data:
```powershell
cmdkey /list                     # List saved credentials
dir C:\Users\*\AppData\Roaming  # Look for config or vaults
```

## Auto-Login Registry Secrets

These registry keys may store plaintext credentials:
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```

## Powershell History

Use it to discover passwords in plain text:
```powershell
cd $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\
ls
type ConsoleHost_history.txt
```

## Network Enumeration

Identify open ports, connections, and shares:
```powershell
netstat -ano                    # Active network connections
net share                       # Shared folders
net view /domain                # Domain computers
```

## Automatic Tools
For advanced techniques and automated enumeration, use these tools:
```powershell
PowerUp.ps1                    # Privilege escalation checks in PowerShell
PowerView.ps1                  # Active Directory enumeration and recon
SharpHound.exe                 # BloodHound data collection tool
```