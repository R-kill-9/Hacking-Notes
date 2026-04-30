> For a deeper understanding and detailed techniques on each topic, review the expanded content available in the **Techniques** directory.

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
net user <user>            # List a single user
net localgroup administrators   # List local admins
net localgroup <group>     # List users from a group
whoami /groups             # List user groups
whoami /priv               # User privileges
whoami /all                # Get all the information related with the user
net user /domain           # List all domain users
net group /domain          # List all domain groups
net group "Domain Admins" /domain # Enumerate members of the Domain Admins group
nltest /dclist:<domain>    # List all domain controllers for the specified domain
```

## Scheduled tasks

Check for scheduled tasks:
```powershell
schtasks /query /fo LIST /v      # Enumerate scheduled tasks
icacls "C:\path\to\service.exe"  # List permissions to modify a binary related to a task
```

## Services

Check for weak service configurations:
```powershell
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -eq "Running"} | Select Name,PathName # List running services
Get-CimInstance -ClassName win32_service | Select Name,PathName | Where-Object {$_.PathName -notlike "C:\Windows\*"} # Identify non-system service binaries
icacls "C:\path\to\service.exe"  # Check file permissions 
Get-Service | Where { $_.StartType -eq "Auto" }  # Autostart services
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """              # List services vulnerables to unquoted paths
```
## Installed Applications

Check for sensitive information in installed applications:
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname   # Enumerate all 32-bit installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname               # Enumerate all 64-bit installed applications
Get-Process                      # Enumerate running applications
Get-Process -Name <ProcessName> | Select-Object Name, Id, Path                                   # Obtain information about an specific process
```
## Credential Access

Use native Windows tools to dump or discover sensitive data:
```powershell
cmdkey /list                    # List saved credentials
Get-ChildItem -Path C:\Users\ -Include *.kdbx,*.ini,*.config,*.settings -File -Recurse -Force -ErrorAction SilentlyContinue   # Search common credential/config files
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -Force -ErrorAction SilentlyContinue    # Search user documents
```

## Auto-Login Registry Secrets

These registry keys may store plaintext credentials:
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```

## History

Use it to discover passwords in plain text:
```powershell
Get-History                                        # Current session history (memory only)
(Get-PSReadLineOption).HistorySavePath            # Path to persistent PSReadLine history
type (Get-PSReadLineOption).HistorySavePath       # Read current user's persistent history

dir C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\    # Enumerate PowerShell history files for all users
type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

dir C:\Users\*\Documents\PowerShell_transcript*.txt -ErrorAction SilentlyContinue    # Common transcript location
Get-ChildItem -Path C:\ -Filter "*transcript*" -Recurse -ErrorAction SilentlyContinue # Search custom transcript paths

reg query "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription"        # Check transcript policy
reg query "HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
```

## Network Enumeration

Identify open ports, connections, and shares:
```powershell
ipconfig /all                   # List all network interfaces 
route print                     # Display the routing table
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