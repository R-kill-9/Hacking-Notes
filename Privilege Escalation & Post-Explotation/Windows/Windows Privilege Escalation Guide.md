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
Get-ChildItem -Path C:\ -Include *.kdbx,*.ini,*.config -File -Recurse -ErrorAction SilentlyContinue   # Search common credential/config files
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue    # Search user documents
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
Get-History                            # Show commands from current PowerShell session (in-memory)
(Get-PSReadlineOption).HistorySavePath # Get path of persistent command history file
type (Get-PSReadlineOption).HistorySavePath  # Read persistent command history (PSReadLine)
dir C:\Users\Public\Transcripts\             # List PowerShell transcript files (if enabled)
type C:\Users\Public\Transcripts\*.txt  # Read transcript logs (commands + output)
Get-ChildItem -Path C:\ -Include *transcript*.txt -Recurse -ErrorAction SilentlyContinue            # Search for transcript files system-wide
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