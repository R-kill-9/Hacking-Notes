## Cmdkey
**cmdkey** is a Windows command-line utility used to manage stored credentials. It can create, list, and delete credentials that are used for network authentication. Common use cases include storing credentials for RDP connections, network shares, and web services.

- `<target>`: Hostname, IP address, or domain (e.g., `192.168.1.100`, `example.com`)
- `<username>`: The username for authentication
- `<password>`: The password for the user

#### Add credentials

```powershell
cmdkey /add:<target> /user:<username> /pass:<password>
```

#### List stored credentials
```powershell
cmdkey /list
```
Although the administrator’s password is not visible in plain text using cmdkey, if stored credentials are returned, we can exploit this by running commands with the saved credentials using:
```powershell
runas.exe /savecred /user:administrator cmd
```

#### Delete credentials
```powershell
cmdkey /delete:<target>
```

#### Abusing Extracted Credentials

If a password is retrieved, an attacker can impersonate the user:

```powershell
runas /user:Administrator cmd
```

---

## Registry Credential Extraction

Windows can be configured to automatically log in a user after boot. This is commonly used in kiosk systems or enterprise environments. To achieve this, the system stores login credentials—including plaintext passwords—in the registry. If misconfigured or left exposed, attackers with local access can extract these credentials and use them for privilege escalation or lateral movement.

#### Target Registry Keys

These values reside under the following registry path:

```powershell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

#### Registry Queries for Auto-Login Configuration
These values can be queried using the following commands:
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```
These values can be queried using the following commands:



---


## Passwords in Windows Configuration Files
#### Passwords Stored in PowerShell History
PowerShell maintains a history of previously executed commands in a plaintext file. If sensitive commands (like those using `cmdkey`, `net use`, `runas`, or scripts with passwords) were run, those credentials may remain in history.

**Location of PowerShell History File**
```powershell
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Unattended.xml
The **unattended.xml** file is an automation configuration file used during Windows installations (including deployments via WDS, MDT, or other tools). It provides instructions for automating tasks like partitioning disks, creating users, and setting passwords.

**Where Passwords Appear**

Administrator account credentials or local user passwords may be included in plaintext under nodes like `<UserAccounts>` or `<AutoLogon>`.

```xml
<AutoLogon>
    <Password>
        <Value>P@ssw0rd123</Value>
    </Password>
</AutoLogon>
```

This file is commonly stored on installation media or left on systems in `C:\Windows\Panther\` or `C:\Windows\System32\Sysprep\`.

The password is stored in base64, so it would need to be decoded.

```bash
echo  "password" > <password_file>
base64 --decode <password_file> 
```

