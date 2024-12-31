
## Unattended.xml
The **unattended.xml** file is an automation configuration file used during Windows installations (including deployments via WDS, MDT, or other tools). It provides instructions for automating tasks like partitioning disks, creating users, and setting passwords.

#### **Where Passwords Appear**

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
