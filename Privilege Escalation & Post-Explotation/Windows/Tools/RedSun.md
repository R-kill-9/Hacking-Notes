[RedSun](https://github.com/Nightmare-Eclipse/RedSun/releases) is a **local privilege escalation exploit** that abuses how **Windows Defender handles malicious file remediation**. Instead of exploiting memory corruption, it leverages a **logic flaw that allows file writes as SYSTEM**.

The attacker forces Defender to interact with attacker-controlled files and redirects the write operation to a **privileged location**, achieving arbitrary file overwrite.

---

## Exploitation Primitive

The vulnerability relies on this behavior:

- Defender scans a file marked as malicious
    
- It attempts remediation (delete/restore/replace)
    
- The operation is executed by `MsMpEng.exe` as **SYSTEM**
    
- If the path is redirected (symlink/junction), Defender writes to an unintended location
    

This results in a **SYSTEM-level arbitrary file write primitive**

---

## Basic Usage 

The PoC automates the process of:

- Creating controlled directories
    
- Placing a file that triggers Defender
    
- Redirecting paths using NTFS links
    
- Forcing Defender to perform the write


```bash
.\redsun.exe
```

If successful, Defender (running as SYSTEM):

- Follows the redirected path
    
- Writes into `System32` (or another protected location)

