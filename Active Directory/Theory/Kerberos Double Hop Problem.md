The Kerberos Double Hop problem occurs when authentication must pass through more than one system.

```
Attack Host → Server A → Server B (Domain Controller / File Server)
```

Kerberos does not forward full user credentials across multiple hops by default.

Kerberos authentication uses **tickets**, not passwords:

- **TGT (Ticket Granting Ticket)** → proves identity to the domain
    
- **TGS (Service Ticket)** → allows access to one specific service
    

When connecting through WinRM or PowerShell Remoting, only a **service ticket (TGS)** is sent to the first server.  
The **TGT is not forwarded**, so the second server cannot verify the user identity.

---

## Why It Happens

When authenticating with:

- WinRM
    
- Enter‑PSSession
    
- Evil‑WinRM
    

the user password or NTLM hash is **not stored in memory**.

Because of this:

- Server A cannot authenticate to Server B on behalf of the user.
    
- Access to domain resources fails even if permissions exist.
    

---

## Typical Symptoms

You successfully obtain a remote shell but domain queries fail.

Example:

```powershell
Enter-PSSession -ComputerName DEV01 -Credential DOMAIN\user
```

Then:

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser -SPN
```

Result:

```
DirectoryServicesCOMException
An operations error occurred
```

---

## Verifying the Problem

Check Kerberos tickets:

```powershell
klist
```

Output shows only a ticket for the current host:

```
Server: HTTP/DEV01
```

No `krbtgt` ticket is present.

---

## Memory Check (Mimikatz)

Inside a WinRM session:

```powershell
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

Observation:

- No reusable credentials for the logged-in user
    
- Password fields appear as `(null)`
    

This confirms credentials were not cached.

---

## Why RDP Does Not Have This Issue

When logging in via RDP:

- Password authentication occurs
    
- NTLM hash and Kerberos TGT are cached
    

Check:

```powershell
klist
```

You will see:

```
krbtgt/DOMAIN.LOCAL
```

Now the host can authenticate to other services.

---

## Workaround 1 — Pass Credentials Manually (PSCredential)

Create credential object:

```powershell
$SecPassword = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("DOMAIN\user",$SecPassword)
```

Execute commands with credentials:

```powershell
Get-DomainUser -SPN -Credential $Cred
```

Credentials are supplied for every request, bypassing double hop.

---

## Workaround 2 — Register PSSession Configuration (Windows Host)

Requires elevated PowerShell and GUI access.

Create delegated session:

```powershell
Register-PSSessionConfiguration -Name newsession -RunAsCredential DOMAIN\user
```

Restart WinRM:

```powershell
Restart-Service WinRM
```

Reconnect:

```powershell
Enter-PSSession -ComputerName DEV01 -ConfigurationName newsession -Credential DOMAIN\user
```

Verify:

```powershell
klist
```

Now a TGT ticket appears.
