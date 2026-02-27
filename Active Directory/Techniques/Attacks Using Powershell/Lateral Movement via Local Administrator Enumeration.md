This is an explanation of lateral movement using **PowerView** to discover **local administrator access** on remote hosts and then leveraging **PowerShell Remoting (WinRM)**.

---

## 1) . .\PowerView.ps1
**Dot-sources** the `PowerView.ps1` script into the current PowerShell session. This imports all functions defined in the file (e.g., `Get-DomainUser`, `Find-LocalAdminAccess`) so you can call them as native commands.

```powershell
. .\PowerView.ps1
```


---

## 2) Find-LocalAdminAccess
`Find-LocalAdminAccess` is a PowerView function designed to find **where a given account (or group) has local administrator rights** on other computers in the domain.
```powershell
Find-LocalAdminAccess
```


**Typical behavior / checks performed**

- Enumerates domain machines (via LDAP/AD or a list).

- For each target host it checks the local Administrators group membership (via `Get-ObjectAcl`, `Invoke-Command`, `NetLocalGroupGetMembers` style calls, or by enumerating group SIDs and membership).

- It determines if the current user (or a specified account) is a member of the local `Administrators` group on remote hosts — either directly or via nested groups.

- It reports the list of hosts where you have local admin rights (very useful for lateral movement and privilege escalation).


**Common usage variants**

```powershell
# Default (checks current domain and current user)
Find-LocalAdminAccess

# Check specific user
Find-LocalAdminAccess -UserName 'research\alice'

# Limit scope to specific computers
Find-LocalAdminAccess -ComputerName (Get-NetComputer -FullData | Select-Object -ExpandProperty Name)
```

**Output**

- A table / list showing hostnames, evidence (which group membership grants the access), and method used (ACL / direct membership).

- Example:


```
ComputerName           AccountThatGivesAdmin
------------           ---------------------
SEClogs                DOMAIN\research\alice
DC01                   DOMAIN\Domain Admins
```


---

## 3) Enter-PSSession seclogs.research.SECURITY.local
Attempts to start an **interactive remote PowerShell session** (PowerShell Remoting / WinRM) to `seclogs.research.SECURITY.local`.

```powershell
Enter-PSSession seclogs.research.SECURITY.local
```
