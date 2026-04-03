Technical notes for **authenticated** reconnaissance of Windows Active Directory environments, extracted from [orange-cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg).

---

## Password Policy Enumeration

```bash
# Dump domain password policy using NetExec
nxc smb <dc_ip> -u '<user>' -p '<password>' --pass-pol

# Enumerate password policy using enum4linux
enum4linux -P <dc_ip>

# Retrieve password policy via LDAP
ldapsearch -H ldap://<dc_ip> -x -b "DC=<domain>,DC=<local>" -s sub "*" | grep pwdHistoryLength

# Retrieve password policy using Windows built‑in command
net accounts /domain

# PowerView enumeration
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

---

## Get all AD users

```bash
# Find users exposed via SMB on the DC.
nxc smb <dc_ip> -u '<user>' -p '<password>' --users

# Dump all AD users from a DC.
GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>
```


---

## Find all users and host-level spidering (SMB reconnaissance)

Spider SMB across an IP range to discover hosts, shares and files.

```bash
# SMB spider with extended module
nxc smb <ip_range> -u '<user>' -p '<password>' -M spider_plus

# Alternative spider that looks for sensitive file extensions
manspider <ip_range> -c passw -e <file extensions> -d <domain> -u <user> -p <password>
```


---

## Enumerate SMB shares (browse and retrieve files)

Enumerate shares and optionally download a file from a share.

```bash
# List shares across an IP range
nxc smb <ip_range> -u '<user>' -p '<password>' --shares

# Get a specific file from a share
nxc smb <ip_range> -u '<user>' -p '<password>' --shares --get-file \\<path>\\<filename> <filename>
```

---

## LDAP enumeration — dumps, searches, and full LDAP harvests

Enumerate LDAP for users, groups, ACLs, delegation, and export results.

```bash
# ldapsearch-ad.py: targeted LDAP queries and output logging
ldapsearch-ad.py -l <dc_ip> -d <domain> -u <user> -p '<password>' -o <output.log> -t all

# ldapdomaindump: dump LDAP domain data to folder
ldapdomaindump -u <user> -p <password> -o <dump_folder> ldap://<dc_ip>:389

# ldeep (LDAP deep enumeration)
ldeep ldap -u <users> -p '<password>' -d <domain> -s ldap://<dc_ip> all <backup_folder>
```


---

## PowerView Enumeration (AD Recon from Windows)

PowerView allows in-memory enumeration of Active Directory without dropping binaries, commonly used after gaining a foothold on a domain-joined machine.

```bash
# Import PowerView
Import-Module .\PowerView.ps1

# List all domain groups
Get-DomainGroup

# List all domain users
Get-DomainUser

# Get members of a specific group
Get-DomainGroupMember -Identity "Domain Admins"

# Find machines where current user has local admin rights
Find-LocalAdminAccess

# Enumerate domain computers
Get-DomainComputer

# Find logged-in users on remote machines
Get-NetSession

# Enumerate shares in the domain
Find-DomainShare

# Check ACLs for interesting permissions
Get-ObjectAcl -Identity "Domain Admins"
```


---

## BloodHound — Legacy collection (SharpHound / PowerShell collectors)

Classic BloodHound collection methods (SharpHound / PowerShell / rusthound / bloodhound-python).

```bash
# SharpHound (executable)
sharphound.exe -c all -d <domain>

# SharpHound via PowerShell
import-module sharphound.ps1; invoke-bloodhound -collectionmethod all -domain <domain>

# rusthound (alternative collector)
rusthound -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z

# bloodhound-python (Linux / python collector)
bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all
```

---

## BloodHound — CE / Community Edition (SOAPHound, SharpHound, rusthound-ce, bloodhound-python)

CE-style and other collectors; produce BH dump files and split caches.

```bash
# SOAPHound (build cache and dump)
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output --autosplit --threshold 900

# SharpHound executable
sharphound.exe -c all -d <domain>

# rusthound-ce (CE variant)
rusthound-ce -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z --ldap-filter=(objectGuid=*)

# bloodhound-python (CE usage)
bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all
```
