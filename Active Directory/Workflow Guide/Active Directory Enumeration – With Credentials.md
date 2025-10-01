Technical notes for **authenticated** reconnaissance of Windows Active Directory environments, extracted from [orange-cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg).


---
## Classic Enumeration

### Get all AD users 

```bash
## Find users exposed via SMB on the DC.
nxc smb <dc_ip> -u '<user>' -p '<password>' --users

## Dump all AD users from a DC.
GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>
```

### Find all users and host-level spidering (SMB reconnaissance)

Spider SMB across an IP range to discover hosts, shares and files.
```bash
# SMB spider with extended module
nxc smb <ip_range> -u '<user>' -p '<password>' -M spider_plus

# Alternative spider that looks for sensitive file extensions
manspider <ip_range> -c passw -e <file extensions> -d <domain> -u <user> -p <password>
```

## Enumerate SMB shares (browse and retrieve files)

Enumerate shares and optionally download a file from a share.
```bash
# List shares across an IP range
nxc smb <ip_range> -u '<user>' -p '<password>' --shares

# Get a specific file from a share
nxc smb <ip_range> -u '<user>' -p '<password>' --shares --get-file \\<path>\\<filename> <filename>
```

### BloodHound — Legacy collection (SharpHound / PowerShell collectors)

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

### BloodHound — CE / Community Edition (SOAPHound, SharpHound, rusthound-ce, bloodhound-python)

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

### LDAP enumeration — dumps, searches, and full LDAP harvests

Enumerate LDAP for users, groups, ACLs, delegation, and export results.
```bash
# ldapsearch-ad.py: targeted LDAP queries and output logging
ldapsearch-ad.py -l <dc_ip> -d <domain> -u <user> -p '<password>' -o <output.log> -t all

# ldapdomaindump: dump LDAP domain data to folder
ldapdomaindump -u <user> -p <password> -o <dump_folder> ldap://<dc_ip>:389

# ldeep (LDAP deep enumeration)
ldeep ldap -u <users> -p '<password>' -d <domain> -s ldap://<dc_ip> all <backup_folder>
```
