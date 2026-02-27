User enumeration is the process of identifying **valid Active Directory usernames** before attempting authentication attacks.  
Accurate username discovery enables controlled password spraying, Kerberos attacks, and credential-based lateral movement while minimizing detection risk.

---

## Kerberos-Based Enumeration (Kerbrute)

Kerberos enumeration is typically the safest starting point when no credentials are available.

Kerbrute sends TGT requests to the Domain Controller without Kerberos pre-authentication. The response reveals account validity:

- `PRINCIPAL UNKNOWN` → username does not exist
    
- Pre-authentication requested → username is valid
    

This technique does not generate normal logon failures and does not increment bad password counters during enumeration.

```bash
kerbrute userenum -d <domain> --dc <dc_ip> <userlist>
```


---

## SMB Enumeration with NXC (NetExec)

NXC provides multiple methods to enumerate users through SMB and RPC services.

#### RID Brute Force (No Credentials)

Active Directory assigns incremental RIDs to objects. By brute forcing RIDs, usernames can often be recovered without authentication.

```bash
nxc smb <dc_ip> --rid-brute 10000
```

Clean extraction of usernames:

```bash
netexec smb <dc_ip> -u 'guest' -p '' --rid-brute \
| grep 'SidTypeUser' \
| sed -n "s/.*\\\\\([^ ]*\).*/\1/p" \
| sort -u
```

This method works even when anonymous enumeration is partially restricted.

#### Credentialed User Enumeration

When valid credentials are available, enumeration becomes significantly more reliable.

```bash
nxc smb <dc_ip> -u <username> -p <password> --users \
| awk '{if(NR>5) print $5}' \
| sort -u > domain_users.txt
```

Credentialed enumeration often reveals the full domain user base.

#### Enumerating Domain Users Group via RPC

Anonymous RPC queries may disclose group membership:

```bash
net rpc group members 'Domain Users' \
-W <domain> -I <dc_ip> -U '%'
```

#### MSSQL Context Enumeration

If SQL Server access is obtained, local users may also be enumerated:

```bash
nxc mssql <target_ip> -u <username> -p <password> \
--rid-brute 10000 --local-auth
```


---

### SMB NULL Session Enumeration

If SMB NULL sessions are enabled on the Domain Controller, usernames can be retrieved without credentials.

Using enum4linux:

```bash
enum4linux -U <dc_ip> \
| grep "user:" \
| cut -f2 -d"[" \
| cut -f1 -d"]"
```

Using rpcclient anonymously:

```bash
rpcclient -U "" -N <dc_ip>
```

Inside the shell:

```
enumdomusers
```

This provides raw domain usernames that can later be cleaned into a spray list.

---

### LDAP Anonymous Enumeration

If anonymous LDAP bind is permitted, it may expose a complete directory user list.

Using ldapsearch:

```bash
ldapsearch -h <dc_ip> -x \
-b "DC=<domain>,DC=<tld>" \
-s sub "(&(objectclass=user))" \
| grep sAMAccountName: | cut -f2 -d" "
```

Using windapsearch:

```bash
./windapsearch.py --dc-ip <dc_ip> -u "" -U
```

LDAP enumeration often returns both users and computer accounts, so filtering is required.