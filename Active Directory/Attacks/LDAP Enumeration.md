**LDAP** (Lightweight Directory Access Protocol) is commonly used by Active Directory to store and organize information such as users, groups, computers, and domain policies.

LDAP enumeration is the process of querying this directory to extract useful information, often without authentication if anonymous bind is enabled.

---

## Detecting LDAP Services

### Using Nmap

```bash
nmap -n -sV --script 'ldap* and not brute' -p 389 10.129.72.90
```

Purpose:

- Detect LDAP service
- Identify domain-related information
- Retrieve naming contexts
- Check if anonymous access is allowed

---

## Retrieve Naming Contexts and Domain Information

```bash
ldapsearch -x -H ldap://10.129.72.90 -s base
```

This command retrieves:

- defaultNamingContext
- rootDomainNamingContext
- Domain functionality level

Example output:

```
defaultNamingContext: dc=cascade,dc=local
```

This value is required as the Base DN for further LDAP queries.

---

## Enumerating Users

### Enumerate All Users

```bash
ldapsearch -x -H ldap://10.129.72.90 -b "dc=cascade,dc=local" "(objectClass=user)"
```

This is one of the most important LDAP queries.

It can reveal:

- sAMAccountName (valid usernames)
- description (often contains sensitive information)
- memberOf (group memberships)
- userAccountControl (account status and flags)
- pwdLastSet (password age)

Important note:  
User objects may contain **sensitive information such as plaintext passwords, temporary credentials, service account details, or internal notes** stored in attributes.


#### Enumerate Only Usernames

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" "(objectClass=user)" sAMAccountName
```

Useful for:

- Password spraying
- Kerberos-based attacks
- Username validation

---

## Enumerating Groups

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" "(objectClass=group)"
```

This allows identification of:

- Privileged groups (Domain Admins, Enterprise Admins)
- Custom administrative groups
- Users with elevated privileges


---

## Searching for Sensitive Descriptions

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" "(description=*)"
```

Why this is critical:  
Administrators sometimes store:

- Passwords
- Temporary credentials
- Service account details
- Operational notes

These fields are frequently overlooked and exposed via LDAP.

---

## Enumerating Computers

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" "(objectClass=computer)"
```

Useful for:

- Identifying servers and workstations
- Detecting additional domain controllers
- Planning lateral movement

---

## Enumerating Service Accounts (SPNs)

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" "(servicePrincipalName=*)"
```

Accounts with SPNs are potential targets for:

- Kerberoasting attacks


---

## Identifying AS-REP Roasting Targets

```bash
ldapsearch -x -H ldap://10.129.72.90 \
-b "dc=cascade,dc=local" \
"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```

This identifies users without Kerberos preauthentication enabled.
