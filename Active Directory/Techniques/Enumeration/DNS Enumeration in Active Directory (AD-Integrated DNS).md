Active Directory environments commonly use AD-integrated DNS zones, where DNS records are stored as objects inside LDAP.  
By default, **any authenticated domain user** can enumerate DNS zone child objects.

This allows attackers to discover:

- Hidden hosts
    
- Internal service names
    
- Non-descriptive machines identified during enumeration
    
- Additional attack targets not visible via standard DNS queries
    

Example problem:

```
SRV01934.DOMAIN.LOCAL
```

Hostnames like this do not reveal purpose. DNS records may expose aliases such as:

```
JENKINS.DOMAIN.LOCAL
BACKUP.DOMAIN.LOCAL
LOGISTICS.DOMAIN.LOCAL
```

---

## Why Standard DNS Queries Are Not Enough

LDAP queries against DNS zones do **not always return all records**.

AD DNS stores entries as directory objects:

```
CN=MicrosoftDNS,DC=DomainDnsZones,DC=domain,DC=local
```

Many records remain unresolved or hidden unless explicitly parsed.

---

## adidnsdump

`adidnsdump` enumerates DNS records directly via LDAP and reconstructs the full zone.

Requirement:

- Valid domain user credentials
    
- LDAP access to a Domain Controller
    

### Basic Enumeration

```
adidnsdump -u DOMAIN\\username ldap://DC_IP
```

Process:

1. Connects to LDAP
    
2. Authenticates (bind)
    
3. Queries DNS zone objects
    
4. Dumps results into `records.csv`
    

Output example:

```
[+] Bind OK
[+] Found 27 records
```

### Reviewing Results

```
head records.csv
```

Example output:

```
type,name,value
?,LOGISTICS,?
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::231
```

Meaning:

- `A` → IPv4 record
    
- `AAAA` → IPv6 record
    
- `?` → unresolved record
    

Unresolved entries often indicate hidden or non-standard DNS objects.

### Resolving Unknown Records

Use the resolve flag:

```
adidnsdump -u DOMAIN\\username ldap://DC_IP -r
```

What `-r` does:

- Performs additional DNS A queries
    
- Attempts to resolve unknown entries automatically
