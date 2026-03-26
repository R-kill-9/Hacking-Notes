**WHOIS** is a protocol used to query public databases that store domain registration information. It operates over TCP port 43 and allows an attacker to gather metadata about domains, IP ranges, and ownership.

In a pentesting context, WHOIS is part of **passive reconnaissance**, meaning no direct interaction with the target system is required. The goal is to identify ownership, infrastructure, and potential pivot points before active enumeration.

---

## Information Retrieved from WHOIS

A WHOIS query can return multiple types of data depending on the registrar and privacy settings. The most relevant fields for an attacker are:

- Domain ownership (registrant)
    
- Registrar information
    
- Name servers (DNS infrastructure)
    
- Creation and expiration dates
    
- Contact details (sometimes exposed)
    
- Network allocation (for IP queries)
    

This information helps build a **profile of the target organization**, which can later be correlated with other findings.

---

## Forward Lookup (Domain → Owner Information)

A forward WHOIS lookup is performed using a domain name.

### Basic usage

```bash
whois example.com
```

### Example output

```text
Domain Name: EXAMPLE.COM
Registrar: NameCheap, Inc.
Creation Date: 2015-06-10
Registry Expiry Date: 2026-06-10

Registrant Name: John Doe
Registrant Organization: Example Corp

Name Server: ns1.example.com
Name Server: ns2.example.com
```

### Practical analysis

From this output, you can extract:

- The organization behind the domain
    
- The DNS servers used (useful for further enumeration)
    
- Domain age (new domains are often suspicious)
    
- Potential usernames (from registrant names)
    

This information is often used to support:

- OSINT profiling
    
- Username generation
    
- Infrastructure mapping
    

---

## Reverse Lookup (IP → Organization Information)

WHOIS can also be used with IP addresses to identify the organization or provider behind a server.

### Example

```bash
whois 8.8.8.8
```

### Output snippet

```text
NetRange:       8.8.8.0 - 8.8.8.255
OrgName:        Google LLC
Country:        US
```

### Practical use

This allows you to determine:

- Hosting provider (AWS, Cloudflare, etc.)
    
- Organization ownership
    
- Network ranges (for expanding scope)
    

This is useful when:

- You only have an IP from scanning
    
- You want to identify related infrastructure
    

---


## Querying Specific WHOIS Servers

You can specify a WHOIS server manually using the `-h` flag.

```bash
whois example.com -h whois.verisign-grs.com
```

This is useful when:

- Default queries are incomplete
    
- You want raw registry data
    
- Working in restricted lab environments (OSCP-style)
    

---

### Subdomain limitation

WHOIS only works on **registered domains**, not subdomains.

```bash
whois admin.example.com   # Invalid
whois example.com         # Valid
```

Subdomains must be analyzed using DNS tools like:

```bash
dig admin.example.com
```
