A **DNS Zone Transfer** is a mechanism used to replicate DNS records from a primary (master) DNS server to secondary (slave) DNS servers. If misconfigured, it allows attackers to retrieve the entire DNS zone, exposing internal hosts and services.

---

## Why It Is Dangerous

An unrestricted zone transfer can disclose:

- Internal hostnames
    
- Subdomains
    
- Mail servers
    
- VPN gateways
    
- Internal IP addresses
    
- Naming conventions useful for attacks
    

---

## Important: Zone Transfers Can Be Allowed on Subzones

Even if a **parent domain** does **not** allow zone transfers, a **child or internal subzone** may still be misconfigured and vulnerable.

For example:

- `example.com` → AXFR denied
    
- `internal.example.com` → AXFR allowed
    

This happens when DNS administrators restrict transfers only on the main zone but forget to apply the same restrictions to internal zones.

---

## How to Identify a Vulnerable DNS Zone Transfer

A zone transfer is successfully exploited when any of the following occur.

### 1. AXFR Returns Records (Parent or Subzone)

If this command returns multiple DNS records instead of an error, the server is vulnerable:

```bash
dig axfr example.com @10.10.10.53
```

If it fails, **try internal subzones**:

```bash
dig axfr internal.example.com @10.10.10.53
```

#### Example: Internal Subzone Vulnerable (AXFR)

```bash
dig axfr internal.corp.example.local @10.10.50.53
```

```text
internal.corp.example.local. 604800 IN SOA  corp.example.local. root.corp.example.local. 3 604800 86400 2419200 604800
internal.corp.example.local. 604800 IN NS   ns.internal.corp.example.local.
internal.corp.example.local. 604800 IN TXT  "v=spf1 ip4:10.10.50.20 ~all"

dc1.internal.corp.example.local. 604800 IN A 10.10.50.10
dc2.internal.corp.example.local. 604800 IN A 10.10.50.11
mail.internal.corp.example.local. 604800 IN A 10.10.50.20
vpn.internal.corp.example.local. 604800 IN A 10.10.50.30
ws01.internal.corp.example.local. 604800 IN A 10.10.50.101
ws02.internal.corp.example.local. 604800 IN A 10.10.50.102

internal.corp.example.local. 604800 IN SOA  corp.example.local. root.corp.example.local. 3 604800 86400 2419200 604800
```

**Why This Confirms Exploitation:**

- The **internal subzone** is fully disclosed
    
- Multiple internal hostnames and IP addresses are returned
    
- The **SOA record appears at both the beginning and end**
    
- No “Transfer failed” or “REFUSED” message is shown
    
- Internal infrastructure that is normally hidden is exposed
    


### 2. nslookup Lists Domain Records

If the following command outputs domain entries, AXFR is allowed:

```text
nslookup
> server 10.10.10.53
> ls -d internal.example.com
```

Vulnerable behavior:

- Hostnames and IPs are enumerated
    
- No permission error is returned
    
### 3. Nmap Confirms Zone Transfer

```bash
nmap --script dns-zone-transfer -p 53 example.com
```

or explicitly against an internal zone:

```bash
nmap --script dns-zone-transfer -p 53 internal.example.com
```

Vulnerable result:

- DNS records are printed in output
    
- Internal hosts are enumerated
