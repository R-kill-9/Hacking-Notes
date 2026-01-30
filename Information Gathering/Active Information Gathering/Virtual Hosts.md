**Virtual hosting** allows a single web server (Apache, Nginx, IIS) to host multiple websites or applications on the same IP address. The web server differentiates incoming requests based on configuration logic, most commonly using the HTTP `Host` header.

Once DNS resolves a domain to an IP address, the web server configuration determines which content is served.

---

### Subdomains vs Virtual Hosts

#### Subdomains

- Defined at the DNS level.
    
- Example: `blog.example.com`
    
- Typically have DNS records (A/AAAA/CNAME).
    
- May point to the same or different IP address.
    
- Used to logically separate services or applications.
    

#### Virtual Hosts (VHosts)

- Defined in the web server configuration.
    
- Can be tied to domains or subdomains.
    
- Multiple VHosts can exist on the same IP without separate DNS records.
    
- Each VHost can have:
    
    - Separate document root
        
    - Separate logs
        
    - Separate security settings
        

A virtual host may exist even if no DNS record is present.

---

## Virtual Host Enumeration

VHost discovery focuses on identifying valid `Host` values that return unique or meaningful responses.

#### Common Techniques

- Brute-forcing the `Host` header
    
- Response size comparison
    
- HTTP status code differences
    
- Content fingerprinting
    


#### Gobuster (VHost Mode)

Used to brute-force virtual hosts by fuzzing the `Host` header.

```bash
gobuster vhost -u http://<IP> -w <wordlist> --append-domain
```

Key options:

- `-u` target URL (IP or base domain)
    
- `-w` wordlist
    
- `--append-domain` appends base domain to each word
    
- `-t` increase threads
    
- `-k` ignore TLS certificate errors
    
- `-o` output to file
    

Example:

```bash
gobuster vhost -u http://inlanefreight.htb:81 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
--append-domain
```


#### ffuf

```bash
ffuf -u http://<IP> -H "Host: FUZZ.example.com" -w wordlist.txt
```

#### Wfuzz

```bash
wfuzz -c \
-w wordlist.txt \
-H "Host: FUZZ.example.com" \
--hc 404 \
http://<TARGET_IP>/

```