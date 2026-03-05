**Medusa** is a **fast, massively parallel, and modular login brute‑forcing tool** used in penetration testing to test the strength of authentication mechanisms. It is often considered an **alternative to Hydra**, particularly in scenarios where **high parallelization and performance are required**, such as testing multiple hosts or large credential lists. While Hydra is widely used for web login brute‑forcing, **Medusa can be more efficient when attacking services like SSH, FTP, IMAP, or RDP across many targets simultaneously** due to its optimized threading and modular architecture.

---

## Installation

Medusa is commonly included in penetration testing distributions such as Kali Linux. You can verify whether it is installed with:

```bash
medusa -h
```

If it is not installed, it can be installed on most Debian-based systems using:

```bash
sudo apt-get update
sudo apt-get install medusa
```

---

## Basic Usage

```bash
medusa -h <target_ip> -U <userlist> -P <passlist> -M <service>
```

### Common Parameters

|Parameter|Description|Example|
|---|---|---|
|-h HOST|Target host (IP or domain)|`-h 192.168.1.10`|
|-H FILE|File containing multiple targets|`-H targets.txt`|
|-u USER|Single username|`-u admin`|
|-U FILE|Username wordlist|`-U users.txt`|
|-p PASS|Single password|`-p password123`|
|-P FILE|Password wordlist|`-P passwords.txt`|
|-M MODULE|Service module to use|`-M ssh`|
|-m OPTION|Additional module parameters|`-m "FORM:username=^USER^&password=^PASS^"`|
|-t TASKS|Number of parallel threads|`-t 10`|
|-n PORT|Custom service port|`-n 2222`|
|-f|Stop after first valid credential per host|`-f`|
|-F|Stop after first valid credential globally|`-F`|
|-v LEVEL|Verbose output level (0–6)|`-v 4`|

---

## Medusa Modules

Medusa uses modules to interact with specific authentication services.

|Module|Service|Example|
|---|---|---|
|ftp|FTP authentication|`medusa -M ftp -h <target> -u admin -P passwords.txt`|
|http|HTTP authentication|`medusa -M http -h <target> -U users.txt -P passwords.txt -m GET`|
|imap|Email server authentication|`medusa -M imap -h mail.example.com -U users.txt -P passwords.txt`|
|mysql|MySQL database authentication|`medusa -M mysql -h <target> -u root -P passwords.txt`|
|pop3|POP3 mail service|`medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt`|
|rdp|Remote Desktop Protocol|`medusa -M rdp -h <target> -u admin -P passwords.txt`|
|ssh|Secure Shell authentication|`medusa -M ssh -h <target> -U users.txt -P passwords.txt`|
|telnet|Telnet service|`medusa -M telnet -h <target> -u admin -P passwords.txt`|
|vnc|VNC remote desktop|`medusa -M vnc -h <target> -P passwords.txt`|
|web-form|Web login form brute-force|`medusa -M web-form -h <target> -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"`|

---

## Brute‑Forcing an SSH Service

A common scenario in penetration testing is verifying whether an SSH server is protected against weak credentials.

Example:

```bash
medusa -h <target_ip> -U usernames.txt -P passwords.txt -M ssh
```

This command performs the following:

- Targets the specified host.
    
- Uses a list of usernames.
    
- Attempts each password from the wordlist.
    
- Uses the **ssh module** to test authentication attempts.
    

Example with a custom port and increased parallelization:

```bash
medusa -h <target_ip> -U usernames.txt -P passwords.txt -M ssh -n 2222 -t 10
```

---

## Testing Multiple Hosts with HTTP Basic Authentication

Medusa can also target **multiple hosts simultaneously**, making it useful during large-scale credential testing.

Example:

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

This attack will:

- Iterate through each target listed in `web_servers.txt`
    
- Attempt authentication using each username and password combination
    
- Use HTTP GET requests to perform authentication attempts.
    

---

## Brute‑Forcing a Web Login Form

Medusa can brute-force web forms by defining POST parameters and failure messages.

Example:

```bash
medusa -h <target_domain> -U users.txt -P passwords.txt -M web-form -m FORM:"username=^USER^&password=^PASS^:F=Invalid"
```

Explanation:

- `^USER^` and `^PASS^` are placeholders replaced with values from the wordlists.
    
- `F=Invalid` defines the failure message returned when authentication fails.
    

---

## Testing for Empty or Default Passwords

Medusa can test for common misconfigurations such as **empty passwords or passwords identical to the username**.

Example:

```bash
medusa -h <target_ip> -U usernames.txt -e ns -M <service_module>
```

Options used:

- `-e n` → test empty passwords
    
- `-e s` → test passwords identical to usernames
    

