**SSH** (Secure Shell) is a protocol used to securely access and manage remote devices over a network. It provides encrypted communication, ensuring data protection during remote login and file transfers.

## Nmap Enumeration
**Nmap** can be used to scan for open SSH ports (default 22) on the target system:

```bash
nmap -p 22 -sV -sS <target_ip>
```

---
## Usage & Enumeration
**Basic Usage:**

```bash
ssh <user>@<ip>
```

**Practical – Public Key Authentication:**

Generate key pair:

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
```

Copy public key to remote host:

```bash
ssh-copy-id user@remote_host
```

Login using key:

```bash
ssh -i ~/.ssh/id_rsa user@remote_host
```

**Auditing SSH server:**

```bash
git clone https://github.com/jtesta/ssh-audit.git
cd ssh-audit
./ssh-audit.py <IP>
```

**Testing authentication methods:**

```bash
ssh -v user@remote_host -o PreferredAuthentications=password
```

---
## Hydra
Brute force attacks can be used to test common or weak usernames and passwords against the SSH login. 

```bash
hydra -l <username> -P <password_list> ssh://<target_ip>
```

## Metasploit Enumeration 
**Metasploit** offers multiple modules for enumerating SSH services on a target.

- **Identify SSH Version**: Use the `ssh_version` module to identify the version of SSH running on the target system. 
- **Brute Force SSH Login**: Use the `ssh_login` module to perform brute force attacks against SSH credentials. If successful, a **session** will be created, allowing you to access the target system. To interact with the session, you must use the `sessions -i <session_id>` command to access and control the compromised system.

```bash
use <module_name>
set RHOSTS <target IP>
run
```