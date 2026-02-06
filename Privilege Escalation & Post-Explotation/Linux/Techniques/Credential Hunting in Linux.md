Credential hunting is one of the **first post-compromise actions** after gaining access to a Linux system. These credentials often enable **horizontal movement**, **privilege escalation**, or **full system compromise** within minutes.

The goal is to locate **stored, reused, or exposed credentials** across the system using systematic enumeration.

---

## Credential Sources Overview

Credential artifacts typically fall into four major categories:

1. **Files**
    
2. **History**
    
3. **Logs**
    
4. **Memory & Keyrings**
    

Effective credential hunting requires enumerating **all categories**, adapting to the system’s role (web server, database server, user workstation, etc.).

---

## 1. File-Based Credential Hunting

Linux follows the principle that _everything is a file_, making filesystem enumeration critical.

### High-Value File Categories

- Configuration files
    
- Databases
    
- Notes
    
- Scripts
    
- Cronjobs
    
- SSH keys
    

---

### Configuration Files

Config files often contain **plaintext credentials**, API keys, or connection strings.

Common extensions:

- `.conf`
    
- `.config`
    
- `.cnf`
    

#### Finding Configuration Files

```bash
for l in .conf .config .cnf; do
  find / -name "*$l" 2>/dev/null | grep -v "lib\|share\|fonts\|core"
done
```

#### Searching for Credentials Inside Configs

```bash
for i in $(find / -name "*.cnf" 2>/dev/null); do
  grep -i "user\|pass\|password" "$i" 2>/dev/null | grep -v "#"
done
```

Common targets:

- `/etc/mysql/debian.cnf`
    
- Application configs
    
- Backup config files
    

---

### Database Files

Credentials may be stored inside database dumps or local DB files.

Common extensions:

- `.sql`
    
- `.db`
    
- `.db*`
    

```bash
for l in .sql .db .*db .db*; do
  find / -name "*$l" 2>/dev/null | grep -v "doc\|lib\|share"
done
```

Notable locations:

- Browser databases (`key4.db`, `cert9.db`)
    
- Application caches
    
- SQLite application storage
    

---

### Notes and Plaintext Files

Admins and developers frequently store credentials in notes.

Targets:

- `.txt` files
    
- Files without extensions
    

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

Look for:

- TODO files
    
- Deployment notes
    
- Debug documentation
    

---

### Scripts and Source Code

Scripts often embed credentials to enable automation.

Common extensions:

- `.sh`
    
- `.py`
    
- `.pl`
    
- `.go`
    
- `.jar`
    
- `.c`
    

```bash
for l in .sh .py .pl .go .jar .c; do
  find / -name "*$l" 2>/dev/null | grep -v "lib\|share"
done
```

Focus on:

- Backup scripts
    
- Deployment scripts
    
- API clients
    

---

### Cronjobs

Cronjobs may execute scripts containing credentials.

Key locations:

- `/etc/crontab`
    
- `/etc/cron.d/`
    
- `/etc/cron.daily/`
    
- `/etc/cron.hourly/`
    

```bash
cat /etc/crontab
ls -la /etc/cron.*
```

Cron scripts frequently run as **root**, making them valuable escalation vectors.

---

## 2. History-Based Credential Hunting

### Bash History

Users often accidentally type credentials directly into the shell.

```bash
tail -n 50 /home/*/.bash_history
```

Also inspect:

- `.bashrc`
    
- `.bash_profile`
    
- `.profile`
    

Look for:

- `mysql -u user -pPASSWORD`
    
- `ssh user@host`
    
- Inline script execution with arguments
    

---

## 3. Log File Analysis

Linux logs often reveal:

- Successful logins
    
- Failed authentication attempts
    
- Password changes
    
- Command execution via sudo
    

### Important Log Files

|File|Purpose|
|---|---|
|`/var/log/auth.log`|Authentication events (Debian)|
|`/var/log/secure`|Authentication events (RedHat)|
|`/var/log/syslog`|System activity|
|`/var/log/cron`|Cron executions|
|`/var/log/httpd/`|Web server logs|
|`/var/log/mysql/`|Database logs|

### Automated Keyword Search

```bash
for i in /var/log/*; do
  grep -Ei "accepted|password|sudo|ssh|session opened|failed" "$i" 2>/dev/null
done
```

Logs can reveal:

- Valid usernames
    
- Password reuse
    
- Administrative behavior
    

---

## 4. Memory, Cache, and Keyrings

### Mimipenguin

[Mimipenguin](https://github.com/huntergregal/mimipenguin) extracts credentials directly from memory.

Requirements:

- Root privileges
    
- Desktop session (e.g. GNOME)
    

```bash
sudo python3 mimipenguin.py
```

Can recover:

- Logged-in user passwords
    
- Cached credentials
    

---

### LaZagne

[LaZagne]([https://raw.githubusercontent.com/AlessandroZ/LaZagne/refs/heads/master/Linux/laZagne.py](https://github.com/AlessandroZ/LaZagne/tree/master/Linux)) is a comprehensive credential extraction framework.

Sources include:

- Browsers
    
- Keyrings
    
- WiFi
    
- SSH
    
- Git
    
- Shadow
    
- ENV variables
    
- Databases
    

```bash
sudo python3 laZagne.py all
```

Especially effective on:

- User workstations
    
- Developer machines
    

---

## 5. Browser Credential Hunting

Browsers store encrypted credentials locally.

### Firefox Storage

Location:

```
~/.mozilla/firefox/<profile>/
```

Key files:

- `logins.json`
    
- `key4.db`
    
- `cert9.db`
    

### Decrypting Firefox Credentials

Using [Firefox Decrypt](https://github.com/unode/firefox_decrypt.git):

```bash
python3 firefox_decrypt.py
```

Recovered data includes:

- URLs
    
- Usernames
    
- Plaintext passwords
    

LaZagne can also extract browser credentials automatically.
