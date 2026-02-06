Linux systems support multiple authentication mechanisms. The most widely used framework is **Pluggable Authentication Modules (PAM)**, which provides a flexible and modular way to handle authentication, authorization, session management, and password policies.

## Pluggable Authentication Modules (PAM)

PAM is a framework that allows applications to authenticate users using configurable modules rather than hard-coded logic.

- Common PAM modules:
    
    - `pam_unix.so` / `pam_unix2.so`: Local UNIX authentication
        
    - `pam_ldap.so`: LDAP-based authentication
        
    - `pam_krb5.so`: Kerberos authentication
        
    - `pam_mount.so`: Mounting resources at login
        
- Module location (Debian-based systems):

```
/usr/lib/x86_64-linux-gnu/security/
```


When a user authenticates or changes a password (e.g., using the `passwd` command), PAM:

1. Validates credentials
    
2. Applies password policies
    
3. Updates authentication databases securely
    

PAM interacts primarily with:

- `/etc/passwd`
    
- `/etc/shadow`
    
- `/etc/security/opasswd`
    

---

## /etc/passwd File

The `/etc/passwd` file contains basic account information for all users and is **world-readable**.

### Format

Each line consists of seven colon-separated fields:

```
username:password:UID:GID:GECOS:home_directory:login_shell
```

Example:

```
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

|Field|Description|
|---|---|
|Username|Account name|
|Password|Placeholder (`x`) or hash (legacy systems)|
|UID|User ID|
|GID|Primary group ID|
|GECOS|User information|
|Home directory|User home path|
|Login shell|Default shell|

### Security Considerations

- The password field usually contains `x`, indicating the hash is stored in `/etc/shadow`
    
- If `/etc/passwd` is mistakenly writable:
    
    - The password field for `root` can be emptied
        
    - This allows passwordless root access
        
- This misconfiguration is rare but critical
    

Example of insecure entry:

```
root::0:0:root:/root:/bin/bash
```

---

## /etc/shadow File

The `/etc/shadow` file stores **hashed passwords** and password aging information.

- Readable only by `root` or privileged processes
    
- If a user exists in `/etc/passwd` but not in `/etc/shadow`, the account is invalid
    

### Format

Each entry has nine colon-separated fields:

```
username:password:last_change:min:max:warn:inactive:expire:reserved
```

Example:

```
htb-student:$y$j9T$...:18955:0:99999:7:::
```

### Password Field Format

```
$<id>$<salt>$<hash>
```

|ID|Hash Algorithm|
|---|---|
|1|MD5|
|2a|Blowfish|
|5|SHA-256|
|6|SHA-512|
|sha1|SHA1crypt|
|y|yescrypt|
|gy|gost-yescrypt|
|7|scrypt|

Modern distributions (e.g., Debian, Ubuntu) use **yescrypt** by default. Older systems may still use weaker algorithms that are easier to crack.

### Special Characters in Password Field

- `!` or `*`: Password login disabled
    
- Empty field: No password required (dangerous)
    
- Other authentication methods (SSH keys, Kerberos) may still work
    

---

## /etc/security/opasswd

The `opasswd` file stores **previous password hashes** to prevent password reuse.

- Managed by `pam_unix.so`
    
- Requires root privileges to read
    
- May contain weaker legacy hashes (e.g., MD5)
    

Example:

```
cry0l1t3:1000:2:$1$HjFAfYTG$...,$1$kcUjWZJX$...
```

### Security Implications

- Older hashes are often easier to crack
    
- Users frequently reuse password patterns
    
- Cracked historical passwords may lead to:
    
    - Credential reuse attacks
        
    - Lateral movement
        
    - Password guessing across services
        
