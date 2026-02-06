Once **root access** is obtained on a Linux system, attackers can extract local authentication data and perform **offline password cracking**. Offline attacks are highly effective because they do not interact with live authentication services and are not subject to lockout policies or rate limits.

---

## Prerequisites

- Root or equivalent privileges
    
- Read access to:
    
    - `/etc/passwd`
        
    - `/etc/shadow`
        
- Password cracking tools (Hashcat or John the Ripper)
    

---

## Extracting Local Password Hashes

Linux stores account metadata and password hashes across two files:

- `/etc/passwd`: User account information (world-readable)
    
- `/etc/shadow`: Password hashes and aging data (root-only)
    

### Step 1: Copy Authentication Files

Authentication files should be copied to a working directory to avoid modifying system-critical files.

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
```

This ensures:

- File integrity
    
- Safer offline processing
    
- Reduced risk of system instability
    

---

## Preparing Hashes for Cracking

### Step 2: Combine Files with unshadow

The `unshadow` utility (part of John the Ripper) merges `/etc/passwd` and `/etc/shadow` into a single crackable format.

```bash
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

The resulting file contains:

- Usernames
    
- Associated password hashes
    
- Correct formatting for cracking tools
    

This format is compatible with:

- John the Ripper
    
- Hashcat
    

---

## Cracking Password Hashes

### Offline Cracking with Hashcat

Hashcat is commonly used for high-performance password cracking using CPU or GPU acceleration.

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o cracked.txt
```

### Parameters Explained

- `-m 1800`: SHA-512 crypt (common on modern Linux systems)
    
- `-a 0`: Dictionary attack
    
- `rockyou.txt`: Wordlist
    
- `-o cracked.txt`: Output file for recovered passwords
    
