## /etc/passwd
This is a file that we can find in all the Linux machines. Once we have gained access to a machine and we want to escalate our privileges we can take a look to this file to see what users are registered in the machine. The fields that we can find for each row are: 
 - Username
 - Password
 - User ID
 - Primary Group ID 
 - User Information
 - Home Directory
 - Shell
 - 
```bash
cat /etc/passwd
#Example of a row:
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

### /etc/shadow

The `/etc/shadow` file stores the encrypted user password hashes and other account-related information in a secure way. Unlike `/etc/passwd`, which is world-readable, `/etc/shadow` is typically only accessible by the root user to enhance security.

```bash
cat /etc/shadow
#Example of a row:
nobody:$6$someSalt$hashedPasswordHere:18000:0:99999:7:::
```

#### Hashing Algorithm for Passwords

The password hash in `/etc/shadow` is created using a cryptographic hash function. Commonly used hashing algorithms include:

1. **MD5** (deprecated but still found in some systems)
    - **Hash format**: `$1$<salt>$<hashed_password>`
2. **SHA-512** (widely used in modern Linux systems)
    - **Hash format**: `$6$<salt>$<hashed_password>`
3. **Blowfish/Bcrypt** (used in some distributions for higher security)
    - **Hash format**: `$2a$<cost>$<salt>$<hashed_password>`
