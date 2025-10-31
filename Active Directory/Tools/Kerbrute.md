**Kerbrute** is a fast and flexible **Kerberos bruteforcer** written in Go, commonly used for user enumeration and password spraying in Active Directory environments. It interacts directly with the Kerberos protocol over UDP/TCP (port 88).


---

### Key Features

- **User Enumeration**: Detects valid usernames by analyzing Kerberos error responses.
- **Password Spraying**: Attempts authentication using a single password across multiple users.
- **Multithreading**: Supports concurrent requests for speed and efficiency.
- **No domain join required**: Works without needing to be part of the domain.

---

### Usage Examples

#### 1. **User Enumeration**

```bash
kerbrute -users usernames.txt -domain example.local -dc-ip 192.168.1.10
```

#### 2. **Password Spraying**

```bash
kerbrute -users usernames.txt -passwords passwords.txt -domain example.local -dc-ip 192.168.1.10
```

#### 3. **Single User Test**

```bash
kerbrute -user admin -password Welcome123 -domain example.local -dc-ip 192.168.1.10
```

---

### Common Flags

|Flag|Description|
|---|---|
|`-users`|Path to file with usernames|
|`-user`|Single username|
|`-passwords`|Path to file with passwords|
|`-password`|Single password|
|`-domain`|Target domain name|
|`-dc-ip`|IP address of Domain Controller|
|`-threads`|Number of concurrent threads (default: 10)|
|`-outputfile`|Save full output to file|
|`-outputusers`|Save only valid usernames to file|
|`-no-save-ticket`|Avoid saving TGTs to disk|
