**IMAP (Internet Message Access Protocol)** allows online management of emails directly on the mail server. Messages remain on the server and support folders, synchronization across multiple clients, and concurrent access.

**POP3 (Post Office Protocol v3)** is simpler: it allows listing, retrieving, and deleting emails. Messages are typically downloaded and removed from the server.

#### Key Differences

- **IMAP**: server-side folders, multi-client sync, concurrent access
    
- **POP3**: download-and-delete model, minimal server-side state
    

#### Default Ports

- **IMAP**: 143 (plaintext / STARTTLS), 993 (IMAPS – SSL/TLS)
    
- **POP3**: 110 (plaintext / STLS), 995 (POP3S – SSL/TLS)
    

> ⚠️ Plaintext ports transmit credentials in cleartext unless STARTTLS is enforced.


---

## Service Footprinting (Nmap)

```bash
# Scan IMAP/POP3 services with default scripts
nmap -sC -sV -p 110,143,993,995 <ip>
```

### Useful Findings

- Mail server software (e.g. Dovecot)
    
- SSL certificate CN (often hostname)
    
- Enabled capabilities (AUTH methods, STARTTLS)
    

---

## Manual Interaction – Telnet / Netcat 

For non-TLS services (SMTP 25, POP3 110, IMAP 143), we can interact manually using **telnet** or **netcat**.

### Connect with Telnet

```bash
telnet <ip> <port>
```

### Connect with Netcat

```bash
nc <ip> <port>
```

Example:

```bash
nc <ip> 110
telnet <ip> 25
```


### POP3 (Port 110)

|Command|Description|
|---|---|
|`USER username`|Identify user|
|`PASS password`|Authenticate|
|`STAT`|Mailbox statistics|
|`LIST`|List messages|
|`RETR <id>`|Retrieve email|
|`DELE <id>`|Delete email|
|`QUIT`|End session|


### IMAP (Port 143)

|Command|Description|
|---|---|
|`A1 LOGIN user pass`|Authenticate user|
|`A1 LIST "" *`|List mailboxes|
|`A1 SELECT INBOX`|Open mailbox|
|`A1 FETCH 1 BODY[]`|Retrieve message|
|`A1 LOGOUT`|Close session|

---

## Manual Interaction – cURL

### IMAPS Login & Mailbox Listing

```bash
curl -k 'imaps://<ip>' --user user:password
```

### Verbose Mode (TLS + Banner Info)

```bash
curl -k 'imaps://<ip>' --user user:password -v
```

Reveals:

- TLS version & cipher
    
- Certificate details
    
- IMAP banner & capabilities
    

---

## Manual Interaction – OpenSSL

### POP3 over TLS

```bash
openssl s_client -connect <ip>:995
```

### IMAP over TLS

```bash
openssl s_client -connect <ip>:993
```

#### Common IMAP Commands


---
## Password Spraying with Hydra 

Hydra can be used to perform password spraying or brute-force attacks against email protocols such as POP3, IMAP, or SMTP.

```bash
hydra -L <users.txt> -p '<Password>' -f <target_ip> pop3
```

