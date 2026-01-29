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

#### Common POP3 Commands

|Command|Description|
|---|---|
|`USER username`|Identify user|
|`PASS password`|Authenticate|
|`STAT`|Mailbox statistics|
|`LIST`|List messages|
|`RETR <id>`|Retrieve email|
|`DELE <id>`|Delete email|
|`CAPA`|Server capabilities|
|`QUIT`|End session|

### IMAP over TLS

```bash
openssl s_client -connect <ip>:993
```

#### Common IMAP Commands

| Command                | Description                  |
| ---------------------- | ---------------------------- |
| `A1 LOGIN user pass`   | Authenticate user            |
| `A1 LIST "" *`         | List all mailboxes           |
| `A1 LSUB "" *`         | List subscribed mailboxes    |
| `A1 SELECT <INBOX>`    | Select mailbox               |
| `A1 FETCH <id> all`    | Retrieve message information |
| `A1 FETCH <id> BODY[]` | Retrieve message body        |
| `A1 UNSELECT`          | Leave mailbox                |
| `A1 LOGOUT`            | Close session                |


---

## Practical Attack Flow

1. Identify mail services via Nmap
    
2. Extract hostnames from SSL certificates
    
3. Enumerate capabilities (AUTH methods)
    
4. Reuse credentials from SMTP / AD
    
5. Access mailboxes via IMAP/POP3
    
6. Read sensitive emails (password resets, VPN creds)
    