`sslscan` is a reconnaissance tool used to enumerate SSL/TLS services. It connects to a target server and reports supported protocols, cipher suites, certificate details, and potential weaknesses. It is commonly used during the initial phase of a pentest to assess the cryptographic posture of a service.

Unlike exploitation tools, `sslscan` is focused on **misconfiguration discovery**, which can later be chained into attacks such as downgrade attacks, weak cipher exploitation, or compliance bypass.

---

## Installation and setup

### Package installation (Linux)

On most distributions:

```bash
sudo apt install sslscan
```

If not available or you want the latest version:

```bash
git clone https://github.com/rbsec/sslscan.git
cd sslscan
make static
```

Binary will be generated in the current directory.

---

## Basic usage 

The simplest scan:

```bash
sslscan example.com
```

Or specifying port:

```bash
sslscan example.com:443
```

Scan output will include:

- Supported SSL/TLS versions
    
- Accepted cipher suites
    
- Certificate information
    
- Weak/unsafe configurations
    

---

## Interpreting results

### Protocol support analysis

Example output:

```text
SSLv2     disabled
SSLv3     enabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled
```

Key observations:

- SSLv2/SSLv3 should always be disabled
    
- TLS 1.0 and 1.1 are deprecated → considered weak
    
- TLS 1.2+ is recommended
    

If older protocols are enabled, the server is potentially vulnerable to downgrade or legacy attacks.

---

### Cipher suite enumeration

Example:

```text
Accepted  TLSv1.2  128 bits  AES128-SHA
Accepted  TLSv1.2  256 bits  AES256-SHA
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384
```

Focus on:

- **Weak ciphers**
    
    - RC4
        
    - DES / 3DES
        
    - NULL ciphers
        
    - EXPORT-grade
        
- **Key exchange**
    
    - RSA (no forward secrecy)
        
    - ECDHE (preferred, provides forward secrecy)
        

If you see:

```text
Accepted  TLSv1.0  40 bits  EXP-RC4-MD5
```

This indicates export-grade encryption → highly insecure.

---

### Certificate inspection

Example:

```text
Subject: CN=example.com
Issuer: Let's Encrypt Authority X3
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength: 2048 bits
```

Things to check:

- Expired certificates
    
- Weak signature algorithms (e.g., SHA1)
    
- Small key sizes (<2048 bits)
    
- Self-signed certificates (depending on context)
    

---

## Advanced scanning techniques

### Forcing specific protocol checks

Test only TLS 1.0:

```bash
sslscan --tls10 example.com
```

Test TLS 1.3:

```bash
sslscan --tls13 example.com
```

Useful for confirming downgrade possibilities.


### Checking for weak ciphers only

```bash
sslscan --no-failed example.com
```

This filters output to only accepted ciphers, making analysis faster.


### STARTTLS services

For services like SMTP, IMAP:

```bash
sslscan --starttls-smtp mail.example.com:25
```

Other modes:

- `--starttls-imap`
    
- `--starttls-pop3`
    
- `--starttls-ftp`
    

