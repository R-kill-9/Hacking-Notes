**Active Directory Certificate Services (AD CS)** is a **Windows Server role** that allows an organization to build and manage its own **Public Key Infrastructure (PKI)**.  
In simple terms, it’s the part of Active Directory that issues and manages **digital certificates** used for authentication, encryption, and digital signing.

A digital certificate is like an ID card for a user, computer, or service that proves identity and can be used for secure communication.

---

## What AD CS Does

AD CS performs several key tasks:

|Function|Description|
|---|---|
|**Certificate Authority (CA)**|Issues and manages digital certificates (like an internal version of a public CA such as DigiCert).|
|**Enrollment Services**|Allows users and computers to request and automatically receive certificates.|
|**Certificate Templates**|Define the rules for how certificates are issued (who can request them, key usage, validity period, etc.).|
|**Revocation Lists (CRL)**|Keeps track of revoked or invalid certificates.|
|**Integration with AD**|Publishes certificates and templates directly in Active Directory for use by domain members.|
## AD CS in Security Testing

In penetration testing or security auditing, AD CS is important because **misconfigured templates** can allow privilege escalation.  
For example:

- A template may allow users to **enroll for authentication certificates** and use them to impersonate another user (ESC1–ESC8 vulnerabilities).
    
- Attackers can abuse certificate-based authentication to gain **Kerberos TGTs** using tools like `Certipy` or `Rubeus`.
    

---

## Example: Certipy Enumeration Output

Below is an example of what `Certipy` might return when enumerating an AD CS environment.

```bash
certipy-ad find -u user@domain.local -p 'Password123!' -dc-ip 10.10.10.5
```

```bash
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates and permissions

CA Name             : ACC10-CA
DNS Name            : acc10-ca.acc10.local
Certificate Template: UserAuthentication
Schema Version      : 2
Template ID         : 1.3.6.1.4.1.311.21.8.12345678.98765432.1111.2222.333333333333
Display Name        : User Authentication
Enrollment Rights   : Domain Users
Subject Name Flags  : ENROLLEE_SUPPLIES_SUBJECT
Extended Key Usage  : Client Authentication, Smartcard Logon
Permissions         : ENROLL, AUTOENROLL
Vulnerable          : ESC1 - Enrollee supplies subject name and client authentication allowed
```

#### Explanation of Each Field

|Field|Meaning|
|---|---|
|**CA Name**|The name of the Certificate Authority issuing certificates.|
|**DNS Name**|The network address of the CA server.|
|**Certificate Template**|The name of the certificate template defined in AD CS.|
|**Schema Version**|Version number of the template (v1, v2, v3). Later versions support more features and controls.|
|**Template ID**|The unique Object Identifier (OID) of the template.|
|**Display Name**|Human-readable name for the template.|
|**Enrollment Rights**|Groups or users allowed to request certificates from this template.|
|**Subject Name Flags**|Defines how the certificate subject name is created. `ENROLLEE_SUPPLIES_SUBJECT` means the requester can specify the name — often a dangerous misconfiguration.|
|**Extended Key Usage (EKU)**|Defines the allowed uses of the certificate (e.g., client authentication, code signing, etc.).|
|**Permissions**|Lists operations the user or group can perform (e.g., ENROLL, AUTOENROLL).|
|**Vulnerable**|Indicates a potential security issue, often following the “ESC” classification (e.g., ESC1, ESC2).|

---

## Common AD CS vulnerabilities

- **ESC1 — Enrollee supplies subject name.**  
Template allows requester to set the certificate subject; an attacker can request a cert for another identity and impersonate it.

- **ESC2 — Enrollment agent / delegation misconfiguration.**  
Overly permissive enrollment agents or delegated rights let low-privileged users request certificates for others.

- **ESC3 — Writable template ACLs / template modification.**  
If templates are writable by non-privileged accounts, an attacker can change template settings to enable abusive certificate issuance.

- **ESC4 — Key escrow or CA key exposure.**  
Escrowed or poorly protected CA keys/backups permit signing or decryption of certificates and compromise of trust.

- **ESC5 — Weak template constraints (broad EKU/SPN).**  
Templates with overly broad EKUs or SPN settings allow certificates to be used where they should not be valid for authentication.

- **ESC6 — CA object / CA permissions misconfiguration.**  
Weak ACLs on the CA itself allow attackers to alter CA behavior or create subordinate CAs, which is high impact.

- **ESC7 — Legacy template versions / missing modern controls.**  
Older/incompatible templates omit modern restrictions, enabling issuance of certificates with excessive privileges.

- **ESC8 — Web enrollment / NDES / IIS attack surface.**  
Exposed web enrollment interfaces can be abused (relay or predictable enrollment) to obtain certificates without LDAP rights.