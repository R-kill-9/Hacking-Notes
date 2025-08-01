### NTLMv2 Authentication

**NTLMv2** is an improved version of the legacy NTLM protocol used in Windows environments to authenticate users more securely.

#### Key Features:

- Based on an enhanced challenge-response mechanism with stronger cryptographic hashing.
- Uses password hashes along with client and server challenges to generate a response.
- Does **not** use tickets like Kerberos.
- Supports mutual authentication (optional).
- Provides better resistance against replay and relay attacks compared to NTLMv1, but still vulnerable to certain attacks if improperly configured.

#### NTLM Flow:
```java
1. Client → Server: Sends Negotiate message to start NTLM authentication.
2. Server → Client: Sends Challenge message containing a random nonce.
3. Client → Server: Sends Authenticate message with username and response hash calculated using the nonce and user's password hash.
4. Server: Validates response by comparing it with the expected hash derived from stored password hash.

```

The hash used is typically the **NT hash** (MD5 of the password), which is stored on the Domain Controller.

---

## Kerberos Authentication

**Kerberos** is a ticket-based authentication protocol that provides more security and flexibility than NTLM. It is the default in Active Directory environments.

#### Key Concepts:

- Based on symmetric key cryptography.
- Uses two types of tickets:
    - **TGT (Ticket Granting Ticket)** for authenticating to the domain.
    - **TGS (Ticket Granting Service)** tickets for accessing specific services.


#### Kerberos Flow:
```bash
1. User enters credentials (username + password)
2. Client → KDC (Authentication Service): Requests TGT
3. KDC validates credentials, returns TGT encrypted with the user's key
4. Client → KDC (Ticket Granting Service): Requests TGS for a specific service
5. KDC returns a TGS
6. Client → Service: Presents the TGS to access the service
```

The **KDC** is usually the **Domain Controller (DC)**.

---

## NTDS.dit (NT Directory Services database)

**NTDS.dit** is the main Active Directory database file located on Domain Controllers. It contains critical domain data, including:

- All user and group objects
- Password hashes (NTLM hashes and sometimes Kerberos keys)
- Group Policy Objects
- Schema information

#### Location (Default):
```bash
C:\Windows\NTDS\NTDS.dit
```

#### Why It's Important:

- Dumping `NTDS.dit` allows an attacker to extract **all password hashes** in the domain.
- These hashes can be used for **pass-the-hash**, **offline cracking**, or **Kerberos ticket forging (Golden Ticket)**.

#### Common Tools for Dumping:

- `ntdsutil` (native, admin usage)
- `Volume Shadow Copy + secretsdump.py` (e.g., from Impacket)
- `Mimikatz` (for extracting from memory or SYSTEM + SECURITY + NTDS.dit)


#### Example (Impacket):
```bash
secretsdump.py -just-dc-ntlm DOMAIN/USER:PASSWORD@DC_IP
```