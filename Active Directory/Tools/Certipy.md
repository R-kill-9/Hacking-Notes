**[Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)** is a Python-based, command-line tool that interfaces with AD CS. It simplifies the discovery and exploitation of common certificate template misconfigurations that affect the security of a Windows domain.

|Category|Description|
|---|---|
|**Purpose**|Enumeration and exploitation of Active Directory Certificate Services (AD CS).|
|**Target Vulnerability**|Misconfigured Certificate Templates (e.g., ESC1, ESC6, ESC8, ESC9).|
|**Authentication Method**|Kerberos/NTLM (often requires a valid user's credentials or hash).|
|**Output**|`.pfx` or `.ccf` files (PKCS#12) containing the forged certificate and private key, which can be used for **PKINIT** authentication.|

---

## Installation and Setup

Certipy is typically installed via `pip` or is pre-installed in specialized distributions like Kali Linux. It requires specific Python dependencies to handle LDAP, Kerberos, and cryptographic operations.

| Category                  | Description                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **Purpose**               | Enumeration and exploitation of Active Directory Certificate Services (AD CS).                                                       |
| **Target Vulnerability**  | Misconfigured Certificate Templates (e.g., ESC1, ESC6, ESC8, ESC9).                                                                  |
| **Authentication Method** | Kerberos/NTLM (often requires a valid user's credentials or hash).                                                                   |
| **Output**                | `.pfx` or `.ccf` files (PKCS#12) containing the forged certificate and private key, which can be used for **PKINIT** authentication. |

---

## Core Usage Commands

The tool operates in three distinct modes: **`find`** (enumeration), **`req`** (request/exploit), and **`auth`** (authentication).

### 1. Enumeration (find) 

This is the initial, crucial step. Certipy queries the domain controller to map out all Certificate Authorities (CAs) and identify misconfigured templates based on known exploit primitives (ESC-series).

```bash
certipy find -u <user>@<domain.local> -p <password> -dc-ip <DC_IP> 
```

|Flag|Description|
|---|---|
|`-u` / `-p`|Specifies the domain user's UPN and password for authenticated queries.|
|`-hashes`|Allows passing NTLM hashes (`LM:NT`) instead of the password.|
|`-dc-ip`|IP address of the Domain Controller.|
|`--vulnerable`|**Key flag:** Filters output to show only templates with known misconfigurations (e.g., ESC1, ESC6) that allow for privilege escalation.|
|`-ca`|Specify a particular Certificate Authority name to query.|

---

### 2. Privilege Escalation (req) 

Once a vulnerable template is found (e.g., ESC1 - where the requester can specify a **Subject Alternative Name**), Certipy can request a certificate on behalf of a privileged user.

```bash
certipy req -u <low_user>@<domain.local> -p <password> -ca <CA_Name> -template <Vulnerable_Template> -alt <Target_UPN>
```

|Flag|Description|
|---|---|
|`-ca`|Name of the Certificate Authority to target.|
|`-template`|Name of the vulnerable certificate template identified by the `find` command.|
|`-alt`|**Critical Flag:** Specifies the **Subject Alternative Name (SAN)**. This is set to the UPN of the high-privileged user (e.g., `Administrator@domain.local`) the attacker wishes to impersonate.|
|`-k`|Use a Kerberos Ticket-Granting Ticket (TGT) for authentication instead of a password/hash.|

**Result:** A successful request creates a file (e.g., `certificate.pfx`) containing the newly issued certificate and the private key.

---

### 3. Post-Exploitation Authentication (auth) 

The generated `.pfx` file is essentially a highly privileged ticket. Certipy uses this file to authenticate to the Domain Controller via **PKINIT** (Public Key Cryptography for Initial Authentication in Kerberos).

Bash

```
certipy auth -pfx <certificate_file.pfx> -dc-ip <DC_IP>
```

|Flag|Description|
|---|---|
|`-pfx`|Path to the PKCS#12 file containing the certificate and private key.|
|`--impersonate`|Optional: Specifies the account whose credentials should be dumped (if the certificate is mapped to a high-privilege user).|

**Result:**

1. **Successful PKINIT authentication** as the impersonated user (e.g., Administrator).

2. Certipy can automatically retrieve a **Ticket-Granting Ticket (TGT)** for the target account.

3. The tool often dumps the NT hash of the target user, which can then be used for **Pass-the-Hash** attacks or **DCSync**.


---

## Advanced Escalation Techniques (ESC-Series)

Certipy supports the exploitation of multiple certificate misconfigurations defined by the security research community.

| Technique | Abused Mechanism                                                                        | Certipy Functionality                                                                   |
| --------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **ESC1**  | Template allows requester to supply a custom SAN (Alt-Subject Name).                    | **`req -alt <Target_UPN>`**                                                             |
| **ESC6**  | Template allows users to enroll for other certificate types (Enrollment Agent).         | Used to enroll for a high-privilege template.                                           |
| **ESC8**  | Weak permissions on the CA, allowing low-privileged users to modify CA object settings. | Can be used to make a template vulnerable or to issue arbitrary certificates.           |
| **ESC9**  | Weak certificate mapping (no `objectSid` validation) combined with UPN modification.    | **`certipy-ad account update`** to change a user's UPN before requesting a certificate. |
