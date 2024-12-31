Windows operating systems use password hashes to securely store user credentials. These hashes represent an encrypted version of the user's password, making it difficult to retrieve the original password directly.
## LSASS (Local Security Authority Subsystem Service)

**LSASS** is a critical system process that handles authentication, user logins, and the management of security tokens. It validates user credentials during login and creates security tokens used to manage access rights.

To dump credentials from LSASS **Mimikatz** can be used:

```bash
.\mimikatz.exe "sekurlsa::logonpasswords"
```

## SAM (Security Accounts Manager)

**SAM** is a database file located at `C:\Windows\System32\Config` that stores user account information, including password hashes for local accounts.

To extract the SAM file (requires SYSTEM privileges):

```bash
.\mimikatz.exe 
lsadump::sam
```

## NTLM

**NTLM** (NT LAN Manager) is a Microsoft authentication protocol used for user and system verification in Windows environments. It's primarily a fallback when Kerberos isn't available and relies on a challenge-response mechanism for authentication.
#### **Key Points**

1. **Versions**:
    - **NTLMv1**: Outdated and insecure, uses DES encryption.
    - **NTLMv2**: Improved with HMAC-MD5, but still vulnerable to attacks.
2. **Weaknesses**:
    - Susceptible to **Pass-the-Hash (PtH)** and **Replay Attacks**.
    - No mutual authentication (doesn’t verify the server).
3. **Usage**:
    - Legacy systems, SMB connections, and environments without Active Directory or Kerberos.
4. **Security**:
    - Strongly advised to replace NTLM with Kerberos or modern alternatives where possible. Disable NTLMv1 for added security.